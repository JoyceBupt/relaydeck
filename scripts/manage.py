#!/usr/bin/env python3
"""Package, install and update verified RelayDeck releases on systemd Linux."""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import pwd
import grp
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import sys
import urllib.parse
import urllib.request

SOURCE = pathlib.Path(__file__).resolve().parent.parent
STATE = pathlib.Path('/var/lib/relaydeck')
CONFIG = pathlib.Path('/etc/relaydeck')
RELEASES = pathlib.Path('/opt/relaydeck/releases')
CURRENT = pathlib.Path('/opt/relaydeck/current')
BIN = pathlib.Path('/usr/local/libexec/relaydeck')
MANAGER = BIN.with_name('relaydeck-manage.py')
UPDATER = pathlib.Path('/usr/local/sbin/relaydeck-update')
UNITS = ('relaydeck-broker.service', 'relaydeck-web.service', 'relaydeck-worker.service')
UPGRADE_UNIT = 'relaydeck-upgrader.service'
ALL_UNITS = (*UNITS, UPGRADE_UNIT)
TRANSACTION = STATE / 'upgrade-transaction.json'
ENV_KEYS = {'RELAYDECK_DATABASE', 'RELAYDECK_MFA_KEY', 'RELAYDECK_LISTEN', 'RELAYDECK_ORIGIN', 'RELAYDECK_TRUST_PROXY', 'RELAYDECK_FRONTEND'}
SAFE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
DEFAULT_PANEL_PORT = 17443
CADDY_ORIGIN = 'https://panel.example.com:17443'


def deployment_origin(value, default_port=DEFAULT_PANEL_PORT):
    # Validate the raw string before urlsplit can strip control characters.
    if not re.fullmatch(r'https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?/?', value):
        raise ValueError('Provide an HTTPS domain origin with an optional port')
    url = urllib.parse.urlsplit(value)
    host = url.hostname
    if len(host) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
        raise ValueError('Invalid panel domain')
    port = url.port if url.port is not None else default_port
    if type(port) is not int or not (port == 443 or 1024 <= port <= 65535) or port == 7410:
        raise ValueError('Panel port must be 443 or 1024..65535, excluding backend port 7410')
    origin = f'https://{host}' + (f':{port}' if port != 443 else '')
    return origin, port


def caddy_configuration(template, origin):
    # Replace the complete authority so custom ports cannot produce two colons.
    if template.count(CADDY_ORIGIN) != 1:
        raise ValueError('Unexpected release Caddy template')
    return template.replace(CADDY_ORIGIN, origin)


def reserve_control_ports(policy, origin):
    # A legacy origin without a port means 443, even after the default changes.
    _, port = deployment_origin(origin, default_port=443)
    ports = policy['reserved_ports']
    if not isinstance(ports, list) or any(type(item) is not int or not 1 <= item <= 65535 for item in ports):
        raise ValueError('Invalid reserved control ports')
    policy['reserved_ports'] = sorted(set(ports) | {22, 80, 443, 7410, port})


def run(*args, env=None, capture=False):
    return subprocess.run(args, check=True, env=env or SAFE_ENV, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def digest(path):
    with open(path, 'rb') as stream:
        checksum = hashlib.sha256()
        while chunk := stream.read(1024 * 1024):
            checksum.update(chunk)
        return checksum.hexdigest()


def root_path(path):
    for item in reversed([path, *path.parents]):
        info = item.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError(f'Unsafe root path: {item}')


def verified_file(path, expected):
    if not re.fullmatch('[a-fA-F0-9]{64}', expected):
        raise ValueError('A trusted SHA-256 digest is required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(descriptor, 'rb')
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        stream.close()
        raise ValueError('Release input must be a single-link regular file')
    snapshot = tempfile.TemporaryFile()
    checksum = hashlib.sha256()
    size = 0
    try:
        with stream:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                if size > 100 * 1024 * 1024:
                    raise ValueError('Release input exceeds size limit')
                checksum.update(chunk)
                snapshot.write(chunk)
        if checksum.hexdigest() != expected.lower():
            raise ValueError('SHA-256 verification failed')
        snapshot.seek(0)
        return snapshot
    except BaseException:
        snapshot.close()
        raise


def extract_release(archive, expected, destination):
    destination = pathlib.Path(destination)
    with verified_file(archive, expected) as stream, tarfile.open(fileobj=stream, mode='r:gz') as tar:
        members = tar.getmembers()
        if len(members) > 4096 or any(member.size < 0 for member in members) or sum(member.size for member in members) > 250 * 1024 * 1024:
            raise ValueError('Release exceeds size or entry limits')
        seen = set()
        for member in members:
            raw = member.name.rstrip('/')
            parts = raw.split('/')
            if any(part in ('', '.', '..') for part in parts) or raw.startswith('/') or raw in seen:
                raise ValueError('Invalid or duplicate release path')
            if not (member.isdir() or member.isfile()):
                raise ValueError('Links and special files are forbidden')
            if parts[0] not in ('bin', 'frontend', 'deploy', 'release.json'):
                raise ValueError('Unexpected release payload')
            if parts[0] == 'bin' and raw not in ('bin', 'bin/relaydeck'):
                raise ValueError('Unexpected executable payload')
            seen.add(raw)
        required = {'bin/relaydeck', 'frontend/index.html', 'release.json', 'deploy/broker.example.json', 'deploy/Caddyfile.example', 'deploy/manage.py', 'deploy/relaydeck-update', 'deploy/relaydeck-upgrader.py', *(f'deploy/{unit}' for unit in ALL_UNITS)}
        if not required <= seen:
            raise ValueError('Incomplete release')
        if not all(tar.getmember(name).isfile() for name in required):
            raise ValueError('Required payloads must be regular files')
        manifest_member = tar.getmember('release.json')
        if manifest_member.size > 4096 or not manifest_member.isfile():
            raise ValueError('Invalid release manifest')
        manifest = json.load(tar.extractfile(manifest_member))
        if set(manifest) != {'version', 'revision', 'target'}:
            raise ValueError('Invalid manifest fields')
        if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?', manifest['version']) or not re.fullmatch('[a-f0-9]{7,40}', manifest['revision']):
            raise ValueError('Invalid release identity')
        if manifest['target'] not in ('aarch64-unknown-linux-gnu', 'x86_64-unknown-linux-gnu'):
            raise ValueError('Unsupported release architecture')
        binary_member = tar.getmember('bin/relaydeck')
        header = tar.extractfile(binary_member).read(20)
        machine = 183 if manifest['target'].startswith('aarch64') else 62
        if len(header) < 20 or header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != machine:
            raise ValueError('Executable architecture does not match manifest')
        for member in members:
            path = destination.joinpath(*member.name.rstrip('/').split('/'))
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('xb') as output, tar.extractfile(member) as source:
                    shutil.copyfileobj(source, output)
                path.chmod(0o755 if member.name == 'bin/relaydeck' else 0o644)
    return manifest


def preflight():
    if platform.system() != 'Linux' or os.geteuid() != 0:
        raise ValueError('Installation and updates require root on systemd Linux')
    if not pathlib.Path('/sys/fs/cgroup/cgroup.controllers').is_file():
        raise ValueError('cgroup v2 is required')
    for command in ('systemctl', 'nft', 'ss', 'ip', 'runuser'):
        if not shutil.which(command, path=SAFE_ENV['PATH']):
            raise ValueError(f'Missing dependency: {command}')


def release_name(manifest):
    return '-'.join(manifest[name] for name in ('version', 'revision', 'target'))


def prepare(args, destination):
    manifest = extract_release(args.bundle, args.sha256, destination)
    arch = 'aarch64' if platform.machine() in ('aarch64', 'arm64') else 'x86_64'
    if not manifest['target'].startswith(arch + '-'):
        raise ValueError('Release does not match this host')
    if run(str(destination / 'bin/relaydeck'), '--version', capture=True).strip() != 'RelayDeck ' + manifest['version']:
        raise ValueError('Executable version does not match manifest')
    return manifest


def atomic_copy(source, destination, mode=0o755):
    root_path(destination.parent)
    if destination.exists() or destination.is_symlink():
        root_path(destination)
        if not destination.is_file() or destination.stat().st_nlink != 1:
            raise ValueError(f'Unexpected destination: {destination}')
    descriptor, name = tempfile.mkstemp(prefix='.relaydeck-', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output, open(source, 'rb') as stream:
            shutil.copyfileobj(stream, output)
            os.fchmod(output.fileno(), mode)
            os.fsync(output.fileno())
        os.replace(name, destination)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def current_link(release):
    root_path(CURRENT.parent)
    if CURRENT.exists() or CURRENT.is_symlink():
        if not CURRENT.is_symlink() or CURRENT.lstat().st_uid != 0:
            raise ValueError('Unexpected current release pointer')
    temporary = CURRENT.with_name('.current-' + str(os.getpid()))
    os.symlink(release, temporary)
    os.replace(temporary, CURRENT)


def management_tools(release):
    atomic_copy(release / 'deploy/manage.py', MANAGER, 0o644)
    atomic_copy(release / 'deploy/relaydeck-update', UPDATER, 0o755)
    if (release / 'deploy/relaydeck-upgrader.py').is_file():
        atomic_copy(release / 'deploy/relaydeck-upgrader.py', BIN.with_name('relaydeck-upgrader.py'), 0o644)



def atomic_json(path, value, mode=0o600):
    with tempfile.TemporaryDirectory(prefix='relaydeck-record-') as work:
        source = pathlib.Path(work) / 'record.json'
        source.write_text(json.dumps(value) + '\n')
        atomic_copy(source, path, mode)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_upgrade_policy():
    path = CONFIG / 'upgrade.json'
    (STATE / 'updates').mkdir(mode=0o755, exist_ok=True)
    root_path(STATE / 'updates')
    account = pwd.getpwnam('relaydeck')
    if path.exists() or path.is_symlink():
        root_path(path)
        value = json.loads(path.read_text())
        if set(value) != {'owner_id', 'web_uid', 'web_gid'} or type(value['owner_id']) is not int or value['owner_id'] <= 0 or value['web_uid'] != account.pw_uid or value['web_gid'] != account.pw_gid:
            raise ValueError('Invalid existing upgrade owner policy')
        return
    # The data UID parses SQLite; root receives only the one bootstrap account ID.
    query = "import sqlite3,sys;d=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True);r=d.execute(\"SELECT id FROM users WHERE role='admin' ORDER BY id\").fetchall();assert len(r)==1,'Bootstrap owner must be unambiguous';print(r[0][0]);d.close()"
    owner = run('runuser', '-u', 'relaydeck', '--', 'python3', '-c', query, str(STATE / 'data/relaydeck.db'), capture=True).strip()
    if not re.fullmatch('[1-9][0-9]{0,9}', owner):
        raise ValueError('Invalid bootstrap owner')
    atomic_json(path, {'owner_id': int(owner), 'web_uid': account.pw_uid, 'web_gid': account.pw_gid}, 0o644)
    (STATE / 'updates').mkdir(mode=0o755, exist_ok=True)
    root_path(STATE / 'updates')

def read_environment():
    path = CONFIG / 'relaydeck.env'
    root_path(path)
    values = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or key not in ENV_KEYS or '\x00' in value:
            raise ValueError('Unexpected service environment')
        values[key] = value
    if values.get('RELAYDECK_DATABASE') != str(STATE / 'data/relaydeck.db') or values.get('RELAYDECK_MFA_KEY') != str(STATE / 'secrets/mfa.key'):
        raise ValueError('Managed data paths differ; manual migration is required')
    return {**SAFE_ENV, **values, 'HOME': str(STATE)}


def as_web(binary, *arguments):
    run('runuser', '-u', 'relaydeck', '--', str(binary), *arguments, env=read_environment())


def wait_health(version):
    last = 'not ready'
    for _ in range(80):
        try:
            with urllib.request.urlopen('http://127.0.0.1:7410/api/health', timeout=1) as response:
                health = json.load(response)
            if health.get('version') == version and health.get('executor') == 'running':
                return
            last = str(health)
        except (OSError, ValueError) as error:
            last = str(error)
        time.sleep(0.25)
    raise RuntimeError('Service health check failed: ' + last)


def manage_lock():
    import fcntl
    root_path(CONFIG)
    descriptor = os.open(CONFIG / 'maintenance.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
        os.close(descriptor)
        raise ValueError('Unexpected maintenance lock')
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return os.fdopen(descriptor, 'w')


def merged_port_reservations(existing, start=None, end=None, control_ports=()):
    ranges = []
    if start is not None or end is not None:
        if type(start) is not int or type(end) is not int or not 1024 <= start <= end <= 65535:
            raise ValueError('Invalid forwarding port range')
        ranges.append((start, end))
    for port in control_ports:
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('Invalid reserved control port')
        ranges.append((port, port))
    for item in existing.strip().split(',') if existing.strip() else []:
        if not re.fullmatch(r'[0-9]+(?:-[0-9]+)?', item):
            raise ValueError('Invalid existing port reservations')
        values = item.split('-')
        low, high = int(values[0]), int(values[-1])
        if not 1 <= low <= high <= 65535:
            raise ValueError('Invalid existing port reservations')
        ranges.append((low, high))
    merged = []
    for low, high in sorted(ranges):
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(high, merged[-1][1]))
        else:
            merged.append((low, high))
    return ','.join(str(low) if low == high else f'{low}-{high}' for low, high in merged)


def reserve_forwarding_ports(policy):
    # ip_local_reserved_ports replaces, rather than appends to, kernel state.
    # Preserve every existing reservation, including those of other services.
    current = pathlib.Path('/proc/sys/net/ipv4/ip_local_reserved_ports')
    existing = current.read_text().strip()
    # Reserve control ports only. Reserving the entire shared high-port pool
    # would exhaust automatic outbound allocation. Actual binds and kernel
    # ownership checks protect each selected forwarding port.
    desired = merged_port_reservations(existing, control_ports=policy['reserved_ports'])
    path = pathlib.Path('/etc/sysctl.d/zz-relaydeck-ports.conf')
    root_path(path.parent)
    if path.exists() or path.is_symlink():
        root_path(path)
        if not path.read_text().startswith('# Managed by RelayDeck\n'):
            raise ValueError(f'Existing sysctl configuration requires review: {path}')
    # Persist an atomic root-owned file; avoid following an unexpected link.
    with tempfile.TemporaryDirectory(prefix='relaydeck-sysctl-') as work:
        source = pathlib.Path(work) / 'ports.conf'
        source.write_text(f'# Managed by RelayDeck\nnet.ipv4.ip_local_reserved_ports = {desired}\n')
        atomic_copy(source, path, 0o644)
    run('sysctl', '-w', f'net.ipv4.ip_local_reserved_ports={desired}')
    return {'previous': existing, 'reserved': desired}


def confirm_update(yes):
    print('更新会中断全部转发，完成后恢复。', flush=True)
    if yes:
        return
    if not sys.stdin.isatty():
        raise ValueError('Use --yes to acknowledge the forwarding interruption in unattended updates')
    if input('继续更新？[y/N] ').strip().lower() not in ('y', 'yes'):
        raise ValueError('Update cancelled')


def install(args):
    preflight()
    if any(path.exists() or path.is_symlink() for path in (CONFIG, STATE, CURRENT, BIN, BIN.with_name('realm'), MANAGER, UPDATER)):
        raise ValueError('Existing installation detected; use update or migrate explicitly')
    origin, _ = deployment_origin(args.origin)
    if not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{2,31}', args.admin):
        raise ValueError('Invalid administrator name')
    with tempfile.TemporaryDirectory(prefix='relaydeck-install-') as work:
        stage = pathlib.Path(work) / 'release'
        manifest = prepare(args, stage)
        caddy = caddy_configuration((stage / 'deploy/Caddyfile.example').read_text(), origin)
        with verified_file(args.realm, args.realm_sha256) as realm:
            header = realm.read(20)
            machine = 183 if manifest['target'].startswith('aarch64') else 62
            if len(header) < 20 or header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != machine:
                raise ValueError('Realm must be a verified Linux executable')
            realm.seek(0)
            with (pathlib.Path(work) / 'realm').open('xb') as output:
                shutil.copyfileobj(realm, output)
        for unit in ALL_UNITS:
            path = pathlib.Path('/etc/systemd/system') / unit
            if path.exists() or path.is_symlink():
                raise ValueError(f'Existing unit requires review: {unit}')
        policy = json.loads((stage / 'deploy/broker.example.json').read_text())
        for slot in range(1, policy['max_owners'] + 1):
            uid = policy['uid_start'] + slot - 1
            name = f'relaydeck-runner-{slot}'
            for lookup, value in ((pwd.getpwuid, uid), (grp.getgrgid, uid), (pwd.getpwnam, name), (grp.getgrnam, name)):
                try:
                    lookup(value)
                except KeyError:
                    continue
                raise ValueError(f'Dedicated runtime identity already exists: {name}/{uid}')
        try:
            account = pwd.getpwnam('relaydeck')
            raise ValueError('Account relaydeck already exists; review its ownership before installation')
        except KeyError:
            run('useradd', '--system', '--user-group', '--home-dir', str(STATE), '--shell', '/usr/sbin/nologin', 'relaydeck')
            account = pwd.getpwnam('relaydeck')
        for slot in range(1, policy['max_owners'] + 1):
            uid = policy['uid_start'] + slot - 1
            name = f'relaydeck-runner-{slot}'
            run('groupadd', '--gid', str(uid), name)
            run('useradd', '--uid', str(uid), '--gid', str(uid), '--home-dir', '/nonexistent', '--no-create-home', '--shell', '/usr/sbin/nologin', name)
        for path in (CONFIG, STATE, STATE / 'runtime', RELEASES, BIN.parent, UPDATER.parent):
            path.mkdir(parents=True, exist_ok=True)
            root_path(path)
            path.chmod(0o755)
        for name in ('data', 'secrets', 'backups'):
            path = STATE / name
            path.mkdir(mode=0o700)
            os.chown(path, account.pw_uid, account.pw_gid)
        release = RELEASES / release_name(manifest)
        shutil.copytree(stage, release)
        atomic_copy(release / 'bin/relaydeck', BIN)
        atomic_copy(pathlib.Path(work) / 'realm', BIN.with_name('realm'))
        management_tools(release)
        current_link(release)
        policy = json.loads((release / 'deploy/broker.example.json').read_text())
        policy.update(web_uid=account.pw_uid, web_gid=account.pw_gid)
        reserve_control_ports(policy, origin)
        (CONFIG / 'broker.json').write_text(json.dumps(policy, indent=2) + '\n')
        (CONFIG / 'broker.json').chmod(0o644)
        environment = {
            'RELAYDECK_DATABASE': str(STATE / 'data/relaydeck.db'),
            'RELAYDECK_MFA_KEY': str(STATE / 'secrets/mfa.key'),
            'RELAYDECK_LISTEN': '127.0.0.1:7410',
            'RELAYDECK_ORIGIN': origin,
            'RELAYDECK_TRUST_PROXY': 'true',
            'RELAYDECK_FRONTEND': str(CURRENT / 'frontend'),
        }
        (CONFIG / 'relaydeck.env').write_text(''.join(f'{key}={value}\n' for key, value in environment.items()))
        os.chown(CONFIG / 'relaydeck.env', 0, account.pw_gid)
        (CONFIG / 'relaydeck.env').chmod(0o640)
        (CONFIG / 'Caddyfile').write_text(caddy)
        (CONFIG / 'Caddyfile').chmod(0o644)
        reservations = reserve_forwarding_ports(policy)
        hashes = {}
        for unit in ALL_UNITS:
            destination = pathlib.Path('/etc/systemd/system') / unit
            if destination.exists() or destination.is_symlink():
                raise ValueError(f'Existing unit requires review: {unit}')
            atomic_copy(release / 'deploy' / unit, destination, 0o644)
            hashes[unit] = digest(destination)
        (CONFIG / 'installation.json').write_text(json.dumps({'units': hashes, 'port_reservations': reservations}) + '\n')
        (CONFIG / 'installation.json').chmod(0o644)
        as_web(BIN, 'init-admin', args.admin)
        ensure_upgrade_policy()
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', '--now', *ALL_UNITS)
        wait_health(manifest['version'])
        print('Installed. Import /etc/relaydeck/Caddyfile into your Caddy configuration before public use. Updates: sudo relaydeck-update --bundle <release.tar.gz> --sha256 <trusted-digest>')
        print(f'Panel: {origin} (open its TCP port and TCP 80 for certificate issuance/renewal).')



def verify_cached_release(existing, stage):
    root_path(existing)
    present = {path.relative_to(existing) for path in existing.rglob('*')}
    expected = {path.relative_to(stage) for path in stage.rglob('*')}
    if present != expected:
        raise ValueError('Cached release contents differ from the verified bundle')
    for relative in expected:
        path = existing / relative
        root_path(path)
        if path.is_symlink():
            raise ValueError('Cached release contains a link')
        source = stage / relative
        if path.is_dir() != source.is_dir() or path.is_file() != source.is_file() or path.is_file() and (path.stat().st_nlink != 1 or digest(path) != digest(source)):
            raise ValueError('Cached release contents differ from the verified bundle')

class UpdateRolledBack(RuntimeError):
    pass


def restore_transaction(record):
    previous = pathlib.Path(record['previous'])
    release = pathlib.Path(record['release'])
    for path in (previous, release):
        root_path(path)
        if path.parent != RELEASES:
            raise ValueError('Unexpected recovery release path')
    old_version = json.loads((previous / 'release.json').read_text())['version']
    run('systemctl', 'stop', *UNITS)
    if record['backup']:
        backup = pathlib.Path(record['backup'])
        if backup.parent != STATE / 'backups' or not re.fullmatch('update-[0-9]+', backup.name):
            raise ValueError('Unexpected recovery backup path')
        restore = "import sqlite3,sys;from urllib.parse import quote;s=sqlite3.connect('file:'+quote(sys.argv[1])+'?mode=ro',uri=True);assert s.execute('PRAGMA quick_check').fetchone()[0]=='ok';d=sqlite3.connect(sys.argv[2]);s.backup(d);d.close();s.close()"
        run('runuser', '-u', 'relaydeck', '--', 'python3', '-c', restore, str(backup / 'relaydeck.db'), str(STATE / 'data/relaydeck.db'), env=SAFE_ENV)
    atomic_copy(previous / 'bin/relaydeck', BIN)
    current_link(previous)
    management_tools(previous)
    for unit in ALL_UNITS:
        destination = pathlib.Path('/etc/systemd/system') / unit
        source = previous / 'deploy' / unit
        if source.is_file():
            atomic_copy(source, destination, 0o644)
        elif unit == UPGRADE_UNIT and destination.exists():
            root_path(destination)
            if digest(destination) != digest(release / 'deploy' / unit):
                raise ValueError('Introduced updater unit was modified; manual recovery required')
            destination.unlink()
    run('systemctl', 'daemon-reload')
    run('systemctl', 'reset-failed', *UNITS)
    # The service hashes correspond to the restored release as well.
    atomic_json(CONFIG / 'installation.json', record['installation'], 0o644)
    if 'broker_policy' in record:
        atomic_json(CONFIG / 'broker.json', record['broker_policy'], 0o644)
    record['phase'] = 'rolled_back'
    atomic_json(TRANSACTION, record)
    run('systemctl', 'start', *UNITS)
    wait_health(old_version)
    TRANSACTION.unlink()


def recover_update():
    preflight()
    with manage_lock():
        if not TRANSACTION.exists():
            return False
        root_path(TRANSACTION)
        record = json.loads(TRANSACTION.read_text())
        if record.get('phase') == 'rolled_back':
            run('systemctl', 'start', *UNITS)
            wait_health(json.loads((pathlib.Path(record['previous']) / 'release.json').read_text())['version'])
            TRANSACTION.unlink()
            return True
        if record.get('phase') == 'committed':
            TRANSACTION.unlink()
            return False
        restore_transaction(record)
        return True


def update(args, progress=lambda step: None):
    preflight()
    confirm_update(args.yes)
    with manage_lock(), tempfile.TemporaryDirectory(prefix='relaydeck-update-') as work:
        if TRANSACTION.exists():
            raise ValueError('An interrupted upgrade must be recovered before another update')
        stage = pathlib.Path(work) / 'release'
        manifest = prepare(args, stage)
        root_path(CURRENT.resolve())
        previous = CURRENT.resolve()
        if previous.parent != RELEASES:
            raise ValueError('Current release is outside the managed release directory')
        record_path = CONFIG / 'installation.json'
        root_path(record_path)
        record = json.loads(record_path.read_text())
        previous_installation = json.loads(json.dumps(record))
        for unit in ALL_UNITS:
            path = pathlib.Path('/etc/systemd/system') / unit
            if unit == UPGRADE_UNIT and not path.exists() and unit not in record['units']:
                continue
            root_path(path)
            if digest(path) != record['units'].get(unit):
                raise ValueError(f'Unit {unit} was customized; preserve it with a systemd drop-in before updating')
        root_path(CONFIG / 'broker.json')
        policy = json.loads((CONFIG / 'broker.json').read_text())
        if not 64 <= policy['limits']['tasks'] <= 256:
            raise ValueError('Set limits.tasks to 64..256 in /etc/relaydeck/broker.json before upgrading the per-rule supervisor (default: 96)')
        previous_ports = list(policy['reserved_ports'])
        reserve_control_ports(policy, read_environment().get('RELAYDECK_ORIGIN', ''))
        # Only add control-port exclusions; keep the existing origin, proxy and
        # other policy settings intact, including when an upgrade rolls back.
        if policy['reserved_ports'] != previous_ports:
            atomic_json(CONFIG / 'broker.json', policy, 0o644)
        record['port_reservations'] = reserve_forwarding_ports(policy)
        ensure_upgrade_policy()
        release = RELEASES / release_name(manifest)
        if release == previous:
            raise ValueError('This release is already installed')
        if release.exists():
            verify_cached_release(release, stage)
        else:
            shutil.copytree(stage, release)
        backup = STATE / 'backups' / ('update-' + str(time.time_ns()))
        transaction = {'previous': str(previous), 'release': str(release), 'backup': None, 'phase': 'prepared', 'installation': previous_installation, 'broker_policy': policy.copy()}
        atomic_json(TRANSACTION, transaction)
        try:
            progress('backup')
            run('systemctl', 'stop', 'relaydeck-web.service', 'relaydeck-worker.service')
            as_web(BIN, 'backup', str(backup))
            transaction.update(backup=str(backup), phase='backed_up')
            atomic_json(TRANSACTION, transaction)
            run('systemctl', 'stop', 'relaydeck-broker.service')
            progress('install')
            # Shared-port releases replace tenant ranges with a quota. Keep the
            # prior root policy in the transaction so rollback restores it too.
            policy.update(allowed_port_start=1024, allowed_port_end=65535)
            atomic_json(CONFIG / 'broker.json', policy, 0o644)
            atomic_copy(release / 'bin/relaydeck', BIN)
            current_link(release)
            management_tools(release)
            for unit in ALL_UNITS:
                atomic_copy(release / 'deploy' / unit, pathlib.Path('/etc/systemd/system') / unit, 0o644)
            as_web(BIN, 'migrate')
            run('systemctl', 'daemon-reload')
            run('systemctl', 'reset-failed', *UNITS)
            run('systemctl', 'start', *UNITS)
            progress('health')
            wait_health(manifest['version'])
            record['units'] = {unit: digest(pathlib.Path('/etc/systemd/system') / unit) for unit in ALL_UNITS}
            atomic_json(record_path, record, 0o644)
            run('systemctl', 'enable', '--now', UPGRADE_UNIT)
            transaction['phase'] = 'committed'
            atomic_json(TRANSACTION, transaction)
            TRANSACTION.unlink()
        except BaseException as error:
            try:
                progress('rollback')
            except Exception:
                pass  # A progress-reporting failure must never prevent recovery.
            restore_transaction(transaction)
            raise UpdateRolledBack('更新失败：' + str(error)) from error
        print(f'Updated to {release.name}. Backup: {backup}')


def package(args):
    git = ['git', '-c', 'safe.directory=' + str(SOURCE)]
    revision = subprocess.check_output([*git, 'rev-parse', 'HEAD'], cwd=SOURCE, text=True).strip()
    if subprocess.check_output([*git, 'status', '--porcelain'], cwd=SOURCE, text=True).strip():
        raise ValueError('Commit source changes before packaging a release')
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--no-deps', '--format-version=1'], cwd=SOURCE))
    version = next(item['version'] for item in metadata['packages'] if item['name'] == 'relaydeck')
    output = pathlib.Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest = {'version': version, 'revision': revision, 'target': args.target}
    archive = output / ('relaydeck-' + release_name(manifest) + '.tar.gz')
    with tempfile.TemporaryDirectory(prefix='relaydeck-package-') as work:
        stage = pathlib.Path(work)
        (stage / 'bin').mkdir()
        shutil.copy2(pathlib.Path(os.environ.get('CARGO_TARGET_DIR', SOURCE / 'target')) / 'release/relaydeck', stage / 'bin/relaydeck')
        shutil.copytree(SOURCE / 'frontend/dist', stage / 'frontend')
        shutil.copytree(SOURCE / 'deploy', stage / 'deploy')
        shutil.copy2(SOURCE / 'scripts/manage.py', stage / 'deploy/manage.py')
        # Build-time only: the installed manager has no Cargo/Node dependency.
        import notices
        notices.collect(SOURCE, args.target, stage / 'deploy/licenses')
        (stage / 'release.json').write_text(json.dumps(manifest) + '\n')
        with tarfile.open(archive, 'w:gz') as tar:
            for child in sorted(stage.iterdir()):
                tar.add(child, arcname=child.name)
    (output / (archive.name + '.sha256')).write_text(digest(archive) + '  ' + archive.name + '\n')
    print(archive)


def main():
    parser = argparse.ArgumentParser(description='Verified releases, private data layout and update rollback')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('install', 'update', 'inspect'):
        sub = commands.add_parser(name)
        sub.add_argument('--bundle', type=pathlib.Path, required=True)
        sub.add_argument('--sha256', required=True, help='SHA-256 from a trusted release channel')
        if name == 'update':
            sub.add_argument('--yes', action='store_true', help='Acknowledge interruption of all forwarding')
        if name == 'install':
            sub.add_argument('--realm', type=pathlib.Path, required=True)
            sub.add_argument('--realm-sha256', required=True)
            sub.add_argument('--origin', required=True, help='HTTPS domain[:port]; new installations default to port 17443')
            sub.add_argument('--admin', required=True)
    commands.add_parser('recover')
    sub = commands.add_parser('package')
    sub.add_argument('--target', required=True)
    sub.add_argument('--output', default='dist')
    args = parser.parse_args()
    if args.command == 'recover':
        recover_update()
    elif args.command == 'inspect':
        with tempfile.TemporaryDirectory(prefix='relaydeck-inspect-') as work:
            print(json.dumps(extract_release(args.bundle, args.sha256, pathlib.Path(work))))
    else:
        globals()[args.command](args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from None
