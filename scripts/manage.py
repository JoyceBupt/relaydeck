#!/usr/bin/env python3
"""Package, install and update verified RelayDeck releases on systemd Linux."""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import pwd
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

SOURCE = pathlib.Path(__file__).resolve().parent.parent
STATE = pathlib.Path('/var/lib/relaydeck')
CONFIG = pathlib.Path('/etc/relaydeck')
RELEASES = pathlib.Path('/opt/relaydeck/releases')
CURRENT = pathlib.Path('/opt/relaydeck/current')
BIN = pathlib.Path('/usr/local/libexec/relaydeck')
UNITS = ('relaydeck-broker.service', 'relaydeck-web.service', 'relaydeck-worker.service')
ENV_KEYS = {'RELAYDECK_DATABASE', 'RELAYDECK_MFA_KEY', 'RELAYDECK_LISTEN', 'RELAYDECK_ORIGIN', 'RELAYDECK_TRUST_PROXY', 'RELAYDECK_FRONTEND'}
SAFE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}


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
        required = {'bin/relaydeck', 'frontend/index.html', 'release.json', 'deploy/broker.example.json', 'deploy/Caddyfile.example', *(f'deploy/{unit}' for unit in UNITS)}
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
    for command in ('systemctl', 'nft', 'bpftool', 'ss', 'ip', 'runuser'):
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


def install(args):
    preflight()
    if any(path.exists() or path.is_symlink() for path in (CONFIG, STATE, CURRENT, BIN, BIN.with_name('realm'))):
        raise ValueError('Existing installation detected; use update or migrate explicitly')
    url = urllib.parse.urlsplit(args.origin)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.path not in ('', '/') or url.query or url.fragment or not re.fullmatch('[a-zA-Z0-9.-]+', url.netloc):
        raise ValueError('Provide a plain HTTPS domain origin')
    if not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{2,31}', args.admin):
        raise ValueError('Invalid administrator name')
    with tempfile.TemporaryDirectory(prefix='relaydeck-install-') as work:
        stage = pathlib.Path(work) / 'release'
        manifest = prepare(args, stage)
        with verified_file(args.realm, args.realm_sha256) as realm:
            header = realm.read(20)
            machine = 183 if manifest['target'].startswith('aarch64') else 62
            if len(header) < 20 or header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != machine:
                raise ValueError('Realm must be a verified Linux executable')
            realm.seek(0)
            with (pathlib.Path(work) / 'realm').open('xb') as output:
                shutil.copyfileobj(realm, output)
        for unit in UNITS:
            path = pathlib.Path('/etc/systemd/system') / unit
            if path.exists() or path.is_symlink():
                raise ValueError(f'Existing unit requires review: {unit}')
        try:
            account = pwd.getpwnam('relaydeck')
            raise ValueError('Account relaydeck already exists; review its ownership before installation')
        except KeyError:
            run('useradd', '--system', '--user-group', '--home-dir', str(STATE), '--shell', '/usr/sbin/nologin', 'relaydeck')
            account = pwd.getpwnam('relaydeck')
        for path in (CONFIG, STATE, STATE / 'runtime', RELEASES, BIN.parent):
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
        current_link(release)
        policy = json.loads((release / 'deploy/broker.example.json').read_text())
        policy.update(web_uid=account.pw_uid, web_gid=account.pw_gid)
        (CONFIG / 'broker.json').write_text(json.dumps(policy, indent=2) + '\n')
        (CONFIG / 'broker.json').chmod(0o644)
        environment = {
            'RELAYDECK_DATABASE': str(STATE / 'data/relaydeck.db'),
            'RELAYDECK_MFA_KEY': str(STATE / 'secrets/mfa.key'),
            'RELAYDECK_LISTEN': '127.0.0.1:7410',
            'RELAYDECK_ORIGIN': args.origin.rstrip('/'),
            'RELAYDECK_TRUST_PROXY': 'true',
            'RELAYDECK_FRONTEND': str(CURRENT / 'frontend'),
        }
        (CONFIG / 'relaydeck.env').write_text(''.join(f'{key}={value}\n' for key, value in environment.items()))
        os.chown(CONFIG / 'relaydeck.env', 0, account.pw_gid)
        (CONFIG / 'relaydeck.env').chmod(0o640)
        (CONFIG / 'Caddyfile').write_text((release / 'deploy/Caddyfile.example').read_text().replace('panel.example.com', url.netloc))
        (CONFIG / 'Caddyfile').chmod(0o644)
        hashes = {}
        for unit in UNITS:
            destination = pathlib.Path('/etc/systemd/system') / unit
            if destination.exists() or destination.is_symlink():
                raise ValueError(f'Existing unit requires review: {unit}')
            atomic_copy(release / 'deploy' / unit, destination, 0o644)
            hashes[unit] = digest(destination)
        (CONFIG / 'installation.json').write_text(json.dumps({'units': hashes}) + '\n')
        (CONFIG / 'installation.json').chmod(0o644)
        as_web(BIN, 'init-admin', args.admin)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', '--now', *UNITS)
        wait_health(manifest['version'])
        print('Installed. Import /etc/relaydeck/Caddyfile into your Caddy configuration before public use.')


def update(args):
    preflight()
    with manage_lock(), tempfile.TemporaryDirectory(prefix='relaydeck-update-') as work:
        stage = pathlib.Path(work) / 'release'
        manifest = prepare(args, stage)
        root_path(CURRENT.resolve())
        previous = CURRENT.resolve()
        if previous.parent != RELEASES:
            raise ValueError('Current release is outside the managed release directory')
        old_version = json.loads((previous / 'release.json').read_text())['version']
        record_path = CONFIG / 'installation.json'
        root_path(record_path)
        record = json.loads(record_path.read_text())
        for unit in UNITS:
            path = pathlib.Path('/etc/systemd/system') / unit
            root_path(path)
            if digest(path) != record['units'].get(unit):
                raise ValueError(f'Unit {unit} was customized; preserve it with a systemd drop-in before updating')
        release = RELEASES / release_name(manifest)
        if release.exists():
            raise ValueError('This release is already installed')
        shutil.copytree(stage, release)
        backup = STATE / 'backups' / ('update-' + str(time.time_ns()))
        run('systemctl', 'stop', 'relaydeck-web.service', 'relaydeck-worker.service')
        try:
            as_web(BIN, 'backup', str(backup))
        except BaseException:
            run('systemctl', 'start', *UNITS)
            raise
        run('systemctl', 'stop', 'relaydeck-broker.service')
        try:
            atomic_copy(release / 'bin/relaydeck', BIN)
            current_link(release)
            for unit in UNITS:
                atomic_copy(release / 'deploy' / unit, pathlib.Path('/etc/systemd/system') / unit, 0o644)
            as_web(BIN, 'migrate')
            run('systemctl', 'daemon-reload')
            run('systemctl', 'start', *UNITS)
            wait_health(manifest['version'])
        except BaseException:
            run('systemctl', 'stop', *UNITS)
            # Restore SQLite through its backup API as the data UID. Root never parses it.
            restore = "import sqlite3,sys;from urllib.parse import quote;s=sqlite3.connect('file:'+quote(sys.argv[1])+'?mode=ro',uri=True);assert s.execute('PRAGMA quick_check').fetchone()[0]=='ok';d=sqlite3.connect(sys.argv[2]);s.backup(d);d.close();s.close()"
            run('runuser', '-u', 'relaydeck', '--', 'python3', '-c', restore, str(backup / 'relaydeck.db'), str(STATE / 'data/relaydeck.db'), env=SAFE_ENV)
            atomic_copy(previous / 'bin/relaydeck', BIN)
            current_link(previous)
            for unit in UNITS:
                atomic_copy(previous / 'deploy' / unit, pathlib.Path('/etc/systemd/system') / unit, 0o644)
            run('systemctl', 'daemon-reload')
            run('systemctl', 'start', *UNITS)
            wait_health(old_version)
            raise RuntimeError(f'Update failed and was rolled back. Backup: {backup}')
        record['units'] = {unit: digest(pathlib.Path('/etc/systemd/system') / unit) for unit in UNITS}
        record_path.write_text(json.dumps(record) + '\n')
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
        if name == 'install':
            sub.add_argument('--realm', type=pathlib.Path, required=True)
            sub.add_argument('--realm-sha256', required=True)
            sub.add_argument('--origin', required=True)
            sub.add_argument('--admin', required=True)
    sub = commands.add_parser('package')
    sub.add_argument('--target', required=True)
    sub.add_argument('--output', default='dist')
    args = parser.parse_args()
    if args.command == 'inspect':
        with tempfile.TemporaryDirectory(prefix='relaydeck-inspect-') as work:
            print(json.dumps(extract_release(args.bundle, args.sha256, pathlib.Path(work))))
    else:
        globals()[args.command](args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from None
