#!/usr/bin/env python3
"""Root-owned release source, bounded IPC and durable systemd upgrade jobs."""
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import re
import secrets
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = 'JoyceBupt/relaydeck'
REPOSITORY_ID = 1403407084
POLICY = pathlib.Path('/etc/relaydeck/upgrade.json')
ROOT = pathlib.Path('/var/lib/relaydeck/updates')
SOCKET = pathlib.Path('/run/relaydeck-upgrade/control.sock')
CURRENT = pathlib.Path('/opt/relaydeck/current')
MANAGER = pathlib.Path('/usr/local/libexec/relaydeck-manage.py')
PROGRAM = pathlib.Path('/usr/local/libexec/relaydeck-upgrader.py')
ACTIVE = {'queued', 'downloading', 'verifying', 'updating', 'recovering'}
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
MAX_BUNDLE = 100 * 1024 * 1024


class UpgradeError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def root_path(path):
    for part in reversed([path, *path.parents]):
        info = part.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError('Unsafe upgrade path: ' + str(part))
    if path.is_file() and path.stat().st_nlink != 1:
        raise ValueError('Upgrade files must have one link')


def read_json(path):
    root_path(path)
    if not path.is_file() or path.stat().st_size > 32768:
        raise ValueError('Invalid upgrade state')
    return json.loads(path.read_text())


def write_json(path, data):
    root_path(path.parent)
    if path.exists() or path.is_symlink():
        root_path(path)
    fd, name = tempfile.mkstemp(prefix='.upgrade-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def policy():
    value = read_json(POLICY)
    if set(value) != {'owner_id', 'web_uid', 'web_gid'} or any(type(v) is not int or v <= 0 for v in value.values()):
        raise ValueError('Invalid owner upgrade policy')
    return value


def identity():
    path = CURRENT.resolve(strict=True)
    root_path(path)
    if path.parent != pathlib.Path('/opt/relaydeck/releases'):
        raise ValueError('Unexpected current release')
    return read_json(path / 'release.json')


def stable_version(value):
    if not isinstance(value, str) or not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', value):
        raise ValueError('Invalid stable release version')
    return tuple(map(int, value.split('.')))


class TrustedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != 'https' or parsed.hostname not in {'api.github.com', 'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'} or parsed.username or parsed.password or parsed.port not in (None, 443):
            raise ValueError('Untrusted release redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# No proxy or CA settings supplied by the Web request or inherited service environment.
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}), TrustedRedirect())


def response(path, binary=False):
    request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + path,
        headers={'Accept': 'application/octet-stream' if binary else 'application/vnd.github+json',
                 'User-Agent': 'RelayDeck-Upgrader', 'X-GitHub-Api-Version': '2022-11-28'})
    return HTTP.open(request, timeout=15)


def fetch_json(path):
    with response(path) as stream:
        data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError('Release metadata exceeds limit')
        return json.loads(data)


def candidate(release, current):
    tag = release.get('tag_name', '')
    if release.get('draft') is not False or release.get('prerelease') is not False or not tag.startswith('v'):
        raise ValueError('Only published stable releases can be installed')
    version = tag[1:]
    if stable_version(version) <= stable_version(current['version']):
        return None
    target = current['target']
    if target not in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'):
        raise ValueError('Unsupported installation architecture')
    matched = []
    for asset in release.get('assets', []):
        match = re.fullmatch(r'relaydeck-' + re.escape(version) + r'-([a-f0-9]{7,40})-' + re.escape(target) + r'\.tar\.gz', asset.get('name', ''))
        if match:
            if asset.get('state') != 'uploaded' or type(asset.get('id')) is not int or asset['id'] <= 0 or type(asset.get('size')) is not int or not 0 < asset['size'] <= MAX_BUNDLE or not re.fullmatch(r'sha256:[a-f0-9]{64}', asset.get('digest') or ''):
                raise ValueError('Release requires a GitHub SHA-256 asset digest')
            matched.append({'version': version, 'revision': match[1], 'target': target,
                            'asset_id': asset['id'], 'size': asset['size'], 'sha256': asset['digest'][7:]})
    if len(matched) != 1 or type(release.get('id')) is not int or release['id'] <= 0:
        raise ValueError('A single matching architecture bundle is required')
    return {**matched[0], 'release_id': release['id'], 'release_url': 'https://github.com/' + REPOSITORY + '/releases/tag/' + tag}


def manager():
    root_path(MANAGER)
    spec = importlib.util.spec_from_file_location('relaydeck_manage', MANAGER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



def maintenance_busy():
    import fcntl
    path = pathlib.Path('/etc/relaydeck/maintenance.lock')
    if not path.exists():
        return False
    root_path(path)
    with path.open('r') as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return False
        except BlockingIOError:
            return True

def job_path(identifier):
    if not re.fullmatch('[a-f0-9]{32}', identifier):
        raise ValueError('Invalid upgrade job')
    return ROOT / ('job-' + identifier + '.json')


def job_unit(identifier):
    job_path(identifier)
    return 'relaydeck-upgrade-job-' + identifier + '.service'


def launch(identifier, recover=False):
    root_path(PROGRAM)
    subprocess.run(['systemd-run', '--quiet', '--no-block', '--collect', '--unit=' + job_unit(identifier),
        '--property=Type=exec', '--property=RuntimeMaxSec=600', '--property=TimeoutStopSec=90',
        '--property=UMask=0077', '--property=MemoryMax=384M', '--property=TasksMax=32',
        '/usr/bin/python3', '-B', str(PROGRAM), 'recover-job' if recover else 'run-job', identifier],
        check=True, env=ENV, timeout=10, capture_output=True)


def update_status(identifier, phase, **extra):
    value = read_json(ROOT / 'status.json')
    if value['id'] != identifier:
        raise ValueError('Upgrade state changed unexpectedly')
    previous = (value['phase'], value.get('step'))
    value.update(phase=phase, updated_at=int(time.time()), **extra)
    write_json(ROOT / 'status.json', value)
    if previous != (value['phase'], value.get('step')):
        print(f"Upgrade job {identifier}: phase={phase} step={value.get('step')} version={value['version']}", flush=True)


def download(offer, destination, identifier):
    checksum = hashlib.sha256()
    total = 0
    end = time.monotonic() + 180
    with response('/releases/assets/' + str(offer['asset_id']), binary=True) as stream, destination.open('xb') as output:
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            if total > offer['size'] or total > MAX_BUNDLE or time.monotonic() > end:
                raise ValueError('Release download exceeded its limit')
            checksum.update(chunk)
            output.write(chunk)
            update_status(identifier, 'downloading', progress=round(total * 100 / offer['size']))
        output.flush()
        os.fsync(output.fileno())
    if total != offer['size'] or checksum.hexdigest() != offer['sha256']:
        raise ValueError('SHA-256 release verification failed')


def run_job(identifier, recover=False):
    record = read_json(job_path(identifier))
    print(f'Upgrade job {identifier}: started recovery={recover}', flush=True)
    try:
        tools = manager()
        if recover:
            reverted = tools.recover_update()
            update_status(identifier, 'rolled_back' if reverted else 'succeeded', step='complete', error='升级任务中断' if reverted else None)
            try:
                subprocess.run(['systemctl', 'restart', 'relaydeck-upgrader.service'], env=ENV, check=True, timeout=15)
            except Exception as reload_error:
                print('Updater reload pending: ' + str(reload_error), flush=True)
            return
        offer = record['release']
        if fetch_json('').get('id') != REPOSITORY_ID:
            raise ValueError('Release repository identity has changed')
        actual = candidate(fetch_json('/releases/' + str(offer['release_id'])), identity())
        if actual != offer:
            raise ValueError('Release identity changed after authorization')
        with tempfile.TemporaryDirectory(prefix='bundle-', dir=ROOT) as work:
            bundle = pathlib.Path(work) / 'release.tar.gz'
            update_status(identifier, 'downloading', step='download', progress=0)
            download(offer, bundle, identifier)
            update_status(identifier, 'verifying', step='verify', progress=100)
            with tempfile.TemporaryDirectory(prefix='verify-', dir=ROOT) as stage:
                manifest = tools.extract_release(bundle, offer['sha256'], pathlib.Path(stage))
                if manifest != {key: offer[key] for key in ('version', 'revision', 'target')}:
                    raise ValueError('Bundle manifest does not match the approved release')
            update_status(identifier, 'updating', step='backup')
            args = type('UpdateArguments', (), {'bundle': bundle, 'sha256': offer['sha256'], 'yes': True})()
            tools.update(args, progress=lambda step: update_status(identifier, 'updating', step=step))
        update_status(identifier, 'succeeded', step='complete', error=None)
        # The job is a separate unit; restarting the IPC service cannot kill it.
        try:
            subprocess.run(['systemctl', 'restart', 'relaydeck-upgrader.service'], env=ENV, check=True, timeout=15)
        except Exception as error:
            print('Updater reload pending: ' + str(error), flush=True)
    except Exception as error:
        phase = 'rolled_back' if error.__class__.__name__ == 'UpdateRolledBack' else 'failed'
        update_status(identifier, phase, step='complete', error=str(error)[:500])
        if phase == 'rolled_back':
            try:
                subprocess.run(['systemctl', 'restart', 'relaydeck-upgrader.service'], env=ENV, check=True, timeout=15)
            except Exception as reload_error:
                print('Updater reload pending: ' + str(reload_error), flush=True)
        raise


class Controller:
    def __init__(self):
        self.offer = None
        self.checked_at = 0
        self.checked_time = 0

    def status(self):
        job = read_json(ROOT / 'status.json') if (ROOT / 'status.json').exists() else None
        return {'checked_at': self.checked_time, 'current_version': identity()['version'], 'job': job, 'latest': self.offer, 'maintenance': maintenance_busy(), 'recovery_required': pathlib.Path('/var/lib/relaydeck/upgrade-transaction.json').exists()}

    def recover(self):
        if maintenance_busy():
            return
        state = self.status()
        job = state['job']
        if job and job['phase'] in ACTIVE:
            if job['phase'] == 'queued' and job['updated_at'] > int(time.time()) - 30:
                return
            active = subprocess.run(['systemctl', 'is-active', job_unit(job['id'])], env=ENV, capture_output=True, text=True, timeout=5).stdout.strip()
            if active in ('active', 'activating'):
                return
        journal = pathlib.Path('/var/lib/relaydeck/upgrade-transaction.json')
        if journal.exists():
            if not job or job['phase'] not in ACTIVE:
                identifier = secrets.token_hex(16)
                write_json(job_path(identifier), {'release': None})
                write_json(ROOT / 'status.json', {'id': identifier, 'version': state['current_version'], 'phase': 'recovering', 'step': 'rollback', 'started_at': int(time.time()), 'updated_at': int(time.time()), 'error': None})
            else:
                identifier = job['id']
                update_status(identifier, 'recovering', step='rollback')
            launch(identifier, recover=True)
        elif job and job['phase'] in ACTIVE:
            installed = identity()
            requested = read_json(job_path(job['id']))['release']
            if requested and all(installed[key] == requested[key] for key in ('version', 'revision', 'target')):
                update_status(job['id'], 'succeeded', step='complete', error=None)
            else:
                update_status(job['id'], 'failed', step='complete', error='升级任务中断，原版本保持运行')

    def dispatch(self, request):
        if not isinstance(request, dict):
            raise UpgradeError('invalid', '升级请求无效')
        op = request.get('op')
        if op == 'status' and set(request) == {'op'}:
            return self.status()
        if op == 'check' and set(request) == {'op'}:
            if self.checked_time and time.monotonic() - self.checked_at < 60:
                return self.status()
            try:
                release = fetch_json('/releases/latest')
            except urllib.error.HTTPError as error:
                if error.code != 404:
                    raise
                release = None
            value = candidate(release, identity()) if release else None
            previous = {key: item for key, item in (self.offer or {}).items() if key not in ('offer', 'expires_at')}
            if not value:
                self.offer = None
            elif previous != value or self.offer['expires_at'] < int(time.time()):
                self.offer = {**value, 'offer': secrets.token_hex(32), 'expires_at': int(time.time()) + 300}
            self.checked_at = time.monotonic()
            self.checked_time = int(time.time())
            return self.status()
        if op == 'start' and set(request) == {'op', 'offer'}:
            if maintenance_busy():
                raise UpgradeError('busy', '服务器维护正在进行')
            self.recover()
            state = self.status()
            if state['job'] and state['job']['phase'] in ACTIVE:
                raise UpgradeError('busy', '升级正在进行')
            if pathlib.Path('/var/lib/relaydeck/upgrade-transaction.json').exists():
                raise UpgradeError('recovery_required', '升级恢复尚未完成')
            if not isinstance(request['offer'], str) or not self.offer or self.offer['expires_at'] < int(time.time()) or not secrets.compare_digest(request['offer'], self.offer['offer']):
                raise UpgradeError('expired', '请重新检查更新')
            identifier = secrets.token_hex(16)
            release = {key: value for key, value in self.offer.items() if key not in ('offer', 'expires_at')}
            write_json(job_path(identifier), {'release': release})
            write_json(ROOT / 'status.json', {'id': identifier, 'version': release['version'], 'phase': 'queued', 'step': 'download', 'started_at': int(time.time()), 'updated_at': int(time.time()), 'error': None})
            self.offer = None
            try:
                launch(identifier)
            except Exception:
                update_status(identifier, 'failed', step='complete', error='升级任务启动失败')
                raise
            print(f"Upgrade job {identifier}: accepted version={release['version']}", flush=True)
            return self.status()
        raise UpgradeError('invalid', '升级请求无效')


def receive(stream, count):
    data = b''
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise ValueError('Incomplete upgrade frame')
        data += chunk
    return data


def serve():
    settings = policy()
    for path in (ROOT, SOCKET.parent):
        path.mkdir(mode=0o755, parents=True, exist_ok=True)
        root_path(path)
    controller = Controller()
    controller.recover()
    if SOCKET.exists():
        info = SOCKET.lstat()
        if info.st_uid != 0 or not stat.S_ISSOCK(info.st_mode):
            raise ValueError('Unsafe updater socket')
        SOCKET.unlink()
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(SOCKET))
        os.chown(SOCKET, 0, settings['web_gid'])
        SOCKET.chmod(0o660)
        listener.listen(8)
        listener.settimeout(2)
        while True:
            try:
                stream, _ = listener.accept()
            except socket.timeout:
                # Web may be stopped when a job is killed; recovery cannot depend on an HTTP poll.
                controller.recover()
                continue
            with stream:
                stream.settimeout(5)
                _, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != settings['web_uid']:
                    continue
                try:
                    size = struct.unpack('!I', receive(stream, 4))[0]
                    if not 0 < size <= 4096:
                        raise ValueError('Upgrade request exceeds size limit')
                    request = json.loads(receive(stream, size))
                    controller.recover()
                    data = controller.dispatch(request)
                    reply = {'data': data}
                except UpgradeError as error:
                    reply = {'error': error.code, 'message': str(error)}
                except Exception as error:
                    print('Upgrade request failed: ' + str(error), flush=True)
                    reply = {'error': 'unavailable', 'message': '升级服务暂不可用'}
                payload = json.dumps(reply).encode()
                try:
                    stream.sendall(struct.pack('!I', len(payload)) + payload)
                except OSError:
                    pass


if __name__ == '__main__':
    import sys
    if platform.system() != 'Linux' or os.geteuid() != 0:
        raise SystemExit('The updater requires root on Linux')
    if sys.argv[1:] == ['serve']:
        serve()
    elif len(sys.argv) == 3 and sys.argv[1] in ('run-job', 'recover-job'):
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(RuntimeError('Upgrade interrupted')))
        run_job(sys.argv[2], recover=sys.argv[1] == 'recover-job')
    else:
        raise SystemExit('Invalid updater command')
