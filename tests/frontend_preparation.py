"""Linux root gates: legacy modes, privileged prestart and actual nonroot HTTP.

All files, databases and optional systemd units belong to a fresh /run fixture.
No installed panel, account database, firewall or real broker is accessed.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
import urllib.error
import socket

SOURCE = pathlib.Path(__file__).resolve().parents[1]
UID = 65534
IDENTITY = ['setpriv', '--reuid', str(UID), '--regid', str(UID), '--clear-groups']


@unittest.skipUnless(os.environ.get('RELAYDECK_POLICY_TEST') == '1', 'Linux root frontend gate only')
class FrontendPreparation(unittest.TestCase):
    def setUp(self):
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise RuntimeError('Frontend tests require Linux root')
        directory = tempfile.TemporaryDirectory(prefix='relaydeck-frontend-tests-', dir='/run')
        self.addCleanup(directory.cleanup)
        self.root = pathlib.Path(directory.name); self.root.chmod(0o755)
        self.releases = self.root / 'releases'; self.releases.mkdir(mode=0o755)
        self.release = self.releases / 'verified-release'; self.release.mkdir(mode=0o700)
        self.front = self.release / 'frontend'; self.front.mkdir(mode=0o700)
        (self.front / 'assets').mkdir(mode=0o700)
        self.html = b'<script type="module" src="/assets/app.js"></script><link rel="stylesheet" href="/assets/app.css">'
        (self.front / 'index.html').write_bytes(self.html)
        (self.front / 'assets/app.js').write_text('export default 1')
        (self.front / 'assets/app.css').write_text('body{}')
        for path in self.front.rglob('*'):
            if path.is_file(): path.chmod(0o644)
        self.current = self.root / 'current'; self.current.symlink_to(self.release)
        self.manager = self.root / 'manage.py'; shutil.copyfile(SOURCE / 'scripts/manage.py', self.manager); self.manager.chmod(0o644)
        self.wrapper = self.root / 'prestart.py'
        self.wrapper.write_text("import importlib.util,pathlib,sys\nspec=importlib.util.spec_from_file_location('installed_manager'," + repr(str(self.manager)) + ")\nm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\nm.CURRENT=pathlib.Path(" + repr(str(self.current)) + ")\nm.RELEASES=pathlib.Path(" + repr(str(self.releases)) + ")\nm.main()\n")
        self.wrapper.chmod(0o644)

    def prepare(self, success=True, identity=()):
        result = subprocess.run([*identity, sys.executable, '-B', str(self.wrapper), 'prepare-frontend'], capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def test_root_only_payload_is_readable_but_not_writable_after_preparation(self):
        private = self.root / 'private'; private.mkdir(mode=0o700)
        key = private / 'mfa.key'; key.write_bytes(b'private fixture'); key.chmod(0o600)
        self.prepare()
        self.prepare()
        subprocess.run([*IDENTITY, 'cat', str(self.front / 'index.html')], check=True, stdout=subprocess.DEVNULL)
        result = subprocess.run([*IDENTITY, sys.executable, '-c', 'import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(b"unauthorized")', str(self.front / 'index.html')], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.front / 'index.html').read_bytes(), self.html)
        self.assertEqual(private.stat().st_mode & 0o7777, 0o700)
        self.assertEqual(key.stat().st_mode & 0o7777, 0o600)

    def test_missing_entry_asset_rejects_startup_before_exposing_the_release(self):
        (self.front / 'assets/app.js').unlink()
        self.prepare(success=False)
        self.assertEqual(self.release.stat().st_mode & 0o7777, 0o700)
        self.assertEqual(self.front.stat().st_mode & 0o7777, 0o700)

    def test_web_identity_cannot_prepare_release_permissions(self):
        self.prepare(success=False, identity=IDENTITY)
        self.assertEqual(self.release.stat().st_mode & 0o7777, 0o700)

    def test_links_and_shared_files_are_rejected_before_changing_any_modes(self):
        outside = self.root / 'private.key'; outside.write_bytes(b'preserve'); outside.chmod(0o600)
        bad = self.front / 'assets/link'
        for kind in ['symlink', 'hardlink', 'fifo']:
            with self.subTest(kind=kind):
                if kind == 'symlink': bad.symlink_to(outside)
                elif kind == 'hardlink': os.link(outside, bad)
                else: os.mkfifo(bad, 0o600)
                self.prepare(success=False)
                self.assertEqual(self.release.stat().st_mode & 0o7777, 0o700)
                self.assertEqual(self.front.stat().st_mode & 0o7777, 0o700)
                self.assertEqual(outside.stat().st_mode & 0o7777, 0o600)
                bad.unlink()

    def test_writable_or_foreign_owned_entries_are_rejected(self):
        entry = self.front / 'assets/app.js'
        entry.chmod(0o666); self.prepare(success=False); entry.chmod(0o644)
        os.chown(entry, UID, UID); self.prepare(success=False); os.chown(entry, 0, 0)
        os.lchown(self.current, UID, UID); self.prepare(success=False); os.lchown(self.current, 0, 0)
        self.current.unlink(); self.current.symlink_to(self.root)
        self.prepare(success=False)
        self.assertEqual(self.release.stat().st_mode & 0o7777, 0o700)

    def test_actual_web_process_exposes_page_assets_and_json_api_errors(self):
        binary = self.root / 'relaydeck'; shutil.copyfile(os.environ['RELAYDECK_TEST_BINARY'], binary); binary.chmod(0o755)
        state = self.root / 'state'; state.mkdir(mode=0o755)
        for name in ['data', 'secrets']:
            path = state / name; path.mkdir(mode=0o700); os.chown(path, UID, UID)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'RELAYDECK_DATABASE': str(state / 'data/panel.db'), 'RELAYDECK_MFA_KEY': str(state / 'secrets/mfa.key'), 'RELAYDECK_FRONTEND': str(self.current / 'frontend'), 'RELAYDECK_LISTEN': f'127.0.0.1:{port}', 'RELAYDECK_ORIGIN': base}
        subprocess.run([*IDENTITY, str(binary), 'init-key'], env=env, check=True, capture_output=True)
        log = self.root / 'web.log'
        with log.open('wb') as output:
            process = subprocess.Popen([*IDENTITY, str(binary), 'serve'], env=env, stdout=output, stderr=output)
            try:
                for _ in range(100):
                    if process.poll() is not None: self.fail(log.read_text())
                    try:
                        with urllib.request.urlopen(base + '/api/health', timeout=1) as r: self.assertEqual(r.status, 200)
                        break
                    except OSError: time.sleep(0.05)
                else: self.fail('Web process did not start: ' + log.read_text())
                with self.assertRaises(urllib.error.HTTPError) as failed:
                    urllib.request.urlopen(base + '/', timeout=1)
                self.assertEqual(failed.exception.code, 404)
                self.prepare()
                for path, expected, kind in [('/', self.html, 'text/html'), ('/settings', self.html, 'text/html'), ('/assets/app.js', b'export default 1', 'text/javascript'), ('/assets/app.css', b'body{}', 'text/css')]:
                    with urllib.request.urlopen(base + path, timeout=1) as response:
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.read(), expected)
                        self.assertEqual(response.headers.get_content_type(), kind)
                with self.assertRaises(urllib.error.HTTPError) as missing:
                    urllib.request.urlopen(base + '/api/not-found', timeout=1)
                self.assertEqual(missing.exception.code, 404)
                self.assertIn('application/json', missing.exception.headers['Content-Type'])
                self.assertEqual((state / 'secrets').stat().st_mode & 0o7777, 0o700)
            finally:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)

    @unittest.skipUnless(os.environ.get('RELAYDECK_SYSTEMD_TEST') == '1', 'Native systemd runner only')
    def test_existing_service_and_slice_caps_are_removed_after_upgrade(self):
        name = 'rdresource' + str(os.getpid())
        directory = pathlib.Path('/run/systemd/system')
        service = directory / (name + '.service')
        slice_file = directory / (name + '.slice')
        self.assertFalse(service.exists())
        self.assertFalse(slice_file.exists())
        slice_text = (SOURCE / 'deploy/relaydeck.slice').read_text()
        resource_keys = ('MemoryHigh=', 'MemoryMax=', 'MemorySwapMax=', 'TasksMax=', 'CPUQuota=', 'LimitNOFILE=')
        resources = '\n'.join(line for line in (SOURCE / 'deploy/relaydeck-web.service').read_text().splitlines() if line.startswith(resource_keys))
        base = '[Service]\nType=exec\nUser=65534\nGroup=65534\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nSlice=' + name + '.slice\nExecStart=/usr/bin/sleep 60\n'
        slice_file.write_text(slice_text.replace('MemoryMax=infinity', 'MemoryMax=256M').replace('CPUQuota=\n', 'CPUQuota=100%\n'))
        service.write_text(base + 'MemoryHigh=32M\nMemoryMax=64M\nMemorySwapMax=0\nCPUQuota=20%\nTasksMax=96\nLimitNOFILE=4096\n')
        def group(unit):
            value = subprocess.check_output(['systemctl', 'show', unit, '-p', 'ControlGroup', '--value'], text=True).strip()
            self.assertTrue(value)
            return pathlib.Path('/sys/fs/cgroup') / value.lstrip('/')
        try:
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            subprocess.run(['systemctl', 'start', service.name], check=True)
            self.assertEqual((group(service.name) / 'memory.high').read_text().strip(), str(32 * 1024 * 1024))
            self.assertEqual((group(slice_file.name) / 'memory.max').read_text().strip(), str(256 * 1024 * 1024))
            self.assertEqual((group(service.name) / 'cpu.max').read_text().split()[0], '20000')
            slice_file.write_text(slice_text)
            service.write_text(base + resources + '\n')
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            subprocess.run(['systemctl', 'restart', service.name], check=True)
            for unit in (service.name, slice_file.name):
                path = group(unit)
                for field in ('memory.high', 'memory.max', 'memory.swap.max', 'pids.max'):
                    self.assertEqual((path / field).read_text().strip(), 'max', unit + ':' + field)
                cpu = path / 'cpu.max'
                if cpu.is_file():
                    self.assertEqual(cpu.read_text().split()[0], 'max')
                else:
                    # systemd disables an unused controller after clearing quotas.
                    self.assertEqual(subprocess.check_output(['systemctl', 'show', unit, '-p', 'CPUQuotaPerSecUSec', '--value'], text=True).strip(), 'infinity')
            pid = subprocess.check_output(['systemctl', 'show', service.name, '-p', 'MainPID', '--value'], text=True).strip()
            line = next(line for line in pathlib.Path('/proc', pid, 'limits').read_text().splitlines() if line.startswith('Max open files'))
            self.assertTrue(all(int(value) > 4096 for value in line[len('Max open files'):].split()[:2]))
        finally:
            subprocess.run(['systemctl', 'stop', service.name, slice_file.name], check=False, capture_output=True)
            service.unlink(); slice_file.unlink()
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            subprocess.run(['systemctl', 'reset-failed', service.name], check=False, capture_output=True)

    @unittest.skipUnless(os.environ.get('RELAYDECK_SYSTEMD_TEST') == '1', 'Native systemd runner only')
    def test_systemd_privileged_prestart_keeps_main_command_nonroot(self):
        self.assertTrue(pathlib.Path('/run/systemd/system').is_dir())
        name = self.root.name + '.service'
        unit = pathlib.Path('/run/systemd/system') / name
        check = self.root / 'check.py'
        check.write_text('import os,pathlib;assert os.geteuid()==65534;assert pathlib.Path(' + repr(str(self.front / 'index.html')) + ').read_bytes()==' + repr(self.html) + '\n')
        check.chmod(0o644)
        unit.write_text('[Service]\nType=oneshot\nUser=65534\nGroup=65534\nUMask=0077\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nExecStartPre=+' + sys.executable + ' -B ' + str(self.wrapper) + ' prepare-frontend\nExecStart=' + sys.executable + ' -B ' + str(check) + '\n')
        unit.chmod(0o644)
        try:
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            result = subprocess.run(['systemctl', 'start', name], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(subprocess.check_output(['systemctl', 'show', name, '-p', 'ExecMainStatus', '--value'], text=True).strip(), '0')
        finally:
            subprocess.run(['systemctl', 'stop', name], check=False, capture_output=True)
            unit.unlink(); subprocess.run(['systemctl', 'daemon-reload'], check=True)
            subprocess.run(['systemctl', 'reset-failed', name], check=False, capture_output=True)


if __name__ == '__main__':
    unittest.main()
