"""Exercise the frozen v0.1.1 updater, including its already-imported module.

The fixture is scripts/manage.py from tag v0.1.1, kept verbatim so CI does not
need Git history or downloads. System services are confined to a temporary
installation; Linux root CI additionally executes the real policy CLI.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, closing, nullcontext
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = SOURCE / 'tests/fixtures/manage_v0_1_1.py'
FROZEN_SHA256 = '734e1b80c022b4917e6ca764e91fd32e3b6cb0ec748ae32869186b5d374ffd41'


class LegacyPanelUpdate(unittest.TestCase):
    def setUp(self):
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(), FROZEN_SHA256)
        spec = importlib.util.spec_from_file_location('legacy_manage', FIXTURE)
        self.tools = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tools)
        self.real_policy = os.environ.get('RELAYDECK_POLICY_TEST') == '1'
        if self.real_policy and (sys.platform != 'linux' or os.geteuid() != 0):
            raise RuntimeError('Real policy integration requires Linux root')
        temporary = tempfile.TemporaryDirectory(prefix='relaydeck-upgrade-tests-', dir='/run' if self.real_policy else None)
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name).resolve()
        self.config = self.root / 'config'; self.config.mkdir()
        self.state = self.root / 'state'; self.state.mkdir()
        self.units = self.root / 'units'; self.units.mkdir()
        self.releases = self.root / 'releases'; self.releases.mkdir()
        for directory in ('data', 'secrets', 'runtime'):
            (self.state / directory).mkdir()
        self.previous = self.releases / 'old'; self.previous.mkdir()
        self.new_source = self.root / 'new-source'; self.new_source.mkdir()
        for release, version, old in ((self.previous, '0.1.1', True), (self.new_source, '0.1.2', False)):
            (release / 'bin').mkdir(); (release / 'bin/relaydeck').write_bytes(b'old binary' if old else b'new binary')
            (release / 'deploy').mkdir()
            (release / 'release.json').write_text(json.dumps({'version': version}))
            (release / 'frontend/assets').mkdir(parents=True)
            (release / 'frontend/index.html').write_text('<script type="module" src="/assets/app.js"></script><link rel="stylesheet" href="/assets/app.css">')
            (release / 'frontend/assets/app.js').write_text('export default 1')
            (release / 'frontend/assets/app.css').write_text('body{}')
            for directory in [release / 'frontend', release / 'frontend/assets']: directory.chmod(0o755 if old else 0o700)
            if not old: release.chmod(0o700)
            for name in self.tools.ALL_UNITS:
                text = (SOURCE / 'deploy' / name).read_text()
                if old and name == 'relaydeck-broker.service':
                    text = '[Service]\nExecStart=/usr/local/libexec/relaydeck broker /etc/relaydeck/broker.json\n'
                if old and name == 'relaydeck-web.service':
                    text = '[Service]\nExecStart=/usr/local/libexec/relaydeck serve\n'
                if old and name == 'relaydeck-worker.service':
                    text = '[Service]\nExecStart=/usr/local/libexec/relaydeck worker /etc/relaydeck/broker.json\n'
                (release / 'deploy' / name).write_text(text)
            shutil.copyfile(FIXTURE if old else SOURCE / 'scripts/manage.py', release / 'deploy/manage.py')
            for name in ('relaydeck-upgrader.py', 'relaydeck-update'):
                (release / 'deploy' / name).write_text('#!/bin/sh\n')
        for unit in self.tools.ALL_UNITS:
            shutil.copyfile(self.previous / 'deploy' / unit, self.units / unit)
        self.current = self.root / 'current'; self.current.symlink_to(self.previous)
        self.binary = self.root / 'relaydeck'; shutil.copyfile(self.previous / 'bin/relaydeck', self.binary)
        self.manager = self.root / 'manage.py'; shutil.copyfile(FIXTURE, self.manager)
        self.database = self.state / 'data/relaydeck.db'
        with closing(sqlite3.connect(self.database)) as db:
            for migration in sorted((SOURCE / 'migrations').glob('*.sql')):
                if migration.name.startswith('0008'): break
                db.executescript(migration.read_text())
            db.execute("INSERT INTO users(id,username,password_hash,role,must_change_password,port_start,port_end,max_rules,created_at,mfa_secret) VALUES(1,'admin','fixture hash','admin',0,40000,40009,10,1,'fixture encrypted secret')")
            db.execute("INSERT INTO rules(id,owner_id,name,listen_port,target_host,target_ip,target_port,protocol,created_at,updated_at) VALUES(1,1,'kept rule',40001,'8.8.8.8','8.8.8.8',443,'both',1,1)")
            db.execute('INSERT INTO port_leases VALUES(40001,1,1,1)')
            db.commit()
        (self.state / 'secrets/mfa.key').write_bytes(b'fixture key preserved byte-for-byte')
        self.policy = json.loads((SOURCE / 'deploy/broker.example.json').read_text())
        self.policy['limits'] = {'tasks': 96}
        self.policy.pop('port_policy_version')
        self.policy.update(database=str(self.database), runtime_dir=str(self.state / 'runtime'), allowed_port_start=40000, allowed_port_end=40999)
        (self.config / 'broker.json').write_text(json.dumps(self.policy))
        self.original_policy = (self.config / 'broker.json').read_bytes()
        (self.config / 'relaydeck.env').write_text(f'RELAYDECK_DATABASE={self.database}\nRELAYDECK_MFA_KEY={self.state}/secrets/mfa.key\nRELAYDECK_ORIGIN=https://panel.example.com:17443\n')
        (self.config / 'Caddyfile').write_text('existing Caddy configuration')
        self.installation = {'units': {name: self.tools.digest(self.units / name) for name in self.tools.ALL_UNITS}}
        (self.config / 'installation.json').write_text(json.dumps(self.installation))
        self.transaction = self.state / 'upgrade-transaction.json'
        self.fail = None
        self.starts = []
        self.reserved = []
        self.preparations = []
        self.web_preparations = []
        patches = ExitStack(); self.addCleanup(patches.close)
        # Redirect the frozen module's sole hard-coded unit directory, without
        # replacing pathlib globally or allowing any real systemctl invocation.
        def path(*args):
            value = pathlib.Path(*args)
            if value == pathlib.Path('/etc/systemd/system'): return self.units
            if value == pathlib.Path('/usr/local/libexec/relaydeck-upgrader.py'): return self.root / 'upgrader'
            return value
        def root_path(value):
            value.resolve().relative_to(self.root)
        def prepare(_, stage):
            shutil.copytree(self.new_source, stage)
            return {'version': '0.1.2', 'revision': 'fixture1', 'target': 'x86_64-unknown-linux-gnu'}
        def reserve(policy):
            value = self.tools.merged_port_reservations('', policy['allowed_port_start'], policy['allowed_port_end'], policy['reserved_ports'])
            self.reserved.append(value)
            return {'after': value}
        def current_link(release):
            release.resolve().relative_to(self.releases)
            self.current.unlink()
            self.current.symlink_to(release)
        replacements = dict(CONFIG=self.config, STATE=self.state, RELEASES=self.releases, CURRENT=self.current,
                            BIN=self.binary, MANAGER=self.manager, UPDATER=self.root / 'update',
                            TRANSACTION=self.transaction, pathlib=SimpleNamespace(Path=path), root_path=root_path,
                            preflight=lambda: None, manage_lock=nullcontext, prepare=prepare,
                            ensure_upgrade_policy=lambda: None, reserve_forwarding_ports=reserve, current_link=current_link,
                            run=self.service, as_web=self.as_web, wait_health=self.health)
        for name, value in replacements.items(): patches.enter_context(patch.object(self.tools, name, value))

    def as_web(self, _, command, *args):
        if command == 'backup':
            backup = pathlib.Path(args[0]); backup.mkdir(parents=True)
            with closing(sqlite3.connect(self.database)) as source, closing(sqlite3.connect(backup / 'relaydeck.db')) as destination:
                source.backup(destination)
            shutil.copyfile(self.state / 'secrets/mfa.key', backup / 'mfa.key')
        elif command == 'migrate':
            with closing(sqlite3.connect(self.database)) as db:
                db.executescript(next((SOURCE / 'migrations').glob('0008*.sql')).read_text())
        else: raise AssertionError(command)

    def service(self, *args, **kwargs):
        if args[0] == 'runuser':
            self.assertEqual(args[4:6], ('python3', '-c'))
            for value in args[7:]: pathlib.Path(value).resolve().relative_to(self.root)
            subprocess.run([sys.executable, *args[5:]], check=True)
            return
        self.assertEqual(args[0], 'systemctl')
        if args[1] != 'start': return
        if 'relaydeck-web.service' in args:
            web = (self.units / 'relaydeck-web.service').read_text()
            for line in web.splitlines():
                if not line.startswith('ExecStartPre='): continue
                command = shlex.split(line.split('=', 1)[1])
                self.assertEqual(command, ['+/usr/bin/python3', '-B', '/usr/local/libexec/relaydeck-manage.py', 'prepare-frontend'])
                self.web_preparations.append(command)
                if self.real_policy:
                    spec = importlib.util.spec_from_file_location('new_disk_manager', self.manager)
                    new = importlib.util.module_from_spec(spec); spec.loader.exec_module(new)
                    new.CURRENT = self.current; new.RELEASES = self.releases
                    new.prepare_frontend()
        broker = (self.units / 'relaydeck-broker.service').read_text()
        self.starts.append(broker)
        if 'ExecStartPre=' not in broker: return
        command = shlex.split(next(line.split('=', 1)[1] for line in broker.splitlines() if line.startswith('ExecStartPre=')))
        self.assertEqual(command, ['/usr/local/libexec/relaydeck', 'prepare-broker-policy', '/etc/relaydeck/broker.json', '/var/lib/relaydeck/runtime/broker-effective.json'])
        self.preparations.append(command)
        if self.fail == 'prestart': raise RuntimeError('injected prestart failure')
        if self.real_policy:
            subprocess.run([os.environ['RELAYDECK_TEST_BINARY'], command[1], str(self.config / 'broker.json'), str(self.state / 'runtime/broker-effective.json')], check=True)

    def health(self, version):
        if self.fail == 'health' and version == '0.1.2': raise RuntimeError('injected health failure')

    def grant(self):
        with closing(sqlite3.connect(self.database)) as db:
            return db.execute('SELECT id,password_hash,mfa_secret,port_start,port_end,max_rules FROM users').fetchone()

    def assert_preserved(self):
        self.assertEqual((self.config / 'broker.json').read_bytes(), self.original_policy)
        self.assertEqual((self.config / 'Caddyfile').read_text(), 'existing Caddy configuration')
        self.assertEqual((self.state / 'secrets/mfa.key').read_bytes(), b'fixture key preserved byte-for-byte')
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('SELECT * FROM port_leases').fetchall(), [(40001, 1, 1, 1)])
            self.assertEqual(db.execute('PRAGMA quick_check').fetchone()[0], 'ok')
        self.assertFalse(self.transaction.exists())

    def test_first_one_click_update_uses_new_units_despite_loaded_old_manager(self):
        old_function = self.tools.update
        self.tools.update(SimpleNamespace(yes=True))
        self.assertIs(self.tools.update, old_function)
        self.assertNotEqual(self.manager.read_bytes(), FIXTURE.read_bytes())
        self.assertEqual(len(self.preparations), 1)
        self.assertEqual(len(self.web_preparations), 1)
        self.assertEqual(self.grant(), (1, 'fixture hash', 'fixture encrypted secret', 1024, 65535, 10))
        self.assertNotIn('1024-65535', self.reserved[0])
        if self.real_policy:
            effective = json.loads((self.state / 'runtime/broker-effective.json').read_text())
            self.assertEqual((effective['port_policy_version'], effective['allowed_port_start'], effective['allowed_port_end']), (2, 1024, 65535))
        self.assert_preserved()

    @unittest.skipUnless(os.environ.get('RELAYDECK_POLICY_TEST') == '1', 'Linux root Web UID gate only')
    def test_legacy_update_reopens_root_only_frontend_without_exposing_private_state(self):
        self.root.chmod(0o755); self.releases.chmod(0o755)
        private = self.state / 'secrets'; private.chmod(0o700)
        before = private.stat().st_mode & 0o7777
        self.tools.update(SimpleNamespace(yes=True))
        index = self.current.resolve() / 'frontend/index.html'
        subprocess.run(['setpriv', '--reuid', '65534', '--regid', '65534', '--clear-groups', 'cat', str(index)], check=True, stdout=subprocess.DEVNULL)
        self.assertEqual(private.stat().st_mode & 0o7777, before)
        self.assert_preserved()

    def test_startup_or_health_failure_rolls_back_old_database_units_and_policy(self):
        for failure in ('prestart', 'health'):
            with self.subTest(failure=failure):
                self.fail = failure
                with self.assertRaises(self.tools.UpdateRolledBack): self.tools.update(SimpleNamespace(yes=True))
                self.assertEqual(self.current.resolve(), self.previous)
                self.assertEqual(self.binary.read_bytes(), b'old binary')
                self.assertEqual(self.manager.read_bytes(), FIXTURE.read_bytes())
                self.assertNotIn('ExecStartPre=', self.starts[-1])
                self.assertEqual(self.grant(), (1, 'fixture hash', 'fixture encrypted secret', 40000, 40009, 10))
                self.assert_preserved()

    def test_restart_recovers_the_old_transaction_after_interrupted_install(self):
        captured = []
        def progress(step):
            if step == 'health': captured.append(self.transaction.read_bytes())
        self.tools.update(SimpleNamespace(yes=True), progress)
        self.transaction.write_bytes(captured[0])
        self.assertTrue(self.tools.recover_update())
        self.assertNotIn('ExecStartPre=', self.starts[-1])
        self.assertEqual(self.grant(), (1, 'fixture hash', 'fixture encrypted secret', 40000, 40009, 10))
        self.assert_preserved()


if __name__ == '__main__':
    unittest.main()
