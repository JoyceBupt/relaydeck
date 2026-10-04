"""Opt-in real Linux root CLI tests; all writes stay inside a new /run fixture."""
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('RELAYDECK_POLICY_TEST') == '1', 'Linux root policy gate only')
class PolicyPreparation(unittest.TestCase):
    def setUp(self):
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise RuntimeError('Policy tests require Linux root')
        directory = tempfile.TemporaryDirectory(prefix='relaydeck-policy-tests-', dir='/run')
        self.addCleanup(directory.cleanup)
        self.root = pathlib.Path(directory.name)
        self.root.chmod(0o755)
        self.binary = self.root / 'relaydeck'
        shutil.copyfile(os.environ['RELAYDECK_TEST_BINARY'], self.binary)
        self.binary.chmod(0o755)
        self.runtime = self.root / 'runtime'; self.runtime.mkdir(mode=0o755)
        self.source = self.root / 'policy.json'
        self.output = self.runtime / 'broker-effective.json'
        self.policy = json.loads((SOURCE / 'deploy/broker.example.json').read_text())
        self.policy.pop('port_policy_version')
        self.policy.update(allowed_port_start=40000, allowed_port_end=40999, runtime_dir=str(self.runtime),
                           reserved_ports=[22, 80, 443, 7410, 17443, 50762], local_ips=['8.8.4.4'])
        self.write_policy()

    def write_policy(self):
        self.source.write_text(json.dumps(self.policy))
        self.source.chmod(0o644)

    def prepare(self, *prefix, output=None, success=True):
        result = subprocess.run([*prefix, str(self.binary), 'prepare-broker-policy', str(self.source), str(output or self.output)], capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return result

    def test_legacy_policy_migrates_idempotently_without_touching_source_or_limits(self):
        original = self.source.read_bytes()
        self.prepare()
        effective = json.loads(self.output.read_text())
        expected = {**self.policy, 'port_policy_version': 2, 'allowed_port_start': 1024, 'allowed_port_end': 65535}
        self.assertEqual(effective, expected)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o644)
        self.assertEqual(self.output.stat().st_uid, 0)
        first = self.output.read_bytes()
        self.prepare()
        self.assertEqual(self.output.read_bytes(), first)
        self.assertEqual(self.source.read_bytes(), original)

    def test_version_two_keeps_explicit_operator_boundary(self):
        self.policy['port_policy_version'] = 2
        self.write_policy()
        self.prepare()
        self.assertEqual(json.loads(self.output.read_text()), self.policy)

    def test_web_identity_cannot_generate_or_replace_root_policy(self):
        self.prepare()
        before = self.output.read_bytes()
        result = self.prepare('setpriv', '--reuid', '65534', '--regid', '65534', '--clear-groups', success=False)
        self.assertIn('requires root', result.stderr)
        self.assertEqual(self.output.read_bytes(), before)

    def test_unsafe_destinations_cannot_overwrite_other_runtime_files(self):
        self.prepare()
        before = self.output.read_bytes()
        for destination in (self.source, self.runtime / 'plan.json', self.root / 'broker-effective.json'):
            with self.subTest(destination=destination):
                self.prepare(output=destination, success=False)
        self.assertEqual(self.output.read_bytes(), before)
        self.output.unlink()
        victim = self.runtime / 'unrelated'; victim.write_text('preserve')
        self.output.symlink_to(victim)
        self.prepare(success=False)
        self.assertEqual(victim.read_text(), 'preserve')
        self.output.unlink()
        self.output.symlink_to(self.runtime / 'missing')
        self.prepare(success=False)
        self.assertTrue(self.output.is_symlink())
        self.output.unlink()
        os.link(victim, self.output)
        self.prepare(success=False)
        self.assertEqual(victim.read_text(), 'preserve')

    def test_invalid_untrusted_or_oversized_source_keeps_last_valid_policy(self):
        self.prepare()
        before = self.output.read_bytes()
        for changes in ({'port_policy_version': 3}, {'web_uid': 0}, {'extra': 'unsupported'}, {'reserved_ports': ['17443']}):
            with self.subTest(changes=changes):
                self.source.write_text(json.dumps({**self.policy, **changes}))
                self.prepare(success=False)
                self.assertEqual(self.output.read_bytes(), before)
        self.write_policy()
        self.source.chmod(0o666)
        self.prepare(success=False)
        self.write_policy()
        self.source.write_text(self.source.read_text() + ' ' * (16 * 1024))
        self.prepare(success=False)
        self.assertEqual(self.output.read_bytes(), before)
        self.write_policy()
        linked = self.root / 'linked'; os.link(self.source, linked)
        self.prepare(success=False)
        linked.unlink()
        self.source.unlink()
        self.source.symlink_to(self.output)
        self.prepare(success=False)


if __name__ == '__main__':
    unittest.main()
