import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from contextlib import ExitStack, nullcontext

MODULE = pathlib.Path(__file__).resolve().parents[1] / 'scripts/manage.py'
spec = importlib.util.spec_from_file_location('relaydeck_manage', MODULE)
manage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manage)


class ReleaseValidation(unittest.TestCase):
    def archive(self, directory, extra=None, target='aarch64-unknown-linux-gnu'):
        path = directory / 'release.tar.gz'
        binary = bytearray(24)
        binary[:6] = b'\x7fELF\x02\x01'
        binary[18:20] = (183).to_bytes(2, 'little')
        entries = {
            'release.json': json.dumps({'version': '0.1.0', 'revision': 'abcdef0', 'target': target}).encode(),
            'bin/relaydeck': bytes(binary),
            'frontend/index.html': b'<!doctype html>',
            'deploy/broker.example.json': b'{}',
            'deploy/Caddyfile.example': b'panel.example.com {}',
            'deploy/manage.py': MODULE.read_bytes(),
            'deploy/relaydeck-upgrader.py': b'#!/usr/bin/env python3\n',
            'deploy/relaydeck-update': b'#!/bin/sh\nexec python3 /usr/local/libexec/relaydeck-manage.py update "$@"\n',
            **{f'deploy/{unit}': b'[Service]\nExecStart=/usr/local/libexec/relaydeck\n' for unit in manage.ALL_UNITS},
        }
        with tarfile.open(path, 'w:gz') as tar:
            for name, data in entries.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
            if extra is not None:
                tar.addfile(extra, io.BytesIO(b'x') if extra.isfile() else None)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_verified_release_extracts_without_preserving_archive_permissions(self):
        with tempfile.TemporaryDirectory() as work:
            root = pathlib.Path(work)
            archive, digest = self.archive(root)
            manifest = manage.extract_release(archive, digest, root / 'stage')
            self.assertEqual(manifest['revision'], 'abcdef0')
            self.assertEqual((root / 'stage/bin/relaydeck').stat().st_mode & 0o7777, 0o755)

    def test_digest_mismatch_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as work:
            root = pathlib.Path(work)
            archive, _ = self.archive(root)
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                manage.extract_release(archive, '0' * 64, root / 'stage')
            self.assertFalse((root / 'stage').exists())

    def test_traversal_links_duplicates_and_unexpected_binaries_are_rejected(self):
        for name, kind in (('../outside', tarfile.REGTYPE), ('frontend/link', tarfile.SYMTYPE),
                           ('frontend/hard', tarfile.LNKTYPE), ('frontend/index.html', tarfile.REGTYPE),
                           ('bin/other', tarfile.REGTYPE), ('frontend/pipe', tarfile.FIFOTYPE)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as work:
                root = pathlib.Path(work)
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = '/etc/passwd'
                member.size = 1 if member.isfile() else 0
                archive, digest = self.archive(root, member)
                with self.assertRaises(ValueError):
                    manage.extract_release(archive, digest, root / 'stage')
                self.assertFalse((root / 'stage').exists())

    def test_architecture_mismatch_and_missing_payload_are_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            root = pathlib.Path(work)
            archive, digest = self.archive(root, target='x86_64-unknown-linux-gnu')
            with self.assertRaisesRegex(ValueError, 'architecture'):
                manage.extract_release(archive, digest, root / 'stage')
            empty = root / 'empty.tar.gz'
            with tarfile.open(empty, 'w:gz'):
                pass
            with self.assertRaisesRegex(ValueError, 'Incomplete'):
                manage.extract_release(empty, manage.digest(empty), root / 'empty-stage')

    def test_verified_snapshot_cannot_change_when_source_is_rewritten(self):
        with tempfile.TemporaryDirectory() as work:
            root = pathlib.Path(work)
            archive, digest = self.archive(root)
            original = archive.read_bytes()
            with manage.verified_file(archive, digest) as snapshot:
                archive.write_bytes(b'replaced after verification')
                self.assertEqual(snapshot.read(), original)


class PortReservations(unittest.TestCase):
    def test_existing_ranges_are_preserved_and_merged(self):
        self.assertEqual(manage.merged_port_reservations('8080,39999,60001-60100',40000,60000),'8080,39999-60100')
        self.assertEqual(manage.merged_port_reservations('',40000,60000),'40000-60000')
        self.assertEqual(manage.merged_port_reservations('50000-65535',40000,60000),'40000-65535')

    def test_invalid_reservations_cannot_reach_sysctl(self):
        for value in ('0','65536','9-2','1,,2','1-2-3','22; reboot'):
            with self.subTest(value=value),self.assertRaises(ValueError):
                manage.merged_port_reservations(value,40000,60000)

    def test_panel_backend_and_existing_service_ports_are_all_reserved(self):
        policy = {'reserved_ports': [8080, 22, 80, 443, 7410]}
        manage.reserve_control_ports(policy, 'https://panel.example.com:17443')
        self.assertEqual(manage.merged_port_reservations('30000-30002', 40000, 40999, policy['reserved_ports']),
                         '22,80,443,7410,8080,17443,30000-30002,40000-40999')
        for invalid in (0, 65536, True, '17443'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                manage.merged_port_reservations('', 40000, 40999, [invalid])

    def test_unattended_upgrade_requires_interruption_acknowledgement(self):
        with patch.object(manage.sys.stdin,'isatty',return_value=False),patch('builtins.print'):
            with self.assertRaisesRegex(ValueError,'--yes'):
                manage.confirm_update(False)
            manage.confirm_update(True)


class PanelOrigin(unittest.TestCase):
    def test_default_custom_and_legacy_https_origins(self):
        self.assertEqual(manage.deployment_origin('https://Panel.Example.com/'), ('https://panel.example.com:17443', 17443))
        self.assertEqual(manage.deployment_origin('https://panel.example.com:50005'), ('https://panel.example.com:50005', 50005))
        self.assertEqual(manage.deployment_origin('https://panel.example.com:443'), ('https://panel.example.com', 443))
        self.assertEqual(manage.deployment_origin('https://panel.example.com', default_port=443), ('https://panel.example.com', 443))

    def test_unsafe_origins_fail_before_installation_mutates_anything(self):
        values = ['http://panel.example.com', 'https://panel.example.com:0', 'https://panel.example.com:65536',
                  'https://panel.example.com:7410', 'https://panel.example.com:80', 'https://user@panel.example.com',
                  'https://panel.example.com/path', 'https://panel.example.com?x=1', 'https://panel.example.com#x',
                  'https://panel.example.com\nimport /etc/passwd', 'https://panel.example.com\r',
                  'https://panel.example.com:\t17443', 'https://-panel.example.com', 'https://panel..example.com']
        with patch.object(manage, 'preflight'), patch.object(manage, 'prepare') as prepare, patch.object(manage, 'run') as run:
            for value in values:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    manage.install(SimpleNamespace(origin=value))
            prepare.assert_not_called()
            run.assert_not_called()

    def test_generated_caddy_address_matches_canonical_origin(self):
        template = (MODULE.parent.parent / 'deploy/Caddyfile.example').read_text()
        for value, address in [('https://panel.example.com', 'https://panel.example.com:17443'),
                               ('https://Custom.Example.com:50005/', 'https://custom.example.com:50005'),
                               ('https://panel.example.com:443', 'https://panel.example.com')]:
            with self.subTest(value=value):
                origin, _ = manage.deployment_origin(value)
                text = manage.caddy_configuration(template, origin)
                self.assertTrue(text.startswith(address + ' {'))
                self.assertIn('disable_tlsalpn_challenge', text)
                self.assertIn('header_up X-RelayDeck-Client-IP {remote_host}', text)
        with self.assertRaises(ValueError):
            manage.caddy_configuration('unexpected template', 'https://panel.example.com:17443')

    def test_upgrade_preserves_existing_origin_and_caddy_while_excluding_control_port(self):
        for origin, panel_port in [('https://panel.example.com', 443), ('https://panel.example.com:50005', 50005)]:
            with self.subTest(origin=origin), tempfile.TemporaryDirectory() as work, ExitStack() as patches:
                root = pathlib.Path(work).resolve()
                config = root / 'config'; config.mkdir()
                state = root / 'state'; state.mkdir()
                releases = root / 'releases'; releases.mkdir()
                previous = releases / 'old'; previous.mkdir()
                current = root / 'current'; current.symlink_to(previous)
                environment = ('RELAYDECK_DATABASE=' + str(state / 'data/relaydeck.db') + '\nRELAYDECK_MFA_KEY=' + str(state / 'secrets/mfa.key') + '\nRELAYDECK_ORIGIN=' + origin + '\n')
                (config / 'relaydeck.env').write_text(environment)
                (config / 'Caddyfile').write_text('custom existing proxy config\n')
                (config / 'installation.json').write_text('{"units":{}}')
                policy = {'limits': {'tasks': 96}, 'allowed_port_start': 40000, 'allowed_port_end': 60000,
                          'reserved_ports': [22, 80, 443, 7410], 'custom_field': 'preserve'}
                (config / 'broker.json').write_text(json.dumps(policy))
                calls = []
                def prepare_release(_, stage):
                    stage.mkdir()
                    return {'version': '0.2.0', 'revision': 'abcdef1', 'target': 'x86_64-unknown-linux-gnu'}
                for name, value in [('CONFIG', config), ('STATE', state), ('CURRENT', current), ('RELEASES', releases),
                                    ('TRANSACTION', state / 'transaction.json'), ('ALL_UNITS', ()),
                                    ('root_path', lambda _: None), ('preflight', lambda: None), ('confirm_update', lambda _: None),
                                    ('manage_lock', nullcontext), ('prepare', prepare_release),
                                    ('reserve_forwarding_ports', lambda policy: calls.append(policy.copy()) or {}),
                                    ('ensure_upgrade_policy', lambda: None), ('management_tools', lambda _: None),
                                    ('current_link', lambda _: None), ('as_web', lambda *_: None),
                                    ('atomic_json', lambda path, value, mode=0o600: path.write_text(json.dumps(value))),
                                    ('atomic_copy', lambda *_: None), ('run', lambda *_: None), ('wait_health', lambda _: None)]:
                    patches.enter_context(patch.object(manage, name, value))
                manage.update(SimpleNamespace(yes=True))
                self.assertEqual((config / 'relaydeck.env').read_text(), environment)
                self.assertEqual((config / 'Caddyfile').read_text(), 'custom existing proxy config\n')
                installed = json.loads((config / 'broker.json').read_text())
                self.assertIn(panel_port, installed['reserved_ports'])
                self.assertEqual(installed['custom_field'], 'preserve')
                self.assertEqual((installed['allowed_port_start'], installed['allowed_port_end']), (1024, 65535))
                self.assertIn(panel_port, calls[0]['reserved_ports'])
                self.assertFalse((state / 'transaction.json').exists())


class CachedRelease(unittest.TestCase):
    def test_verified_failed_release_can_be_retried_without_overwriting_cache(self):
        with tempfile.TemporaryDirectory() as work, patch.object(manage, 'root_path'):
            root = pathlib.Path(work)
            stage = root / 'stage'; stage.mkdir(); (stage / 'bin').mkdir(); (stage / 'bin/app').write_bytes(b'verified')
            import shutil
            cached = root / 'cached'; shutil.copytree(stage, cached)
            manage.verify_cached_release(cached, stage)
            (cached / 'bin/app').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'differ'):
                manage.verify_cached_release(cached, stage)

    def test_extra_files_and_links_in_cached_releases_are_rejected(self):
        with tempfile.TemporaryDirectory() as work, patch.object(manage, 'root_path'):
            root = pathlib.Path(work)
            stage = root / 'stage'; stage.mkdir(); (stage / 'app').write_bytes(b'verified')
            cached = root / 'cached'; cached.mkdir(); (cached / 'app').write_bytes(b'verified'); (cached / 'extra').write_bytes(b'extra')
            with self.assertRaises(ValueError): manage.verify_cached_release(cached, stage)
            (cached / 'extra').unlink(); (cached / 'app').unlink(); (cached / 'app').symlink_to(stage / 'app')
            with self.assertRaises(ValueError): manage.verify_cached_release(cached, stage)

class SharedPortDeployment(unittest.TestCase):
    def test_shared_pool_does_not_exhaust_outbound_ephemeral_ports(self):
        self.assertEqual(manage.merged_port_reservations('40000-40999', control_ports=[22, 80, 443, 7410, 17443]),
                         '22,80,443,7410,17443,40000-40999')
        self.assertEqual(manage.merged_port_reservations('', control_ports=[7410, 17443]), '7410,17443')

    def test_rollback_restores_the_previous_root_port_boundary(self):
        with tempfile.TemporaryDirectory() as work, ExitStack() as patches:
            root = pathlib.Path(work).resolve()
            config = root / 'config'; config.mkdir()
            releases = root / 'releases'; releases.mkdir()
            previous = releases / 'old'; previous.mkdir()
            release = releases / 'new'; release.mkdir()
            (previous / 'release.json').write_text('{"version":"0.1.1"}')
            policy = {'allowed_port_start':40000, 'allowed_port_end':40999, 'limits':{'tasks':96}, 'reserved_ports':[17443]}
            (config / 'broker.json').write_text('{"allowed_port_start":1024,"allowed_port_end":65535}')
            transaction = root / 'transaction.json'; transaction.write_text('{}')
            for name, value in [('CONFIG', config), ('RELEASES', releases), ('TRANSACTION', transaction), ('ALL_UNITS', ()),
                                ('root_path', lambda _: None), ('atomic_copy', lambda *_: None),
                                ('current_link', lambda _: None), ('management_tools', lambda _: None),
                                ('run', lambda *_: None), ('wait_health', lambda _: None),
                                ('atomic_json', lambda path, value, mode=0o600: path.write_text(json.dumps(value)))]:
                patches.enter_context(patch.object(manage, name, value))
            manage.restore_transaction({'previous':str(previous), 'release':str(release), 'backup':None,
                                        'installation':{'units':{}}, 'broker_policy':policy})
            self.assertEqual(json.loads((config / 'broker.json').read_text()), policy)
            self.assertFalse(transaction.exists())


if __name__ == '__main__':
    unittest.main()
