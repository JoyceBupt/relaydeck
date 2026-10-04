import hashlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

SOURCE = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('upgrader', SOURCE / 'deploy/relaydeck-upgrader.py')
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)
CURRENT = {'version': '0.1.0', 'revision': 'abcdef0', 'target': 'aarch64-unknown-linux-gnu'}
PAYLOAD = b'release-fixture'


def release():
    return {'id': 22, 'tag_name': 'v0.2.0', 'draft': False, 'prerelease': False,
            'assets': [{'id': 33, 'name': 'relaydeck-0.2.0-abcdef1-aarch64-unknown-linux-gnu.tar.gz',
                        'state': 'uploaded', 'size': len(PAYLOAD), 'digest': 'sha256:' + hashlib.sha256(PAYLOAD).hexdigest(),
                        'browser_download_url': 'http://127.0.0.1/never-used'}]}


class UpgradeFlow(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        for name, value in [('ROOT', self.root), ('root_path', lambda _: None),
                            ('identity', lambda: CURRENT.copy()), ('maintenance_busy', lambda: False)]:
            mock = patch.object(upgrade, name, value)
            mock.start()
            self.addCleanup(mock.stop)
        self.controller = upgrade.Controller()

    def offer(self):
        with patch.object(upgrade, 'fetch_json', side_effect=lambda path: {'id':upgrade.REPOSITORY_ID} if path == '' else release()):
            state = self.controller.dispatch({'op': 'check'})
        self.assertEqual(state['latest']['release_url'], 'https://github.com/JoyceBupt/relaydeck/releases/tag/v0.2.0')
        return state['latest']['offer']

    def start(self):
        token = self.offer()
        with patch.object(upgrade, 'launch') as launch:
            state = self.controller.dispatch({'op': 'start', 'offer': token})
            launch.assert_called_once_with(state['job']['id'])
        return state

    def test_one_owner_authorization_creates_one_durable_job(self):
        token = self.offer()
        with patch.object(upgrade, 'launch') as launch:
            state = self.controller.dispatch({'op': 'start', 'offer': token})
            with self.assertRaises(upgrade.UpgradeError):
                self.controller.dispatch({'op': 'start', 'offer': token})
            self.assertEqual(launch.call_count, 1)
        job = upgrade.read_json(upgrade.job_path(state['job']['id']))
        self.assertEqual(job['release']['asset_id'], 33)
        self.assertNotIn('offer', job['release'])
        self.assertNotIn('browser_download_url', job['release'])
        fresh = upgrade.Controller().status()
        self.assertEqual(fresh['job']['id'], state['job']['id'])

    def test_missing_expired_and_forged_offers_cannot_launch_jobs(self):
        self.offer()
        self.controller.offer['expires_at'] = 0
        with patch.object(upgrade, 'launch') as launch:
            for token in ['0' * 64, self.controller.offer['offer'], '', 'https://attacker.test/a']:
                with self.assertRaises(upgrade.UpgradeError):
                    self.controller.dispatch({'op': 'start', 'offer': token})
            launch.assert_not_called()

    def test_arbitrary_operations_urls_paths_and_additional_fields_are_rejected(self):
        with patch.object(upgrade, 'launch') as launch:
            for request in [{'op': 'shell', 'command': 'reboot'}, {'op': 'start', 'bundle': '/tmp/payload'},
                            {'op': 'status', 'owner_id': 1}, {'op': 'check', 'url': 'http://localhost'}, [],
                            {'op': 'start', 'offer': 'a' * 64, 'sha256': 'a' * 64}]:
                with self.assertRaises(upgrade.UpgradeError):
                    self.controller.dispatch(request)
            launch.assert_not_called()

    def test_network_error_keeps_an_existing_offer_and_does_not_start_update(self):
        token = self.offer()
        self.controller.checked_at -= 61
        with patch.object(upgrade, 'fetch_json', side_effect=OSError('network unavailable')) as fetch:
            with self.assertRaises(OSError):
                self.controller.dispatch({'op': 'check'})
            fetch.assert_called_once()
        self.assertEqual(self.controller.status()['latest']['offer'], token)

    def test_job_checks_manifest_and_reports_success_after_update(self):
        state = self.start()
        tools = type('Manager', (), {})()
        tools.extract_release = lambda *_: {'version': '0.2.0', 'revision': 'abcdef1', 'target': CURRENT['target']}
        calls = []
        tools.update = lambda args, progress: (calls.append(args.sha256), progress('backup'), progress('health'))
        with patch.object(upgrade, 'manager', return_value=tools), patch.object(upgrade, 'fetch_json', side_effect=lambda path: {'id':upgrade.REPOSITORY_ID} if path == '' else release()), patch.object(upgrade, 'response', return_value=io.BytesIO(PAYLOAD)), patch.object(upgrade.subprocess, 'run'):
            upgrade.run_job(state['job']['id'])
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.controller.status()['job']['phase'], 'succeeded')

    def test_changed_asset_digest_and_invalid_manifest_fail_before_installation(self):
        for invalid_manifest in (False, True):
            self.controller = upgrade.Controller()
            if (self.root / 'status.json').exists():
                (self.root / 'status.json').unlink()
            state = self.start()
            tools = type('Manager', (), {})()
            tools.extract_release = lambda *_: {**CURRENT, 'version': '0.9.0'}
            calls = []
            tools.update = lambda *args, **kwargs: calls.append(args)
            metadata = release()
            if not invalid_manifest:
                metadata['assets'][0]['digest'] = 'sha256:' + '0' * 64
            with patch.object(upgrade, 'manager', return_value=tools), patch.object(upgrade, 'fetch_json', side_effect=lambda path: {'id':upgrade.REPOSITORY_ID} if path == '' else metadata), patch.object(upgrade, 'response', return_value=io.BytesIO(PAYLOAD)):
                with self.assertRaises(ValueError):
                    upgrade.run_job(state['job']['id'])
            self.assertEqual(calls, [])
            self.assertEqual(self.controller.status()['job']['phase'], 'failed')

    def test_download_digest_mismatch_cannot_reach_package_extraction(self):
        state = self.start()
        tools = type('Manager', (), {})()
        calls = []
        tools.extract_release = lambda *_: calls.append(True)
        with patch.object(upgrade, 'manager', return_value=tools), patch.object(upgrade, 'fetch_json', side_effect=lambda path: {'id':upgrade.REPOSITORY_ID} if path == '' else release()), patch.object(upgrade, 'response', return_value=io.BytesIO(b'x' * len(PAYLOAD))):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                upgrade.run_job(state['job']['id'])
        self.assertEqual(calls, [])

    def test_confirmed_rollback_is_distinct_from_unrecovered_failure(self):
        state = self.start()
        class UpdateRolledBack(RuntimeError):
            pass
        tools = type('Manager', (), {})()
        tools.extract_release = lambda *_: {'version': '0.2.0', 'revision': 'abcdef1', 'target': CURRENT['target']}
        def update(*_, **__):
            raise UpdateRolledBack('restored')
        tools.update = update
        with patch.object(upgrade, 'manager', return_value=tools), patch.object(upgrade, 'fetch_json', side_effect=lambda path: {'id':upgrade.REPOSITORY_ID} if path == '' else release()), patch.object(upgrade, 'response', return_value=io.BytesIO(PAYLOAD)), patch.object(upgrade.subprocess, 'run'):
            with self.assertRaises(UpdateRolledBack):
                upgrade.run_job(state['job']['id'])
        self.assertEqual(self.controller.status()['job']['phase'], 'rolled_back')

    def test_manual_maintenance_blocks_start_without_consuming_offer(self):
        token = self.offer()
        with patch.object(upgrade, 'maintenance_busy', return_value=True), patch.object(upgrade, 'launch') as launch:
            with self.assertRaises(upgrade.UpgradeError):
                self.controller.dispatch({'op': 'start', 'offer': token})
            launch.assert_not_called()
        self.assertEqual(self.controller.offer['offer'], token)


class ReleaseTrust(unittest.TestCase):
    def test_wrong_architecture_drafts_missing_digest_and_ambiguous_assets_fail_closed(self):
        for change in ('architecture', 'draft', 'digest', 'duplicate', 'prerelease'):
            metadata = release()
            if change == 'architecture': metadata['assets'][0]['name'] = metadata['assets'][0]['name'].replace('aarch64', 'x86_64')
            if change == 'draft': metadata['draft'] = True
            if change == 'digest': metadata['assets'][0].pop('digest')
            if change == 'duplicate': metadata['assets'] *= 2
            if change == 'prerelease': metadata['prerelease'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                upgrade.candidate(metadata, CURRENT)

    def test_same_version_or_downgrade_is_not_an_upgrade(self):
        for version in ('0.1.0', '0.0.9'):
            metadata = release()
            metadata['tag_name'] = 'v' + version
            self.assertIsNone(upgrade.candidate(metadata, CURRENT))

    def test_redirects_cannot_escape_https_github_release_hosts(self):
        handler = upgrade.TrustedRedirect()
        for url in ('http://github.com/file', 'https://attacker.test/file', 'https://github.com:1234/file', 'https://user:secret@github.com/file', 'https://127.0.0.1/file'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(None, None, 302, '', {}, url)

    def test_job_ids_cannot_select_paths_or_systemd_units(self):
        for identifier in ('../etc/passwd', 'x.service', '-a', '', 'A' * 32):
            with self.assertRaises(ValueError):
                upgrade.job_unit(identifier)


if __name__ == '__main__':
    unittest.main()
