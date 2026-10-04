"""Public frontend extraction and upgrade-readiness regressions."""
import importlib.util
import io
import os
import pathlib
import tempfile
import unittest
from email.message import Message
from unittest.mock import patch

SOURCE = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('frontend_manage', SOURCE / 'scripts/manage.py')
manage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manage)
import test_deployment as deployment


class FrontendExtraction(unittest.TestCase):
    def test_restrictive_updater_umask_does_not_make_public_payload_root_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            archive, digest = deployment.ReleaseValidation().archive(root)
            previous = os.umask(0o077)
            try:
                manage.extract_release(archive, digest, root / 'release')
            finally:
                os.umask(previous)
            for path in [root / 'release', *(p for p in (root / 'release').rglob('*') if p.is_dir())]:
                self.assertEqual(path.stat().st_mode & 0o7777, 0o755)
            self.assertEqual((root / 'release/frontend/index.html').stat().st_mode & 0o7777, 0o644)


class FrontendReadiness(unittest.TestCase):
    def test_health_api_alone_cannot_commit_a_broken_frontend(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            front = root / 'frontend'; (front / 'assets').mkdir(parents=True)
            html = b'<script type="module" src="/assets/app.js"></script><link rel="stylesheet" href="/assets/app.css">'
            (front / 'index.html').write_bytes(html)
            (front / 'assets/app.js').write_bytes(b'export default 1')
            (front / 'assets/app.css').write_bytes(b'body{}')
            for broken in [None, '/', '/assets/app.js', '/assets/app.css', 'mime', 'content']:
                with self.subTest(broken=broken):
                    def response(url, timeout):
                        path = url.removeprefix('http://127.0.0.1:7410')
                        if path == broken: raise OSError('frontend unavailable')
                        body = b'{"version":"0.2.2","executor":"running"}' if path == '/api/health' else html if path == '/' else (front / path.lstrip('/')).read_bytes()
                        if broken == 'content' and path.endswith('.js'): body = html
                        stream = io.BytesIO(body); stream.status = 200; stream.headers = Message()
                        stream.headers['Content-Type'] = 'application/json' if path == '/api/health' else 'text/html' if path == '/' or broken == 'mime' else 'text/css' if path.endswith('.css') else 'text/javascript'
                        return stream
                    with patch.object(manage, 'CURRENT', root), patch.object(manage.urllib.request, 'urlopen', side_effect=response), patch.object(manage.time, 'sleep'):
                        if broken is None: manage.wait_health('0.2.2')
                        else:
                            with self.assertRaisesRegex(RuntimeError, 'health check failed'):
                                manage.wait_health('0.2.2')

    def test_asset_paths_cannot_escape_the_local_release(self):
        for name in ['https://other.test/app.js', '/api/session', '/assets/../secret.js', '/assets/%2e%2e/secret.js']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                parser = manage.FrontendAssets()
                parser.feed('<script type="module" src="' + name + '"></script>')
