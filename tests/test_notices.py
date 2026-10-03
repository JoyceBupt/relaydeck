import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('relaydeck_notices', pathlib.Path(__file__).resolve().parents[1] / 'scripts/notices.py')
notices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notices)


class ReleaseNotices(unittest.TestCase):
    def fixture(self, root):
        source = root / 'source'; source.mkdir()
        (source / 'LICENSE').write_text('RelayDeck MIT copyright')
        frontend = source / 'frontend'; frontend.mkdir()
        (frontend / 'package.json').write_text(json.dumps({'dependencies': {'demo-font': '1.0.0'}}))
        font = frontend / 'node_modules/demo-font'; font.mkdir(parents=True)
        (font / 'package.json').write_text(json.dumps({'name': 'demo-font', 'version': '1.0.0', 'license': 'OFL-1.1'}))
        (font / 'LICENSE').write_text('Font copyright and OFL conditions')
        crate = root / 'crate'; crate.mkdir()
        (crate / 'LICENSE').write_text('Crate copyright and MIT conditions')
        metadata = {'packages': [{'name': 'demo-crate', 'version': '1.0.0', 'license': 'MIT', 'manifest_path': str(crate / 'Cargo.toml')}]}
        runtime = root / 'toolchain/share/doc/rust'; runtime.mkdir(parents=True)
        (runtime / 'COPYRIGHT-library.html').write_text('Rust runtime attribution')
        (runtime / 'licenses').mkdir(); (runtime / 'licenses/MIT.txt').write_text('Rust MIT conditions')
        return source, crate, metadata

    def test_release_keeps_copyrights_font_terms_and_runtime_notices_without_local_paths(self):
        with tempfile.TemporaryDirectory() as work:
            root = pathlib.Path(work); source, _, metadata = self.fixture(root)
            with patch.object(notices.subprocess, 'check_output', side_effect=[json.dumps(metadata).encode(), str(root / 'toolchain')]):
                notices.collect(source, 'aarch64-unknown-linux-gnu', root / 'output')
            text = (root / 'output/THIRD_PARTY_NOTICES.txt').read_text()
            self.assertIn('Font copyright and OFL conditions', text)
            self.assertIn('Crate copyright and MIT conditions', text)
            self.assertNotIn(str(root), text)
            self.assertEqual((root / 'output/RelayDeck-MIT.txt').read_text(), 'RelayDeck MIT copyright')
            self.assertEqual((root / 'output/rust-runtime/COPYRIGHT-library.html').read_text(), 'Rust runtime attribution')

    def test_missing_upstream_text_stops_packaging_before_claiming_compliance(self):
        with tempfile.TemporaryDirectory() as work:
            root = pathlib.Path(work); source, crate, metadata = self.fixture(root)
            (crate / 'LICENSE').unlink()
            with patch.object(notices.subprocess, 'check_output', return_value=json.dumps(metadata).encode()):
                with self.assertRaisesRegex(ValueError, 'Missing upstream license for Rust demo-crate'):
                    notices.collect(source, 'aarch64-unknown-linux-gnu', root / 'output')
            self.assertFalse((root / 'output').exists())
