import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest

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
            **{f'deploy/{unit}': b'[Service]\nExecStart=/usr/local/libexec/relaydeck\n' for unit in manage.UNITS},
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


if __name__ == '__main__':
    unittest.main()
