"""Validate the actual native release bundle in an isolated Linux container.

Run after packaging, before publishing either architecture. This never starts
services or touches an installed panel; root policy tests use new /run fixtures.
"""
import importlib.util
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import tempfile
import tomllib
from types import SimpleNamespace

SOURCE = pathlib.Path(__file__).resolve().parents[1]


def main():
    if platform.system() != 'Linux' or os.geteuid() != 0 or not pathlib.Path('/.dockerenv').exists():
        raise RuntimeError('Release acceptance requires an isolated root Linux Docker container')
    machine = platform.machine()
    if machine not in ('x86_64', 'aarch64', 'arm64'):
        raise RuntimeError('Unsupported release architecture')
    target = ('x86_64' if machine == 'x86_64' else 'aarch64') + '-unknown-linux-gnu'
    with (SOURCE / 'Cargo.toml').open('rb') as stream:
        version = tomllib.load(stream)['package']['version']
    if json.loads((SOURCE / 'frontend/package.json').read_text())['version'] != version:
        raise RuntimeError('Frontend and backend release versions differ')
    revision = os.environ['RELAYDECK_EXPECTED_REVISION']
    if not re.fullmatch('[a-f0-9]{40}', revision):
        raise RuntimeError('Release acceptance needs the exact source revision')
    archives = list((SOURCE / 'dist').glob('*.tar.gz'))
    expected_name = f'relaydeck-{version}-{revision}-{target}.tar.gz'
    if len(archives) != 1 or archives[0].name != expected_name:
        raise RuntimeError('Expected exactly one bundle matching version, revision and architecture')
    archive = archives[0]
    if archive.stat().st_size > 100 * 1024 * 1024:
        raise RuntimeError('Release exceeds the installed updater download limit')
    spec = importlib.util.spec_from_file_location('release_manage', SOURCE / 'scripts/manage.py')
    manage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manage)
    checksum = archive.with_name(archive.name + '.sha256').read_text().split()[0]
    with tempfile.TemporaryDirectory(prefix='relaydeck-release-acceptance-') as directory:
        stage = pathlib.Path(directory) / 'release'
        previous_umask = os.umask(0o077)
        try:
            manifest = manage.prepare(SimpleNamespace(bundle=archive, sha256=checksum), stage)
        finally:
            os.umask(previous_umask)
        if manifest != {'version': version, 'revision': revision, 'target': target}:
            raise RuntimeError('Packaged release manifest differs from source')
        binary = stage / 'bin/relaydeck'
        symbols = subprocess.check_output(['readelf', '--version-info', str(binary)], text=True)
        glibc = {tuple(map(int, item.split('.'))) for item in re.findall(r'GLIBC_([0-9]+(?:\.[0-9]+)+)', symbols)}
        if not glibc or max(glibc) > (2, 36):
            raise RuntimeError('Executable requires a newer libc than the Debian 12 deployment baseline')
        environment = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'RELAYDECK_POLICY_TEST': '1', 'RELAYDECK_TEST_BINARY': str(binary)}
        subprocess.run([sys.executable, str(SOURCE / 'tests/policy_preparation.py'), '-v'], env=environment, check=True)
        subprocess.run([sys.executable, str(SOURCE / 'tests/frontend_preparation.py'), '-v'], env=environment, check=True)
        subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', str(SOURCE / 'tests'), '-p', 'test_legacy_update.py', '-v'], env=environment, check=True)
        print(f'Accepted {target}: binary={binary.stat().st_size} bytes, bundle={archive.stat().st_size} bytes, maximum GLIBC={".".join(map(str, max(glibc)))}', flush=True)


if __name__ == '__main__':
    main()
