"""Collect upstream license texts for source-built release dependencies."""
import json
import pathlib
import shutil
import subprocess


def license_files(root):
    roots = [root, *(p for p in root.iterdir() if p.is_dir() and p.name.lower() in ('licenses', 'licences'))]
    return sorted({p for directory in roots for p in directory.iterdir() if p.is_file()
                   and (directory != root or p.name.lower().startswith(('license', 'licence', 'copying', 'notice', 'ofl')))})


def collect(source, target, output):
    metadata = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--filter-platform', target, '--format-version', '1'], cwd=source))
    components = []
    for package in metadata['packages']:
        if package['name'] != 'relaydeck':
            components.append(('Rust', package['name'], package['version'], package['license'],
                               pathlib.Path(package['manifest_path']).parent))
    modules = source / 'frontend/node_modules'
    if not modules.is_dir():
        raise ValueError('Install locked frontend dependencies before packaging')
    dependencies = json.loads((source / 'frontend/package.json').read_text())['dependencies']
    pending = [(modules / name).resolve() for name in dependencies]
    seen = set()
    while pending:
        root = pending.pop()
        package = json.loads((root / 'package.json').read_text())
        identity = (package['name'], package['version'])
        if identity in seen:
            continue
        seen.add(identity)
        components.append(('Frontend', *identity, package.get('license'), root))
        for name in package.get('dependencies', {}):
            candidates = [root / 'node_modules' / name, *(p / name for p in root.parents if p.name == 'node_modules')]
            found = next((p.resolve() for p in candidates if (p / 'package.json').is_file()), None)
            if found is None:
                raise ValueError(f'Missing installed frontend dependency: {name}')
            pending.append(found)
    text = ['Third-party notices\n\nThis inventory conservatively includes build dependencies. '
            'Each component retains its own license; RelayDeck\'s MIT license does not replace it.\n']
    # This npm version omits its LICENSE. Preserve the exact upstream tag text:
    # https://github.com/vuejs/devtools-v6/blob/v6.6.4/LICENSE
    overrides = {('Frontend', '@vue/devtools-api', '6.6.4'): source / 'licenses/vue-devtools-api-6.6.4-MIT.txt'}
    for ecosystem, name, version, license_id, root in sorted(components):
        files = license_files(root)
        override = overrides.get((ecosystem, name, version))
        if not files and override is not None and override.is_file():
            files = [override]
        if not license_id or not files:
            raise ValueError(f'Missing upstream license for {ecosystem} {name} {version}')
        text.append(f'\n{"=" * 72}\n{ecosystem}: {name} {version}\nLicense: {license_id}\n')
        for path in files:
            label = path.name if path == override else path.relative_to(root)
            text.append(f'\n--- {label} ---\n{path.read_text()}\n')
    sysroot = pathlib.Path(subprocess.check_output(['rustc', '--print', 'sysroot'], text=True).strip())
    runtime = sysroot / 'share/doc/rust'
    if not (runtime / 'COPYRIGHT-library.html').is_file() or not (runtime / 'licenses').is_dir():
        raise ValueError('Rust runtime copyright and license texts are missing')
    output.mkdir(parents=True)
    shutil.copy2(source / 'LICENSE', output / 'RelayDeck-MIT.txt')
    (output / 'THIRD_PARTY_NOTICES.txt').write_text(''.join(text))
    (output / 'README.txt').write_text(
        'RelayDeck: MIT (RelayDeck-MIT.txt).\n'
        'Rust and frontend dependencies: THIRD_PARTY_NOTICES.txt.\n'
        'Rust runtime attribution: rust-runtime/COPYRIGHT-library.html and licenses/.\n'
        'Realm is supplied separately; retain its upstream license when redistributing it.\n')
    shutil.copytree(runtime / 'licenses', output / 'rust-runtime/licenses')
    shutil.copy2(runtime / 'COPYRIGHT-library.html', output / 'rust-runtime/COPYRIGHT-library.html')
