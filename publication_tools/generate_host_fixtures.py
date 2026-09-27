#!/usr/bin/env python3
"""Prepare a fresh, isolated host-test tree without changing published artifacts.

Historical example keys and prebuilt MCU images are left untouched. A newly
generated RSA key exists only in process memory; only its public key and signed
synthetic test fixtures are written. These fixtures are not for flashing a
published MCU image and are not experimental evidence.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(root, output):
    root, output = root.resolve(), output.resolve()
    if output == root or root in output.parents:
        raise ValueError('Host-test output must be outside the published release')
    if output.exists():
        raise ValueError('Use a fresh output directory')
    folders = ['host', 'tests', 'tools', 'firmware']
    sources = []
    for name in folders:
        if not (root / name).is_dir():
            raise ValueError('Required source directory is absent: ' + name)
        for path in sorted((root / name).rglob('*')):
            if '__pycache__' in path.parts or '.pytest_cache' in path.parts:
                continue
            if path.is_symlink():
                raise ValueError('Refusing to follow a source-tree symlink: ' + str(path))
            if path.is_file() and path.suffix not in {'.pyc', '.pyo', '.bin', '.elf', '.map'}:
                sources.append(path)
    sources.append(root / 'pyproject.toml')
    pins = {p.relative_to(root).as_posix(): sha(p) for p in sources}
    output.mkdir(parents=True, exist_ok=False)
    for source in sources:
        relative = source.relative_to(root)
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if sha(target) != pins[relative.as_posix()]:
            raise ValueError('Source changed during copying: ' + str(relative))
    # Generator source is copied from the publication; no original example
    # directory, development key or prebuilt image enters this isolated tree.
    sys.path.insert(0, str(output / 'host'))
    from cryptography.hazmat.primitives.asymmetric import rsa
    from ids_update_lab.artifacts import generate_demo
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fixture = output / 'examples/synthetic_demo'
    generate_demo(fixture, key)
    del key
    result = {
        'status': 'prepared', 'purpose': 'isolated host-only tests',
        'source_modified': False, 'hardware_access_attempted': False,
        'fixture_is_hardware_evidence': False,
        'fixture_compatible_with_published_prebuilt_images': False,
        'private_key_saved': False, 'source_sha256': pins,
        'fixture_sha256': {p.relative_to(output).as_posix(): sha(p) for p in sorted(fixture.iterdir())},
        'excluded': ['original examples', 'all prebuilt binaries', 'native simulator executable', 'dataset inputs', 'recorded evidence'],
    }
    (output / 'HOST_TEST_PREPARATION.json').write_text(json.dumps(result, indent=2) + '\n')
    (output / 'HOST_TESTS_ONLY.md').write_text(
        '# Isolated host-test tree\n\n'
        'The generated synthetic fixture is signed with a newly generated key whose private part was not saved. '
        'It is not compatible with the published MCU firmware keys. Do not use this tree to flash hardware. '
        'The original release and original recorded evidence were not changed.\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--run-tests', action='store_true')
    args = parser.parse_args()
    result = prepare(args.release_root, args.output)
    output = args.output.resolve()
    print(json.dumps({'status': 'prepared', 'output': str(output), 'source_modified': False,
                      'hardware_access_attempted': False}), flush=True)
    if not args.run_tests:
        return 0
    env = os.environ.copy()
    env['PYTHONPATH'] = str(output / 'host') + (os.pathsep + env['PYTHONPATH'] if env.get('PYTHONPATH') else '')
    # The selected root tests exercise mocks and native host compilation. A
    # separate full native simulator is intentionally absent, giving explicit
    # skips instead of loading a binary built for another signing fixture.
    command = [sys.executable, '-m', 'pytest', 'tests', '-q']
    run = subprocess.run(command, cwd=output, env=env, capture_output=True, text=True)
    log = run.stdout + run.stderr
    print(log, end='')
    (output / 'HOST_TEST_OUTPUT.txt').write_text(log, encoding='utf-8')
    (output / 'HOST_TEST_RESULT.json').write_text(json.dumps({
        'status': 'passed_with_reported_skips' if run.returncode == 0 else 'failed',
        'command': command, 'returncode': run.returncode,
        'log_sha256': sha(output / 'HOST_TEST_OUTPUT.txt'),
        'source_modified': False, 'hardware_access_attempted': False}, indent=2) + '\n')
    return run.returncode


if __name__ == '__main__':
    raise SystemExit(main())
