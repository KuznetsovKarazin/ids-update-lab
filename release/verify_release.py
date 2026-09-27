#!/usr/bin/env python3
"""Verify the delivered files without running experiments or contacting hardware."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = json.loads((root / 'MANIFEST.sha256.json').read_text(encoding='utf-8'))
    failed = []
    for record in manifest['files']:
        rel = PurePosixPath(record['path'])
        if rel.is_absolute() or '..' in rel.parts:
            raise ValueError('Unsafe manifest path')
        path = root / rel
        if not path.is_file():
            failed.append({'path': str(rel), 'reason': 'missing'})
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != record['sha256'] or path.stat().st_size != record['bytes']:
            failed.append({'path': str(rel), 'reason': 'content differs'})
    print(json.dumps({'status': 'failed' if failed else 'verified',
                      'distribution': manifest['distribution'],
                      'files_checked': len(manifest['files']), 'failed': failed}, indent=2))
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
