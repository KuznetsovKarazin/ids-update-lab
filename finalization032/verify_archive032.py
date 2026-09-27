#!/usr/bin/env python3
"""Verify a 032 archive without extracting files or accessing hardware."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile


def verify(path: Path) -> dict:
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if len(names) != len(set(names)):
            raise ValueError('Duplicate ZIP member names')
        for name in names:
            parts = PurePosixPath(name).parts
            if not parts or name.startswith('/') or '\\' in name or '..' in parts or ':' in parts[0]:
                raise ValueError(f'Unsafe ZIP member: {name}')
        manifest = json.loads(z.read('MANIFEST032.json'))
        items = manifest['files']
        if len({item['path'] for item in items}) != len(items):
            raise ValueError('Duplicate manifest entries')
        expected = {item['path'] for item in items} | {'MANIFEST032.json'}
        if set(names) != expected:
            raise ValueError('ZIP and manifest membership differ')
        total = 0
        for item in items:
            h = hashlib.sha256()
            count = 0
            with z.open(item['path']) as f:
                for block in iter(lambda: f.read(1024 * 1024), b''):
                    h.update(block)
                    count += len(block)
            if count != item['bytes'] or h.hexdigest() != item['sha256']:
                raise ValueError(f'Hash or length mismatch: {item["path"]}')
            total += count
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return {'status': 'verified', 'archive': str(path), 'bytes': path.stat().st_size,
            'sha256': h.hexdigest(), 'verified_files': len(items),
            'verified_uncompressed_bytes': total,
            'crc_and_member_sha256_verified': True, 'hardware_access_attempted': False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('archive', type=Path)
    a = p.parse_args()
    try:
        print(json.dumps(verify(a.archive), ensure_ascii=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print(json.dumps({'status': 'failed', 'error': str(exc)}, ensure_ascii=False))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
