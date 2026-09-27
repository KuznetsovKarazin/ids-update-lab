#!/usr/bin/env python3
"""Preserve immutable evidence archives plus new reviews; never edits inputs."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import zipfile
from verify_archive032 import verify

SOURCES = [
    'ids-update-lab-all-results-2026-09-25.zip',
    'upload/ton-diagnostics-028-results.zip',
    'upload/ids-completion-030-results.zip',
    'ids-update-lab-completion-030.zip',
    'ids-update-lab-energy-recovery-031.zip',
]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def selection(root, small):
    files, excluded = {}, []
    dirs = ['finalization032', 'closure032', 'powercut032']
    if not small:
        dirs += ['review028_actual', 'review030', 'preservation032_inventory']
        for name in SOURCES:
            p = root / name
            if not p.is_file():
                raise FileNotFoundError(p)
            files['sources/' + p.name] = p
    for directory in dirs:
        for p in sorted((root / directory).rglob('*')):
            if not p.is_file():
                continue
            relative = p.relative_to(root).as_posix()
            reason = None
            if '__pycache__' in p.parts or p.suffix in {'.pyc', '.pyo'}:
                reason = 'reproducible_python_cache'
            elif relative.startswith(('review030/input/', 'review028_actual/input/')):
                reason = 'raw_evidence_preserved_in_immutable_source_zip'
            elif relative == 'review030/energy_diagnosis/samples.npz':
                reason = 'decoded_CFN_cache_reproducible_from_preserved_raw_CFN'
            elif relative.startswith('preservation032_inventory/collector/'):
                reason = 'collector_identical_copy_delivered_under_finalization032'
            if reason:
                excluded.append({'path': relative, 'reason': reason})
            else:
                if p.is_symlink():
                    raise ValueError(f'Symlink: {p}')
                files[relative] = p
    if not small:
        files['START_HERE_RU.md'] = root / 'finalization032/START_HERE_RU.md'
    return files, excluded


def build(root, output, small):
    if output.exists():
        raise FileExistsError(output)
    partial = output.with_name(output.name + '.partial')
    files, excluded = selection(root, small)
    records = [{'path': name, 'bytes': p.stat().st_size, 'sha256': digest(p)}
               for name, p in sorted(files.items())]
    manifest = {'schema': 'ids-preservation-032-v1',
        'created_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'kind': 'portable_finalization_tools' if small else 'all_available_evidence_through031',
        'source_evidence_modified': False, 'hardware_access_attempted': False,
        'physical_power_loss_tested': False,
        'scope': 'Available shared evidence; full Windows source datasets and local 031 output not present here.',
        'files': records, 'excluded_working_copies': excluded,
        'authoritative_recovered_energy': 'review030/energy_recovered031_final/summary.json',
        'user_local031_confirmation': 'finalization032/STATUS032.json'}
    with partial.open('xb') as f:
        with zipfile.ZipFile(f, 'w', allowZip64=True, compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for record in records:
                name = record['path']
                z.write(files[name], name, compress_type=zipfile.ZIP_STORED if name.endswith('.zip') else zipfile.ZIP_DEFLATED)
            z.writestr('MANIFEST032.json', json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    result = verify(partial)
    os.link(partial, output)
    partial.unlink()
    result['archive'] = str(output)
    output.with_suffix(output.suffix + '.sha256.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--small', action='store_true')
    a = p.parse_args()
    print(json.dumps(build(a.root.resolve(), a.output.resolve(), a.small)))


if __name__ == '__main__':
    main()
