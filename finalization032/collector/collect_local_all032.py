#!/usr/bin/env python3
"""Read-only, dependency-free evidence collector. Does not access an MCU."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile

SKIP_DIRS = {'.git', '.venv', 'venv', '__pycache__', '.pytest_cache',
             '.mypy_cache', 'node_modules', '.ruff_cache'}
SUPPORT = re.compile(r'^(runs|stage\d+|completion\d+|research(?:\d+.*)?|'
                     r'prebuilt|tools|tests|docs|host|firmware|core|examples|'
                     r'include|src|fnb.*|energy.*|review\d+.*|preservation\d+.*|'
                     r'recovery\d+.*|finalization\d+.*|data|datasets?|ton.*)$', re.I)
PUBLIC_TEST_KEY_SHA256 = '43fcd1bf91cf1ed6d61eff4ec4d6a9829889147fd363318fdb479c518ec387ee'
ARCHIVES = {'.zip', '.7z', '.rar', '.tar', '.gz', '.xz', '.bz2'}
PRIVATE_MARKERS = (b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----',
                   b'-----BEGIN EC PRIVATE KEY-----', b'-----BEGIN OPENSSH PRIVATE KEY-----')


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def collect(root: Path, output: Path, extra: list[str], include_archives: bool,
            include_large_datasets: bool = False) -> dict:
    root, output = root.resolve(), output.resolve()
    if not root.is_dir():
        raise ValueError(f'Not a directory: {root}')
    if output.exists():
        raise FileExistsError(f'Output already exists; choose a new name: {output}')
    partial = output.with_name(output.name + '.partial')
    if partial.exists():
        raise FileExistsError(f'Partial output exists; inspect it or choose a new name: {partial}')
    excluded, candidates = [], {}
    selected = [p for p in root.iterdir() if p.is_dir() and SUPPORT.fullmatch(p.name)]
    selected += [p for p in root.iterdir() if p.is_file()]
    for value in extra:
        path = (root / value).resolve()
        if not path.is_relative_to(root):
            raise ValueError(f'Extra path must be inside root: {value}')
        if not path.exists():
            raise FileNotFoundError(path)
        selected.append(path)
    for p in root.iterdir():
        if p.is_dir() and p not in selected and not any(q.is_relative_to(p) for q in selected):
            excluded.append({'path': p.relative_to(root).as_posix(),
                             'reason': 'top_level_directory_not_selected'})
    for initial in selected:
        if initial.is_symlink():
            excluded.append({'path': str(initial.relative_to(root)), 'reason': 'symbolic_link'})
            continue
        if initial.is_file():
            candidates[initial.relative_to(root).as_posix()] = initial
            continue
        for directory, subdirs, files in os.walk(initial, followlinks=False):
            parent = Path(directory)
            for name in list(subdirs):
                p = parent / name
                if name in SKIP_DIRS or name.lower().startswith(('.venv', 'venv')) or p.is_symlink():
                    subdirs.remove(name)
                    excluded.append({'path': p.relative_to(root).as_posix(),
                                     'reason': 'cache_dependency_vcs_or_link_directory'})
            for name in files:
                p = parent / name
                candidates[p.relative_to(root).as_posix()] = p
    chosen = []
    for relative, p in sorted(candidates.items()):
        if p.resolve() in {output, partial}:
            excluded.append({'path': relative, 'reason': 'current_output'})
            continue
        if p.is_symlink() or not stat.S_ISREG(p.stat().st_mode):
            excluded.append({'path': relative, 'reason': 'not_regular_file'})
            continue
        size = p.stat().st_size
        evidence = relative.split('/')[0].lower() == 'runs' or bool(re.match(r'^(fnb|energy)', relative, re.I))
        reason = None
        if p.suffix.lower() in {'.pyc', '.pyo'}:
            reason = 'python_cache'
        elif p.name.lower() in {'.env', '.netrc', '.npmrc', 'credentials.json'} or p.name.lower().startswith('.env.'):
            reason = 'credential_file'
        elif not include_archives and p.suffix.lower() in ARCHIVES:
            reason = 'existing_archive_not_embedded_use_include_existing_archives_if_needed'
        elif not include_large_datasets and not evidence and p.suffix.lower() in {'.csv', '.tsv', '.parquet', '.pcap', '.pcapng'} and size > 32 * 1024**2:
            reason = 'large_raw_dataset_outside_runs_keep_source_separately'
        if not reason and size <= 2 * 1024**2:
            with p.open('rb') as stream:
                header = stream.read(8192)
            if header.lstrip().startswith(PRIVATE_MARKERS):
                if p.name == 'PUBLIC_DEVELOPMENT_ONLY_private.pem' and digest(p) == PUBLIC_TEST_KEY_SHA256:
                    pass  # Exact deliberately public laboratory key; see manifest.
                else:
                    reason = 'private_key'
        if reason:
            item = {'path': relative, 'bytes': size, 'reason': reason}
            if reason not in {'private_key', 'credential_file', 'python_cache'}:
                item['sha256'] = digest(p)
            excluded.append(item)
        else:
            chosen.append((relative, p))
    if not any(relative.startswith('runs/') for relative, _ in chosen):
        raise ValueError('No runs/ evidence files found. Check --root.')
    manifest = {'schema': 'ids-update-lab-local-preservation-032-v1',
                'created_utc': utc(), 'source_root': str(root),
                'hardware_access_attempted': False, 'evidence_modified': False,
                'claims_independently_verified': False,
                'include_existing_archives': include_archives,
                'include_large_datasets': include_large_datasets,
                'scope': 'Selected local runs and supporting code; includes failed runs. See exclusions.',
                'selected_roots': sorted(set(p.relative_to(root).as_posix() for p in selected)),
                'public_development_key_exception': {'filename': 'PUBLIC_DEVELOPMENT_ONLY_private.pem',
                    'sha256': PUBLIC_TEST_KEY_SHA256,
                    'purpose': 'Exact deliberately public test key for repeatable experiments; never use in production'},
                'files': [], 'excluded': excluded}
    summaries = []
    snapshot_stats = {relative: (p.stat().st_size, p.stat().st_mtime_ns) for relative, p in chosen}
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with partial.open('xb') as target:
            with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
                for index, (relative, path) in enumerate(chosen, 1):
                    before = path.stat()
                    if (before.st_size, before.st_mtime_ns) != snapshot_stats[relative]:
                        raise RuntimeError(f'File changed since collection began: {relative}')
                    h = hashlib.sha256()
                    with path.open('rb') as source, archive.open('project/' + relative, 'w', force_zip64=True) as dest:
                        for block in iter(lambda: source.read(1024 * 1024), b''):
                            h.update(block)
                            dest.write(block)
                    after = path.stat()
                    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                        raise RuntimeError(f'File changed during collection: {relative}. Wait for experiments to finish and rerun with a new output name.')
                    manifest['files'].append({'path': 'project/' + relative, 'source_relative_path': relative,
                                              'bytes': after.st_size, 'sha256': h.hexdigest()})
                    if path.name == 'summary.json':
                        try:
                            j = json.loads(path.read_text(encoding='utf-8-sig'))
                            summaries.append({'path': 'project/' + relative, 'reported_status': j.get('status'),
                                              'stage': j.get('stage'), 'measurement_origin': j.get('measurement_origin'),
                                              'inferred_records': j.get('inferred_records'), 'error': j.get('error')})
                        except (ValueError, OSError, AttributeError) as exc:
                            summaries.append({'path': 'project/' + relative, 'read_error': str(exc)})
                    if index % 250 == 0:
                        print(f'Collected {index}/{len(chosen)} files', flush=True)
                manifest['file_count'] = len(manifest['files'])
                manifest['summary_index'] = summaries
                for relative, path in chosen:
                    current = path.stat()
                    if (current.st_size, current.st_mtime_ns) != snapshot_stats[relative]:
                        raise RuntimeError(f'File changed during collection: {relative}. Wait for running experiments to finish.')
                archive.writestr('COLLECTION_MANIFEST.json', json.dumps(manifest, ensure_ascii=False, indent=2))
                archive.writestr('README_RU.txt', 'Снимок локальных результатов и кода. Плата не использовалась. Неуспешные опыты сохранены.\n'
                                 'Проверьте COLLECTION_MANIFEST.json: там SHA-256, список выбранных путей и исключений.\n'
                                 'Большие исходные датасеты вне runs и прежние ZIP (включая runs) по умолчанию сохраняются отдельно.\n')
        with zipfile.ZipFile(partial) as archive:
            for item in manifest['files']:
                h = hashlib.sha256()
                with archive.open(item['path']) as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b''):
                        h.update(block)
                if h.hexdigest() != item['sha256']:
                    raise RuntimeError(f'Archive verification failed: {item["path"]}')
            # Reading every member checks ZIP CRC as well.
            archive.read('COLLECTION_MANIFEST.json')
            archive.read('README_RU.txt')
        if output.exists():
            raise FileExistsError(f'Output appeared during collection: {output}')
        # Exclusive creation: link fails if another process created output.
        # Same-directory NTFS/ext4 hard link avoids an overwrite race.
        os.link(partial, output)
        partial.unlink()
    except Exception:
        print(f'Incomplete archive retained for inspection if present: {partial}', file=sys.stderr)
        raise
    return {'output': str(output), 'bytes': output.stat().st_size, 'sha256': digest(output),
            'file_count': len(manifest['files']), 'summary_count': len(summaries),
            'crc_and_member_sha256_verified': True, 'hardware_access_attempted': False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--include-relative', action='append', default=[])
    parser.add_argument('--include-existing-archives', action='store_true', help='Also embed old ZIP/7z archives. May greatly increase size.')
    parser.add_argument('--include-large-datasets', action='store_true', help='Also embed large raw CSV/TSV/Parquet/PCAP files from selected directories.')
    args = parser.parse_args()
    try:
        print(json.dumps(collect(args.root, args.output, args.include_relative, args.include_existing_archives,
                                 args.include_large_datasets), ensure_ascii=False))
        return 0
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
