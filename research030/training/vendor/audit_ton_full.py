#!/usr/bin/env python3
"""Streaming TON metadata audit; never loads models, predicts, fits or chooses splits.

Python 3.11+ and NumPy. All production inputs are pinned; there is no CLI bypass.
Full source files remain unchanged. Only small aggregate reports are written.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import re
import sys
import time

import numpy as np

FEATURES = ('duration', 'src_bytes', 'dst_bytes', 'missed_bytes',
            'src_pkts', 'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes')
STAGES = ('all_source', 'invalid_raw_contract', 'valid_raw_contract',
          'known_input_overlap', 'candidate_unseen_input')
REASONS = {1: 'non_numeric', 2: 'nonfinite', 3: 'negative_float32',
           4: 'float32_overflow'}
RECEIPT_NAME = 'acquisition_download_20260925T090032614352Z.json'
EXPECTED_RECEIPT = '8bc238eb5c578b21b9097fbb246bf53e35e1eb54b73fc897600d1765c7dfed8f'
MANIFEST_NAME = 'ton_iot_mirror_v1_manifest.json'
EXPECTED_MIRROR_MANIFEST = '6e54fed0d6cf0d3b935eddcdb93e532cce9b47eb4f50fd2746deadb4e03a0db5'
EXPECTED_KIT_MANIFEST = '15b72753672c9c85a9824c51addd1f3cbf2e773e5e3db64a6d2e87eb0df13736'
EXPECTED_KNOWN_SOURCE = '26ddc513552de36de6428b2e578efaed2b57504c716dfba847cc0109a64e1974'
KNOWN_FILES = ('artifacts/known_input_fingerprints.npz',
               'artifacts/known_input_fingerprints.sha256', 'external_protocol.json')
EXPECTED_NAMES = tuple(f'Network_dataset_{i}.csv' for i in range(1, 24))
MAX_LABELS, MAX_TYPES, MAX_DAYS, MAX_DAILY_CELLS = 32, 256, 4096, 200000
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path, progress=None):
    digest = hashlib.sha256()
    total = 0
    last = time.monotonic()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(8 << 20), b''):
            digest.update(block)
            total += len(block)
            if progress and time.monotonic() - last >= 5:
                progress({'event': 'hash_progress', 'file': Path(path).name,
                          'bytes_hashed': total})
                last = time.monotonic()
    return digest.hexdigest()


def read_pinned_json(path, expected):
    if sha256_file(path) != expected:
        raise ValueError(f'Pinned metadata SHA256 mismatch: {path}')
    return json.loads(Path(path).read_text(encoding='utf-8'))


def load_pinned_inputs(inputs_dir):
    """Validate exact user acquisition receipt and previously distributed schema."""
    inputs_dir = Path(inputs_dir)
    manifest = read_pinned_json(inputs_dir / MANIFEST_NAME, EXPECTED_MIRROR_MANIFEST)
    receipt = read_pinned_json(inputs_dir / RECEIPT_NAME, EXPECTED_RECEIPT)
    if (manifest['total_files'] != 23 or manifest['dataset_version'] != 1
            or manifest['required_features'] != list(FEATURES)):
        raise ValueError('Unexpected mirror manifest contract')
    if receipt.get('status') != 'complete' or receipt.get('command') != 'download':
        raise ValueError('Acquisition receipt is not a completed download')
    if receipt['manifest_sha256'] != EXPECTED_MIRROR_MANIFEST:
        raise ValueError('Receipt and manifest are not linked')
    entries = manifest['files']
    downloads = receipt['files']
    if (len(entries) != 23 or len(downloads) != 23
            or {x['name'] for x in entries} != set(EXPECTED_NAMES)
            or {x['file'] for x in downloads} != set(EXPECTED_NAMES)):
        raise ValueError('Expected exactly the 23 pinned file names')
    expected = {x['name']: x for x in entries}
    for item in downloads:
        entry = expected[item['file']]
        if (item['bytes'] != entry['bytes'] or item['expected_bytes'] != entry['bytes']
                or item['column_count'] != entry['column_count']
                or item['dataset_version'] != 1
                or item['manifest_sha256'] != EXPECTED_MIRROR_MANIFEST
                or not re.fullmatch('[0-9a-f]{64}', item['local_sha256'])):
            raise ValueError('Invalid receipt entry: ' + item['file'])
    if sum(x['bytes'] for x in entries) != manifest['total_bytes']:
        raise ValueError('Manifest total-byte mismatch')
    return manifest, receipt


def load_known(kit):
    """Open only manifest, protocol and fingerprint NPZ/sidecar; never model files."""
    kit = Path(kit)
    manifest = read_pinned_json(kit / 'KIT_MANIFEST.json', EXPECTED_KIT_MANIFEST)
    verified = {}
    for name in KNOWN_FILES:
        actual = sha256_file(kit / name)
        if actual != manifest['sha256'][name]:
            raise ValueError('Frozen kit file mismatch: ' + name)
        verified[name] = actual
    if (kit / KNOWN_FILES[1]).read_text(encoding='utf-8').split()[0] != verified[KNOWN_FILES[0]]:
        raise ValueError('Known-input sidecar mismatch')
    protocol = json.loads((kit / 'external_protocol.json').read_text(encoding='utf-8'))
    if protocol['feature_names'] != list(FEATURES) or protocol['known_source_sha256'] != EXPECTED_KNOWN_SOURCE:
        raise ValueError('Frozen feature order or source changed')
    with np.load(kit / KNOWN_FILES[0], allow_pickle=False) as data:
        known = data['fingerprints'].copy()
        rows = int(data['source_rows'])
        source = str(data['source_sha256'])
    if known.dtype != np.dtype('V32') or known.ndim != 1:
        raise ValueError('Unexpected fingerprint representation')
    known.sort()
    if (len(known) != 92330 or len(np.unique(known)) != len(known)
            or rows != 211043 or source != EXPECTED_KNOWN_SOURCE):
        raise ValueError('Unexpected frozen fingerprint metadata')
    return known, {'kit_manifest_sha256': EXPECTED_KIT_MANIFEST,
                   'verified_files': verified, 'known_source_sha256': source,
                   'known_source_rows': rows, 'known_unique_inputs': len(known)}


def normalize_raw(tokens):
    """Python float -> float32 contract; returned reason codes are per field.

    Domain is checked AFTER float32 conversion, matching the frozen evaluator.
    In particular, a tiny negative value rounding to -0 is accepted/canonicalized.
    Invalid rows must never be fingerprinted by callers.
    """
    n = len(tokens)
    doubles = np.zeros((n, len(FEATURES)), dtype=np.float64)
    reasons = np.zeros(doubles.shape, dtype=np.uint8)
    for i, row in enumerate(tokens):
        if len(row) != len(FEATURES):
            raise ValueError('Expected exactly eight raw numeric fields')
        for j, token in enumerate(row):
            try:
                doubles[i, j] = float(token)
            except (ValueError, TypeError, OverflowError):
                reasons[i, j] = 1
    with np.errstate(over='ignore', invalid='ignore', under='ignore'):
        values = doubles.astype('<f4')
    parsed = reasons == 0
    reasons[parsed & ~np.isfinite(doubles)] = 2
    reasons[parsed & np.isfinite(doubles) & ~np.isfinite(values)] = 4
    reasons[(reasons == 0) & (values < 0)] = 3
    valid = ~(reasons != 0).any(axis=1)
    signed_zero_count = int(((values[valid] == 0) & np.signbit(values[valid])).sum())
    values[values == 0] = 0.0
    return values, valid, reasons, signed_zero_count


def fingerprint_rows(values):
    values = np.ascontiguousarray(values, dtype='<f4')
    if values.ndim != 2 or values.shape[1] != 8:
        raise ValueError('Fingerprint input must have shape (n, 8)')
    if not np.isfinite(values).all() or (values < 0).any():
        raise ValueError('Cannot fingerprint contract-invalid input')
    values = values.copy()
    values[values == 0] = 0.0
    raw = memoryview(values).cast('B') if len(values) else memoryview(b'')
    blob = b''.join(hashlib.sha256(raw[i:i+32]).digest() for i in range(0, len(raw), 32))
    return np.frombuffer(blob, dtype='V32')


def parse_timestamp(token):
    """Interpret UNIX seconds in UTC using float64, independently of raw inputs."""
    try:
        value = float(token)
    except (ValueError, TypeError, OverflowError):
        return None, None, 'non_numeric'
    if not math.isfinite(value):
        return None, None, 'nonfinite'
    try:
        day = (EPOCH + timedelta(days=math.floor(value / 86400))).date().isoformat()
        # Also ensure the seconds themselves have a representable UTC value.
        EPOCH + timedelta(seconds=value)
    except (ValueError, OverflowError):
        return None, None, 'out_of_datetime_range'
    return value, day, None


def timestamp_iso(value):
    return None if value is None else (EPOCH + timedelta(seconds=value)).isoformat()


def new_report():
    return {'rows': 0, 'unknown_label_rows': 0, 'invalid_timestamp_rows': 0,
            'invalid_timestamp_reasons': Counter(), 'invalid_timestamp_examples': [],
            'invalid_raw_fields': {x: Counter() for x in FEATURES},
            'invalid_raw_examples': [], 'unknown_label_examples': [],
            'signed_zero_values_canonicalized': 0,
            'stages': {s: {'rows': 0, 'label_counts': Counter(), 'type_counts': Counter(),
                            'timestamp_min': None, 'timestamp_max': None,
                            'invalid_timestamp_rows': 0} for s in STAGES},
            'timestamp_first_valid': None, 'timestamp_last_valid': None,
            'backwards_between_consecutive_valid_timestamps': 0}


def bump(counter, key, limit):
    if key not in counter and len(counter) >= limit:
        raise ValueError('Metadata category limit exceeded; inspect source before enlarging limits')
    counter[key] += 1


def add_stage(report, stage, label, kind, ts):
    target = report['stages'][stage]
    target['rows'] += 1
    bump(target['label_counts'], label, MAX_LABELS)
    bump(target['type_counts'], kind, MAX_TYPES)
    if ts is None:
        target['invalid_timestamp_rows'] += 1
    else:
        target['timestamp_min'] = ts if target['timestamp_min'] is None else min(ts, target['timestamp_min'])
        target['timestamp_max'] = ts if target['timestamp_max'] is None else max(ts, target['timestamp_max'])


def audit_csv(path, expected_header, known, chunk_rows, progress_callback=None):
    """Stream one CSV; callers enforce production source hashes separately.

    Return (aggregate_report, daily_counter, observed_known_mask).
    Daily keys are (UTC day or INVALID_TS, stage, original label, original type).
    """
    if chunk_rows < 1:
        raise ValueError('chunk_rows must be positive')
    path = Path(path)
    known = np.asarray(known)
    if known.dtype != np.dtype('V32') or known.ndim != 1 or not np.array_equal(known, np.sort(known)):
        raise ValueError('Known fingerprints must be a sorted V32 array')
    report, daily = new_report(), Counter()
    seen = np.zeros(len(known), dtype=bool)
    observed_days = set()
    last_progress, last_progress_rows = time.monotonic(), 0

    def consume(batch):
        nonlocal last_progress, last_progress_rows
        raw = [r[0] for r in batch]
        values, valid, reasons, zeros = normalize_raw(raw)
        report['signed_zero_values_canonicalized'] += zeros
        fingerprints = fingerprint_rows(values[valid])
        matched_valid = np.isin(fingerprints, known)
        matched = np.zeros(len(batch), dtype=bool)
        matched[valid] = matched_valid
        if matched_valid.any():
            seen[np.searchsorted(known, fingerprints[matched_valid])] = True
        for j, name in enumerate(FEATURES):
            for code, reason in REASONS.items():
                amount = int((reasons[:, j] == code).sum())
                if amount:
                    report['invalid_raw_fields'][name][reason] += amount
        for i, (_, label, kind, ts_token, record_index) in enumerate(batch):
            report['rows'] += 1
            if label not in ('0', '1'):
                report['unknown_label_rows'] += 1
                if len(report['unknown_label_examples']) < 10:
                    report['unknown_label_examples'].append({'source_row_index_zero_based': record_index,
                                                            'label': label[:160]})
            ts, day, reason = parse_timestamp(ts_token)
            if reason:
                report['invalid_timestamp_rows'] += 1
                report['invalid_timestamp_reasons'][reason] += 1
                if len(report['invalid_timestamp_examples']) < 10:
                    report['invalid_timestamp_examples'].append({'source_row_index_zero_based': record_index,
                        'ts': ts_token[:160], 'reason': reason})
            else:
                previous = report['timestamp_last_valid']
                if previous is not None and ts < previous:
                    report['backwards_between_consecutive_valid_timestamps'] += 1
                if report['timestamp_first_valid'] is None:
                    report['timestamp_first_valid'] = ts
                report['timestamp_last_valid'] = ts
            day = day or 'INVALID_TS'
            observed_days.add(day)
            if len(observed_days) > MAX_DAYS:
                raise ValueError('UTC-day category limit exceeded')
            stages = ['all_source']
            if not valid[i]:
                stages.append('invalid_raw_contract')
                if len(report['invalid_raw_examples']) < 10:
                    report['invalid_raw_examples'].append({'source_row_index_zero_based': record_index,
                        'fields': {FEATURES[j]: {'value': raw[i][j][:160], 'reason': REASONS[int(reasons[i,j])]}
                                   for j in range(8) if reasons[i,j]}})
            else:
                stages += ['valid_raw_contract', 'known_input_overlap' if matched[i] else 'candidate_unseen_input']
            for stage in stages:
                add_stage(report, stage, label, kind, ts)
                bump(daily, (day, stage, label, kind), MAX_DAILY_CELLS)
            if progress_callback and i % 4096 == 0 and time.monotonic() - last_progress >= 5:
                progress_callback({'event': 'audit_progress', 'file': path.name, 'rows': report['rows']})
                last_progress, last_progress_rows = time.monotonic(), report['rows']
        now = time.monotonic()
        if progress_callback and (now - last_progress >= 5 or report['rows'] - last_progress_rows >= 250000):
            progress_callback({'event': 'audit_progress', 'file': path.name, 'rows': report['rows']})
            last_progress, last_progress_rows = now, report['rows']

    # Large URIs/user-agent fields should not trip the csv module's small default.
    csv.field_size_limit(16 << 20)
    with path.open(encoding='utf-8-sig', newline='') as source:
        reader = csv.reader(source, strict=True)
        header = next(reader, None)
        if header != list(expected_header) or len(header or []) != len(set(header or [])):
            raise ValueError('Missing, duplicate or unexpected CSV header: ' + path.name)
        if not set(FEATURES + ('ts', 'label', 'type')).issubset(header):
            raise ValueError('Missing required named columns')
        feature_idx = [header.index(name) for name in FEATURES]
        label_idx, type_idx, ts_idx = (header.index(name) for name in ('label', 'type', 'ts'))
        batch = []
        for row_index, row in enumerate(reader):
            if len(row) != len(header):
                raise ValueError(f'{path.name}: malformed record {row_index}: expected {len(header)} fields, got {len(row)}')
            if len(row[label_idx]) > 256 or len(row[type_idx]) > 256:
                raise ValueError('Oversized label or type metadata')
            batch.append(([row[k] for k in feature_idx], row[label_idx], row[type_idx], row[ts_idx], row_index))
            if len(batch) >= chunk_rows:
                consume(batch)
                batch = []
            elif progress_callback and row_index % 4096 == 0 and time.monotonic() - last_progress >= 5:
                progress_callback({'event': 'csv_read_progress', 'file': path.name, 'rows_read': row_index + 1,
                                   'rows_aggregated': report['rows']})
                last_progress = time.monotonic()
        if batch:
            consume(batch)
    validate_counts(report)
    report['unique_known_inputs_observed'] = int(seen.sum())
    report['valid_utc_days_observed'] = len(observed_days - {'INVALID_TS'})
    return report, daily, seen


def validate_counts(report):
    s = report['stages']
    if not (report['rows'] == s['all_source']['rows']
            == s['invalid_raw_contract']['rows'] + s['valid_raw_contract']['rows']
            and s['valid_raw_contract']['rows']
            == s['known_input_overlap']['rows'] + s['candidate_unseen_input']['rows']):
        raise ValueError('Internal aggregate row invariant failed')
    for stage in s.values():
        if sum(stage['label_counts'].values()) != stage['rows'] or sum(stage['type_counts'].values()) != stage['rows']:
            raise ValueError('Internal aggregate label/type invariant failed')


def merge_report(total, part):
    for name in ('rows', 'unknown_label_rows', 'invalid_timestamp_rows', 'signed_zero_values_canonicalized',
                 'backwards_between_consecutive_valid_timestamps'):
        total[name] += part[name]
    for name in ('invalid_raw_examples', 'invalid_timestamp_examples', 'unknown_label_examples'):
        total[name] = (total[name] + part[name])[:10]
    total['invalid_timestamp_reasons'].update(part['invalid_timestamp_reasons'])
    for name in FEATURES:
        total['invalid_raw_fields'][name].update(part['invalid_raw_fields'][name])
    first, last = part['timestamp_first_valid'], part['timestamp_last_valid']
    if first is not None:
        if total['timestamp_last_valid'] is not None and first < total['timestamp_last_valid']:
            total['backwards_between_consecutive_valid_timestamps'] += 1
        if total['timestamp_first_valid'] is None:
            total['timestamp_first_valid'] = first
        total['timestamp_last_valid'] = last
    for name in STAGES:
        target, source = total['stages'][name], part['stages'][name]
        target['rows'] += source['rows']
        target['invalid_timestamp_rows'] += source['invalid_timestamp_rows']
        for axis, limit in (('label_counts', MAX_LABELS), ('type_counts', MAX_TYPES)):
            target[axis].update(source[axis])
            if len(target[axis]) > limit:
                raise ValueError('Global metadata category limit exceeded')
        for axis, operation in (('timestamp_min', min), ('timestamp_max', max)):
            if source[axis] is not None:
                target[axis] = source[axis] if target[axis] is None else operation(target[axis], source[axis])


def write_json(path, data):
    # Only used in a new output directory; failed summaries replace no successful run.
    with Path(path).open('w', encoding='utf-8', newline='\n') as destination:
        json.dump(data, destination, indent=2, ensure_ascii=False, allow_nan=False)
        destination.write('\n')


def stat_signature(path):
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns, stat.st_ino


def run_audit(args):
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    started = utc_now()
    started_clock = time.monotonic()
    per_file, total, global_daily = [], new_report(), Counter()
    provenance = {'stage': '022', 'analysis': 'metadata_only', 'started_utc': started,
                  'script_sha256': sha256_file(__file__), 'predictions_computed': False,
                  'models_loaded': False, 'training_performed': False, 'test_split_selected': False,
                  'python': platform.python_version(), 'numpy': np.__version__,
                  'data_dir': str(Path(args.data_dir).resolve()), 'kit': str(Path(args.kit).resolve()),
                  'chunk_rows': args.chunk_rows}
    progress_stream = (output / 'progress.jsonl').open('x', encoding='utf-8')

    def progress(record):
        item = {'utc': utc_now(), **record}
        progress_stream.write(json.dumps(item, ensure_ascii=False) + '\n')
        progress_stream.flush()
        print(json.dumps(record, ensure_ascii=False), flush=True)

    try:
        if not 1 <= args.chunk_rows <= 250000:
            raise ValueError('chunk_rows must be between 1 and 250000')
        manifest, receipt = load_pinned_inputs(Path(__file__).resolve().parents[1] / 'inputs')
        wanted = list(args.files) if args.files else list(EXPECTED_NAMES)
        if len(wanted) != len(set(wanted)) or not set(wanted).issubset(EXPECTED_NAMES):
            raise ValueError('Select unique exact manifest file names with --files')
        selected = [name for name in EXPECTED_NAMES if name in wanted]
        if not selected:
            raise ValueError('No files selected')
        entries = {x['name']: x for x in manifest['files']}
        downloads = {x['file']: x for x in receipt['files']}
        known, known_metadata = load_known(args.kit)
        all_seen = np.zeros(len(known), dtype=bool)
        provenance.update({'scope': 'full_collection' if len(selected) == 23 else 'selected_files',
            'selected_files_in_processing_order': selected, 'omitted_files': [x for x in EXPECTED_NAMES if x not in selected],
            'expected_mirror_manifest_sha256': EXPECTED_MIRROR_MANIFEST,
            'user_acquisition_receipt_sha256': EXPECTED_RECEIPT,
            'hash_authority': 'user_download_receipt_not_publisher_verified',
            'mirror_dataset': manifest['dataset'], 'mirror_dataset_version': 1,
            'known_inputs': known_metadata, 'feature_order': list(FEATURES),
            'numeric_contract': 'Python float -> little-endian float32; finite and nonnegative AFTER conversion; canonical signed zero',
            'raw_input_fingerprint': 'SHA256 of eight little-endian float32 values; no label or timestamp',
            'timestamp_rule': 'UNIX seconds interpreted in UTC with float64; invalid ts counted, never excluded from numeric stages',
            'label_rule': 'exact text 0 or 1; any other value blocks suitability',
            'global_backwards_rule': 'consecutive valid timestamps across selected files in numeric file order; not proof of collection ordering',
            'candidate_unique_input_count_computed': False,
            'independent_test_established': False, 'temporal_training_established': False,
            'limitations': [
                'Candidate unseen means only not equal to a known eight-feature float32 vector.',
                'Identical compressed vectors need not identify the same original network flow.',
                'Matching-vector timestamp bounds are conservative source occurrences, NOT recovered training-row times.',
                'Additional TON files belong to the same collection; no independent collection or future test is established.',
                'No output rows, model predictions, detector metrics, split or threshold choices are produced.',
                'Candidate duplicates are retained in row counts; global distinct candidate count is deliberately not computed.',
                'Feature names/header checks do not prove original extraction semantics or byte identity to the official source.']})
        write_json(output / 'provenance.json', provenance)
        # Verify every selected file before reading any for metadata. No silent fallback.
        checked = {}
        for name in selected:
            path = Path(args.data_dir) / name
            before = stat_signature(path)
            progress({'event': 'verify_file', 'file': name, 'bytes': before[0]})
            if before[0] != entries[name]['bytes']:
                raise ValueError('Source size mismatch: ' + name)
            digest = sha256_file(path, progress)
            if digest != downloads[name]['local_sha256']:
                raise ValueError('Source SHA256 differs from your acquisition receipt: ' + name)
            with path.open(encoding='utf-8-sig', newline='') as stream:
                header = next(csv.reader(stream, strict=True), None)
            if header != entries[name]['csv_header'] or len(header or []) != len(set(header or [])):
                raise ValueError('Source header mismatch: ' + name)
            if before != stat_signature(path):
                raise ValueError('Source changed while verifying: ' + name)
            checked[name] = before
        provenance['selected_source_integrity_verified'] = True
        provenance['selected_source_hashes'] = {name: downloads[name]['local_sha256'] for name in selected}
        write_json(output / 'provenance.json', provenance)
        for name in selected:
            path = Path(args.data_dir) / name
            if checked[name] != stat_signature(path):
                raise ValueError('Source changed after verification: ' + name)
            progress({'event': 'audit_file_start', 'file': name})
            report, daily, seen = audit_csv(path, entries[name]['csv_header'], known,
                                             args.chunk_rows, progress)
            if checked[name] != stat_signature(path):
                raise ValueError('Source changed during CSV audit: ' + name)
            report.update({'file': name, 'bytes': checked[name][0], 'sha256': downloads[name]['local_sha256'],
                           'column_count': len(entries[name]['csv_header'])})
            for field in ('invalid_raw_examples', 'invalid_timestamp_examples', 'unknown_label_examples'):
                for item in report[field]:
                    item['file'] = name
            per_file.append(report)
            merge_report(total, report)
            global_daily.update(daily)
            if len(global_daily) > MAX_DAILY_CELLS or len({key[0] for key in global_daily}) > MAX_DAYS:
                raise ValueError('Global daily metadata aggregation limit exceeded')
            all_seen |= seen
            write_json(output / 'per_file.json', per_file)
            progress({'event': 'audit_file_complete', 'file': name, 'rows': report['rows'],
                      'total_rows': total['rows'], 'candidate_rows': report['stages']['candidate_unseen_input']['rows']})
        validate_counts(total)
        status = 'blocked_unknown_labels' if total['unknown_label_rows'] else 'complete'
        with (output / 'daily_counts.csv').open('x', encoding='utf-8', newline='') as destination:
            writer = csv.writer(destination)
            writer.writerow(['utc_day', 'stage', 'label', 'type', 'rows'])
            for key, count in sorted(global_daily.items()):
                writer.writerow([*key, count])
        total.update({'stage': '022', 'status': status, 'scope': provenance['scope'],
            'files_processed': len(per_file), 'files_in_full_collection': 23,
            'predictions_computed': False, 'models_loaded': False, 'training_performed': False,
            'test_split_selected': False, 'independent_test_established': False,
            'temporal_training_established': False,
            'known_unique_inputs': len(known), 'unique_known_inputs_observed': int(all_seen.sum()),
            'known_unique_inputs_not_observed': int((~all_seen).sum()),
            'candidate_unique_input_count': None,
            'candidate_unique_input_count_reason': 'Not computed: streaming metadata audit retains no global candidate fingerprints.',
            'matching_known_vector_timestamp_bounds_utc': {
                'min': timestamp_iso(total['stages']['known_input_overlap']['timestamp_min']),
                'max': timestamp_iso(total['stages']['known_input_overlap']['timestamp_max']),
                'meaning': 'All matching-vector source occurrences; NOT actual historical training-row times.'},
            'started_utc': started, 'finished_utc': utc_now(),
            'elapsed_seconds': time.monotonic() - started_clock})
        write_json(output / 'summary.json', total)
        progress({'event': 'finished', 'status': status, 'scope': provenance['scope'],
                  'rows': total['rows'], 'output': str(output.resolve())})
        return 0 if status == 'complete' else 2
    except (Exception, KeyboardInterrupt) as error:
        failed = {'stage': '022', 'status': 'failed', 'error': str(error) or type(error).__name__,
                  'error_type': type(error).__name__, 'started_utc': started, 'finished_utc': utc_now(),
                  'files_completed': len(per_file), 'rows_in_completed_files': total['rows'],
                  'partial_counts_usable_as_full_result': False, 'predictions_computed': False,
                  'models_loaded': False, 'training_performed': False,
                  'independent_test_established': False, 'temporal_training_established': False}
        write_json(output / 'summary.json', failed)
        write_json(output / 'per_file.json', per_file)
        write_json(output / 'provenance.json', provenance)
        progress({'event': 'failed', 'error': failed['error'], 'output': str(output.resolve())})
        return 2
    finally:
        progress_stream.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', type=Path, required=True)
    parser.add_argument('--kit', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--files', nargs='+', help='Optional subset of exact file names; report marked selected_files (partial audit)')
    parser.add_argument('--chunk-rows', type=int, default=50000)
    args = parser.parse_args(argv)
    if args.output.exists():
        print('ERROR: Output exists; choose a fresh output directory. Nothing was overwritten.', file=sys.stderr)
        return 2
    try:
        return run_audit(args)
    except OSError as error:
        print('ERROR: Could not create fresh audit output: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
