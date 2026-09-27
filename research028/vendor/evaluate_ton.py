#!/usr/bin/env python3
"""Frozen-model confirmation on all audited TON candidate rows, without training.

This is a new SAME-COLLECTION protocol; it does not relax stage020's external-
collection guard. Sources, runtime, model packets and the prior metadata audit
are pinned before the first new prediction. Outputs are bounded aggregates.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import sys
import time

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PROTOCOL_SHA256 = '0c9f764fb309fa9c49bb51c8518cadd5599125c3887f2b6f27a57ad06d064269'
EXPECTED_AUDIT_SHA256 = 'b7b042464a70f1447b5885971ae92e7768d209ce6b89f7e053ecf744aa0dd37a'
EXPECTED_KIT_MANIFEST = '15b72753672c9c85a9824c51addd1f3cbf2e773e5e3db64a6d2e87eb0df13736'
MODEL_IDS = ('A', 'B', 'stale_scale', 'stale_threshold', 'stale_both',
             'compatible_probability', 'compatible_decision', 'restored_B', 'DT_A', 'DT_B')
COUNT_NAMES = ('tn', 'fp', 'fn', 'tp', 'changed')
METRIC_NAMES = ('attack_recall', 'FPR', 'balanced_accuracy', 'accuracy', 'decision_disagreement')


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n', encoding='utf-8')


def import_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError('Cannot load pinned module: ' + str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def reference_indices(model_ids):
    names = list(model_ids)
    if len(names) != len(set(names)):
        raise ValueError('Duplicate model IDs')
    return [names.index('DT_B' if name.startswith('DT_') else 'B') for name in names]


def metric_counts(labels, predictions, references):
    labels, predictions = np.asarray(labels), np.asarray(predictions)
    if labels.ndim != 1 or predictions.ndim != 2 or len(labels) != len(predictions):
        raise ValueError('Invalid prediction or target shapes')
    if not np.isin(labels, [0, 1]).all() or not np.isin(predictions, [0, 1]).all():
        raise ValueError('Expected binary targets and decisions')
    references = np.asarray(references, dtype=np.int64)
    if references.shape != (predictions.shape[1],) or (references < 0).any() or (references >= predictions.shape[1]).any():
        raise ValueError('Invalid reference model indices')
    neg, pos = labels[:, None] == 0, labels[:, None] == 1
    return np.stack(((neg & (predictions == 0)).sum(axis=0),
                     (neg & (predictions == 1)).sum(axis=0),
                     (pos & (predictions == 0)).sum(axis=0),
                     (pos & (predictions == 1)).sum(axis=0),
                     (predictions != predictions[:, references]).sum(axis=0)), axis=1).astype(np.int64)


def metrics_from_counts(counts):
    values = np.asarray(counts)
    if values.shape != (5,) or not np.isfinite(values).all() or (values < 0).any() or (values != np.floor(values)).any():
        raise ValueError('Expected five nonnegative integer counts')
    tn, fp, fn, tp, changed = map(int, values)
    n = tn + fp + fn + tp
    if changed > n:
        raise ValueError('Disagreement exceeds evaluated records')
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    return {'attack_recall': recall, 'FPR': fpr,
            'balanced_accuracy': (recall + 1 - fpr) / 2 if recall is not None and fpr is not None else None,
            'accuracy': (tn + tp) / n if n else None,
            'decision_disagreement': changed / n if n else None}


def result_from_counts(counts, model_ids):
    counts = np.asarray(counts)
    if counts.shape != (len(model_ids), 5):
        raise ValueError('Unexpected model-count shape')
    references = reference_indices(model_ids)
    measured = [metrics_from_counts(row) for row in counts]
    result = {}
    for i, name in enumerate(model_ids):
        tn, fp, fn, tp, changed = map(int, counts[i])
        base = measured[references[i]]
        result[name] = {'reference_model_id': model_ids[references[i]],
                        'confusion_matrix_0_1': [[tn, fp], [fn, tp]],
                        'evaluated_rows': tn + fp + fn + tp,
                        'decision_disagreement_count': changed, 'metrics': measured[i],
                        'paired_delta_vs_reference': {
                            key: measured[i][key] - base[key] if measured[i][key] is not None and base[key] is not None else None
                            for key in METRIC_NAMES}}
    return result


def leave_one_day_out(total_counts, by_day_counts, model_ids):
    total_counts = np.asarray(total_counts)
    if not np.array_equal(sum(by_day_counts.values(), np.zeros_like(total_counts)), total_counts):
        raise ValueError('Daily confusion counts do not sum to global counts')
    omitted = {day: result_from_counts(total_counts - counts, model_ids)
               for day, counts in sorted(by_day_counts.items())}
    ranges = {}
    for name in model_ids:
        ranges[name] = {}
        for key in METRIC_NAMES:
            values = [records[name]['paired_delta_vs_reference'][key] for records in omitted.values()]
            finite = [x for x in values if x is not None]
            ranges[name][key] = {'min': min(finite) if finite else None,
                                 'max': max(finite) if finite else None,
                                 'defined_omissions': len(finite), 'total_omissions': len(values)}
    return {'interpretation': 'Descriptive sensitivity to omitting one observed UTC day; not confidence intervals or independent replications.',
            'by_omitted_utc_day': omitted, 'paired_delta_ranges': ranges}


def new_accumulator(model_ids):
    n = len(model_ids)
    return {'model_ids': list(model_ids), 'counts': np.zeros((n, 5), dtype=np.int64),
            'by_day': {}, 'by_type': {}, 'probability_abs_diff_sum': np.zeros(n, dtype=np.float64),
            'probability_abs_diff_max': np.zeros(n, dtype=np.float64),
            'changed_reference_margin_sum': np.zeros(n, dtype=np.float64),
            'changed_reference_margin_min': np.full(n, np.inf),
            'changed_reference_margin_max': np.zeros(n, dtype=np.float64)}


def accumulate_predictions(raw, labels, days, types, models, predictors, accumulator, progress=None):
    names = accumulator['model_ids']
    if list(models) != names or set(predictors) != set(names):
        raise ValueError('Loaded model order differs from frozen accumulator')
    raw, labels = np.asarray(raw), np.asarray(labels)
    days, types = np.asarray(days), np.asarray(types)
    if raw.ndim != 2 or raw.shape[1] != 8 or any(len(v) != len(raw) for v in (labels, days, types)):
        raise ValueError('Invalid retained batch shapes')
    if not len(raw):
        return
    # Sub-batches keep the original scalar-tree runtime responsive on slow PCs.
    if len(raw) > 4096:
        for start in range(0, len(raw), 4096):
            sl = slice(start, start + 4096)
            accumulate_predictions(raw[sl], labels[sl], days[sl], types[sl], models, predictors, accumulator, progress)
        return
    pairs = [predictors[name](models[name], raw) for name in names]
    probabilities = np.stack([pair[0] for pair in pairs], axis=1)
    predictions = np.stack([pair[1] for pair in pairs], axis=1)
    if probabilities.shape != (len(raw), len(names)) or not np.isfinite(probabilities).all() or (probabilities < 0).any() or (probabilities > 1).any():
        raise ValueError('Invalid model probability output')
    references = reference_indices(names)
    accumulator['counts'] += metric_counts(labels, predictions, references)
    for field, values in (('by_day', days), ('by_type', types)):
        for value in np.unique(values):
            selected = values == value
            bucket = accumulator[field].setdefault(str(value), np.zeros_like(accumulator['counts']))
            bucket += metric_counts(labels[selected], predictions[selected], references)
    differences = np.abs(probabilities.astype(np.float64) - probabilities[:, references].astype(np.float64))
    accumulator['probability_abs_diff_sum'] += differences.sum(axis=0)
    accumulator['probability_abs_diff_max'] = np.maximum(accumulator['probability_abs_diff_max'], differences.max(axis=0))
    for i, index in enumerate(references):
        changed = predictions[:, i] != predictions[:, index]
        if changed.any():
            margins = np.abs(probabilities[changed, index].astype(np.float64) - float(np.float32(models[names[index]].threshold)))
            accumulator['changed_reference_margin_sum'][i] += margins.sum()
            accumulator['changed_reference_margin_min'][i] = min(accumulator['changed_reference_margin_min'][i], float(margins.min()))
            accumulator['changed_reference_margin_max'][i] = max(accumulator['changed_reference_margin_max'][i], float(margins.max()))
    if progress:
        progress({'event': 'prediction_progress', 'retained_rows_scored': int(accumulator['counts'][0, :4].sum())}, force=False)


def finalize_results(accumulator, models, all_types):
    names = accumulator['model_ids']
    result = result_from_counts(accumulator['counts'], names)
    for i, name in enumerate(names):
        records = result[name]['evaluated_rows']
        changes = result[name]['decision_disagreement_count']
        result[name].update({'threshold': float(np.float32(models[name].threshold)),
            'probability_abs_difference_vs_reference': {
                'sum': float(accumulator['probability_abs_diff_sum'][i]),
                'mean': float(accumulator['probability_abs_diff_sum'][i] / records) if records else None,
                'max': float(accumulator['probability_abs_diff_max'][i]) if records else None},
            'reference_probability_distance_to_threshold_on_disagreements': {
                'count': changes,
                'min': float(accumulator['changed_reference_margin_min'][i]) if changes else None,
                'max': float(accumulator['changed_reference_margin_max'][i]) if changes else None,
                'mean': float(accumulator['changed_reference_margin_sum'][i] / changes) if changes else None}})
    by_type = {kind: result_from_counts(accumulator['by_type'].get(kind, np.zeros_like(accumulator['counts'])), names)
               for kind in sorted(all_types)}
    by_day = {day: result_from_counts(counts, names) for day, counts in sorted(accumulator['by_day'].items())}
    if not np.array_equal(sum(accumulator['by_type'].values(), np.zeros_like(accumulator['counts'])), accumulator['counts']):
        raise ValueError('Type confusion counts do not sum to global counts')
    return {'metrics': result, 'by_day': by_day, 'by_type': by_type,
            'leave_one_day_out': leave_one_day_out(accumulator['counts'], accumulator['by_day'], names)}


def load_frozen_models(kit):
    kit = Path(kit).resolve()
    if sha256_file(kit / 'KIT_MANIFEST.json') != EXPECTED_KIT_MANIFEST:
        raise ValueError('Frozen KIT_MANIFEST SHA256 mismatch')
    manifest = json.loads((kit / 'KIT_MANIFEST.json').read_text(encoding='utf-8'))['sha256']
    required = {'tools/evaluate_external.py', 'external_protocol.json',
                'artifacts/dt/feature_contract.json', 'artifacts/dt/release-A.sids', 'artifacts/dt/release-B.sids',
                'references/artifacts019/feature_contract.json', 'references/artifacts019/public.pem'}
    required.update('references/artifacts019/release-' + name + '.sids' for name in MODEL_IDS if not name.startswith('DT_'))
    required.update(name for name in manifest if name.startswith('host/') and name.endswith('.py'))
    runtime_paths = {p.relative_to(kit).as_posix() for p in (kit / 'host').rglob('*.py')}
    if not runtime_paths.issubset(required):
        raise ValueError('Unmanifested Python file in frozen host runtime')
    verified = {}
    for name in sorted(required):
        actual = sha256_file(kit / name)
        if name not in manifest or actual != manifest[name]:
            raise ValueError('Frozen model/runtime file mismatch: ' + name)
        verified[name] = actual
    for name, module in list(sys.modules.items()):
        if name == 'ids_update_lab' or name.startswith('ids_update_lab.'):
            source = getattr(module, '__file__', None)
            if source is None or not Path(source).resolve().is_relative_to(kit / 'host'):
                raise ValueError('Another ids_update_lab runtime is already imported; run in a fresh Python process')
    module = import_file('_frozen_stage020_external_for023', kit / 'tools/evaluate_external.py')
    models, predictors = module.load_models()
    if tuple(models) != MODEL_IDS:
        raise ValueError('Frozen model set/order mismatch')
    for module_name in ('ids_update_lab.package', 'ids_update_lab.tree_package'):
        source = Path(sys.modules[module_name].__file__).resolve()
        if not source.is_relative_to(kit / 'host'):
            raise ValueError('Runtime import escaped the verified host directory')
    return models, predictors, {'kit_manifest_sha256': EXPECTED_KIT_MANIFEST,
        'verified_kit_files': verified,
        'model_payload_sha256': {name: hashlib.sha256(model.payload()).hexdigest() for name, model in models.items()}}


def load_protocol(root=ROOT):
    root = Path(root)
    protocol_path = root / 'protocol.json'
    if sha256_file(protocol_path) != EXPECTED_PROTOCOL_SHA256:
        raise ValueError('Pinned stage023 protocol SHA256 mismatch')
    protocol = json.loads(protocol_path.read_text(encoding='utf-8'))
    if protocol['stage'] != '023' or tuple(protocol['model_ids']) != MODEL_IDS or protocol['kit_manifest_sha256'] != EXPECTED_KIT_MANIFEST:
        raise ValueError('Unexpected frozen protocol identifiers')
    for relative, expected in protocol['pinned_files'].items():
        path = (root / relative).resolve()
        if not path.is_relative_to(root.resolve()) or sha256_file(path) != expected:
            raise ValueError('Pinned stage023 input mismatch: ' + relative)
    audit_path = root / 'tools/audit_ton_full.py'
    if sha256_file(audit_path) != EXPECTED_AUDIT_SHA256:
        raise ValueError('Frozen stage022 numeric audit code mismatch')
    return protocol, import_file('_frozen_stage022_audit_for023', audit_path)


def read_daily(path):
    result = Counter()
    with Path(path).open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != ['utc_day', 'stage', 'label', 'type', 'rows']:
            raise ValueError('Unexpected audited daily metadata header')
        for row in reader:
            key = tuple(row[name] for name in ('utc_day', 'stage', 'label', 'type'))
            if key in result or int(row['rows']) <= 0:
                raise ValueError('Invalid/duplicate audited daily metadata row')
            result[key] = int(row['rows'])
    return result


def validate_metadata(observed_stages, observed_daily, expected_summary, expected_daily=None):
    if set(observed_stages) != set(expected_summary['stages']):
        raise ValueError('Stage names differ from metadata audit')
    for name, observed in observed_stages.items():
        expected = expected_summary['stages'][name]
        for axis in ('rows', 'label_counts', 'type_counts', 'timestamp_min', 'timestamp_max', 'invalid_timestamp_rows'):
            if observed[axis] != expected[axis]:
                raise ValueError('Recomputed stage022 aggregate mismatch: ' + name + '/' + axis)
    if expected_daily is not None and dict(observed_daily) != dict(expected_daily):
        raise ValueError('Recomputed stage022 UTC-day/label/type metadata mismatch')


def validate_audit_inputs(summary, provenance, receipt):
    if (summary.get('status') != 'complete' or summary.get('scope') != 'full_collection'
            or summary.get('files_processed') != 23 or summary.get('unknown_label_rows') != 0
            or summary.get('invalid_timestamp_rows') != 0 or summary.get('predictions_computed') is not False):
        raise ValueError('A completed label/time-valid full23 metadata-only audit is required')
    receipt_hashes = {item['file']: item['local_sha256'] for item in receipt['files']}
    if provenance.get('selected_source_integrity_verified') is not True or provenance.get('selected_source_hashes') != receipt_hashes:
        raise ValueError('Metadata audit provenance is not linked to all acquisition hashes')
    if provenance.get('script_sha256') != EXPECTED_AUDIT_SHA256:
        raise ValueError('Metadata audit was produced by a different script')


def verify_sources(data_dir, manifest, receipt, audit, progress):
    entries = {item['name']: item for item in manifest['files']}
    downloads = {item['file']: item for item in receipt['files']}
    checked = {}
    for name in audit.EXPECTED_NAMES:
        path = Path(data_dir) / name
        before = audit.stat_signature(path)
        progress({'event': 'verify_file', 'file': name, 'bytes': before[0]})
        if before[0] != entries[name]['bytes']:
            raise ValueError('Source size mismatch: ' + name)
        if audit.sha256_file(path, progress) != downloads[name]['local_sha256']:
            raise ValueError('Source SHA256 differs from stage022/acquisition: ' + name)
        with path.open(encoding='utf-8-sig', newline='') as stream:
            header = next(csv.reader(stream, strict=True), None)
        if header != entries[name]['csv_header'] or len(header or []) != len(set(header or [])):
            raise ValueError('Pinned source header mismatch: ' + name)
        if before != audit.stat_signature(path):
            raise ValueError('Source changed during integrity check: ' + name)
        checked[name] = before
    return checked


def evaluate_csv(path, expected_header, known, chunk_rows, audit, models, predictors, accumulator, progress):
    stages = audit.new_report()['stages']
    daily = Counter()
    rows_read = 0

    def consume(batch):
        values, valid, reasons, zeros = audit.normalize_raw([row[0] for row in batch])
        overlap = np.zeros(len(batch), dtype=bool)
        overlap[valid] = np.isin(audit.fingerprint_rows(values[valid]), known)
        keep = valid & ~overlap
        labels, days, kinds = [], [], []
        for i, (_, label, kind, ts_token) in enumerate(batch):
            if label not in ('0', '1'):
                raise ValueError('Unknown target label')
            ts, day, reason = audit.parse_timestamp(ts_token)
            if reason:
                raise ValueError('Invalid timestamp; audited source should contain none')
            active = ['all_source', 'valid_raw_contract' if valid[i] else 'invalid_raw_contract']
            if valid[i]:
                active.append('known_input_overlap' if overlap[i] else 'candidate_unseen_input')
            for stage in active:
                audit.add_stage({'stages': stages}, stage, label, kind, ts)
                audit.bump(daily, (day, stage, label, kind), audit.MAX_DAILY_CELLS)
            if keep[i]:
                labels.append(int(label)); days.append(day); kinds.append(kind)
            if i % 4096 == 0:
                progress({'event': 'metadata_progress', 'file': path.name, 'rows_read': rows_read}, force=False)
        accumulate_predictions(values[keep], np.asarray(labels, dtype=np.int64), days, kinds,
                               models, predictors, accumulator, progress)

    csv.field_size_limit(16 << 20)
    with Path(path).open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.reader(stream, strict=True)
        header = next(reader, None)
        if header != list(expected_header) or len(header or []) != len(set(header or [])):
            raise ValueError('Source header changed')
        indices = [header.index(name) for name in audit.FEATURES]
        label_index, type_index, ts_index = [header.index(name) for name in ('label', 'type', 'ts')]
        batch = []
        for row in reader:
            if len(row) != len(header):
                raise ValueError('Malformed source CSV record')
            if len(row[label_index]) > 256 or len(row[type_index]) > 256:
                raise ValueError('Oversized source metadata')
            batch.append(([row[index] for index in indices], row[label_index], row[type_index], row[ts_index]))
            rows_read += 1
            if len(batch) >= chunk_rows:
                consume(batch)
                batch = []
            elif rows_read % 4096 == 0:
                progress({'event': 'csv_read_progress', 'file': path.name, 'rows_read': rows_read}, force=False)
        if batch:
            consume(batch)
    return stages, daily


def merge_stages(target, source):
    for name, values in source.items():
        current = target[name]
        current['rows'] += values['rows']
        current['invalid_timestamp_rows'] += values['invalid_timestamp_rows']
        current['label_counts'].update(values['label_counts'])
        current['type_counts'].update(values['type_counts'])
        for key, operation in (('timestamp_min', min), ('timestamp_max', max)):
            if values[key] is not None:
                current[key] = values[key] if current[key] is None else operation(current[key], values[key])


def run(args):
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    started, started_clock = utc_now(), time.monotonic()
    state = {'stage': '023', 'status': 'running', 'measurement_origin': 'host_frozen_models',
             'data_origin': 'TON_IoT_same_collection_unseen_input_confirmation',
             'same_collection_as_development': True, 'independent_collection_established': False,
             'temporal_training_established': False, 'training_performed': False,
             'threshold_selection_performed': False, 'hardware_inference_measured': False,
             'physical_power_loss_tested': False, 'energy_measured': False,
             'predictions_computed': False, 'started_utc': started,
             'candidate_unique_input_count': None, 'candidate_duplicates_retained': True,
             'files_completed': 0, 'retained_rows_scored': 0}
    provenance = {'script_sha256': sha256_file(__file__), 'python': platform.python_version(),
                  'numpy': np.__version__, 'data_dir': str(Path(args.data_dir).resolve()),
                  'kit': str(Path(args.kit).resolve()), 'chunk_rows': args.chunk_rows}
    last_progress = [0.0]
    stream = (output / 'progress.jsonl').open('x', encoding='utf-8')

    def progress(record, force=True):
        now = time.monotonic()
        if not force and now - last_progress[0] < 5:
            return
        last_progress[0] = now
        entry = {'utc': utc_now(), **record}
        stream.write(json.dumps(entry, ensure_ascii=False) + '\n'); stream.flush()
        print(json.dumps(record, ensure_ascii=False), flush=True)

    accumulator = None
    try:
        if not 1 <= args.chunk_rows <= 250000:
            raise ValueError('chunk-rows must be between 1 and 250000')
        protocol, audit = load_protocol()
        manifest, receipt = audit.load_pinned_inputs(ROOT / 'inputs')
        audit_root = ROOT / 'inputs/audit022'
        expected = json.loads((audit_root / 'summary.json').read_text(encoding='utf-8'))
        audit_provenance = json.loads((audit_root / 'provenance.json').read_text(encoding='utf-8'))
        expected_daily = read_daily(audit_root / 'daily_counts.csv')
        expected_files = {item['file']: item for item in json.loads((audit_root / 'per_file.json').read_text(encoding='utf-8'))}
        validate_audit_inputs(expected, audit_provenance, receipt)
        known, known_metadata = audit.load_known(args.kit)
        checked = verify_sources(args.data_dir, manifest, receipt, audit, progress)
        models, predictors, bindings = load_frozen_models(args.kit)
        provenance.update({'protocol_sha256': EXPECTED_PROTOCOL_SHA256, 'known_inputs': known_metadata,
            'source_sha256': {item['file']: item['local_sha256'] for item in receipt['files']},
            'source_sizes': {name: values[0] for name, values in checked.items()},
            'hash_authority': 'user_acquisition_receipt_and_stage022_audit_not_publisher_hashes', **bindings})
        # This lock is completed BEFORE any new-corpus call to a predictor.
        dump(output / 'protocol_lock_before_predictions.json', {'locked_utc': utc_now(), 'protocol': protocol, 'bindings': provenance})
        dump(output / 'provenance.json', provenance)
        dump(output / 'summary.json', state)
        accumulator = new_accumulator(MODEL_IDS)
        stages, daily = audit.new_report()['stages'], Counter()
        entries = {item['name']: item for item in manifest['files']}
        for name in audit.EXPECTED_NAMES:
            path = Path(args.data_dir) / name
            if checked[name] != audit.stat_signature(path):
                raise ValueError('Source changed after integrity check: ' + name)
            progress({'event': 'evaluate_file_start', 'file': name})
            state['predictions_computed'] = True
            part, part_daily = evaluate_csv(path, entries[name]['csv_header'], known, args.chunk_rows,
                                           audit, models, predictors, accumulator, progress)
            if checked[name] != audit.stat_signature(path):
                raise ValueError('Source changed during evaluation: ' + name)
            # The previous audit exposes per-file stages and global daily cells.
            validate_metadata(part, part_daily, expected_files[name])
            merge_stages(stages, part); daily.update(part_daily)
            state['files_completed'] += 1
            state['retained_rows_scored'] = int(accumulator['counts'][0, :4].sum())
            progress({'event': 'evaluate_file_complete', 'file': name, 'files_completed': state['files_completed'],
                      'source_rows_processed': stages['all_source']['rows'], 'retained_rows_scored': state['retained_rows_scored']})
        validate_metadata(stages, daily, expected, expected_daily)
        if state['retained_rows_scored'] != stages['candidate_unseen_input']['rows']:
            raise ValueError('Scored row count differs from the confirmed cohort')
        results = finalize_results(accumulator, models, expected['stages']['all_source']['type_counts'])
        for name, value in results.items():
            dump(output / (name + '.json'), value)
        state.update({'status': 'complete', 'finished_utc': utc_now(),
                      'elapsed_seconds': time.monotonic() - started_clock,
                      'scope': 'all_23_audited_files_all_candidate_rows', 'aggregate_metadata_matches_stage022': True,
                      'rows_by_stage': stages, 'model_ids': list(MODEL_IDS),
                      'observed_utc_days': sorted(accumulator['by_day']),
                      'descriptive_sensitivity_only': True, 'confidence_intervals_computed': False,
                      'limitations': [
                          'This confirmation reuses the TON collection; no independent session/device or future test is established.',
                          'Exact raw-vector exclusion is conservative and does not identify original-flow identity.',
                          'Retained repeated vectors contribute their row frequency; global unique candidate count is not computed.',
                          'Leave-one-day-out ranges are sensitivity summaries, not confidence intervals.',
                          'Coverage after exclusion differs by attack type; zero-coverage types have undefined metrics.',
                          'Exported float32 model semantics are evaluated on the host; MCU agreement was tested separately.',
                          'No model or threshold may be selected using this confirmation and still described as frozen for it.']})
        dump(output / 'summary.json', state)
        progress({'event': 'finished', 'status': 'complete', 'retained_rows_scored': state['retained_rows_scored'], 'output': str(output.resolve())})
        return 0
    except (Exception, KeyboardInterrupt) as error:
        if accumulator is not None:
            state['retained_rows_scored'] = int(accumulator['counts'][0, :4].sum())
        state.update({'status': 'failed', 'error': str(error) or type(error).__name__,
                      'error_type': type(error).__name__, 'finished_utc': utc_now(),
                      'partial_results_usable_as_full_confirmation': False})
        dump(output / 'summary.json', state); dump(output / 'provenance.json', provenance)
        progress({'event': 'failed', 'error': state['error'], 'output': str(output.resolve())})
        return 2
    finally:
        stream.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', type=Path, required=True)
    parser.add_argument('--kit', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--chunk-rows', type=int, default=50000)
    args = parser.parse_args(argv)
    if args.output.exists():
        print('ERROR: Output exists. Choose a fresh output directory; nothing was overwritten.', file=sys.stderr)
        return 2
    try:
        return run(args)
    except OSError as error:
        print('ERROR: Cannot create fresh output: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
