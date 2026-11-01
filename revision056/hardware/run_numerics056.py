#!/usr/bin/env python3
"""Reviewer checks: expanded input panel, frozen export evaluation, and MCU parity.

Original software author: Oleksandr Kuznetsov.
The numerical reference and signed-container codec are reused from frozen030.
No fitting, threshold selection, or implicit MCU mutation occurs in prepare/future.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import platform
import shutil
import sqlite3
import sys
import time
from types import SimpleNamespace
import numpy as np

SEED = 23102026
FAMILIES = ('lr', 'dt', 'mlp_float', 'mlp_int8')
FEATURES = ['duration', 'src_bytes', 'dst_bytes', 'missed_bytes', 'src_pkts', 'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes']
PERCENTILES = ('percentile999_transferred', 'percentile999_recalibrated')
TARGET = np.array([0, 0, 0, 0, 1, 63, 0, 0], dtype='<f4')
TOLERANCE = 2e-6


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + '\n', encoding='utf-8')


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for data in iter(lambda: handle.read(1 << 20), b''):
            h.update(data)
    return h.hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def modules(root):
    root = Path(root).resolve()
    sys.path.insert(0, str(root / 'research030/training'))
    ref = module('model030', root / 'research030/training/model030.py')
    train = module('revision039_training030', root / 'research030/training/run_training030.py')
    codec = module('revision039_codec030', root / 'research030/hardware_codec/codec030.py')
    qref = module('revision039_percentile035', root / 'paper037/new_diagnostics/quantization/analyze_percentile035.py')
    return ref, train, codec, qref


def training_path(prior):
    prior = Path(prior).resolve()
    if (prior / 'training/models').is_dir():
        return prior / 'training'
    if (prior / 'models').is_dir():
        return prior
    raise ValueError('Expected prior run with training/models, or the training directory itself: ' + str(prior))


def frozen_models(root, prior):
    root = Path(root).resolve()
    try:
        training = training_path(prior)
    except ValueError:
        prior = Path(prior).resolve()
        training = prior if prior.name == 'training' else prior / 'training'
    public_training = root / 'paper037/evidence_inputs/training'
    software_pins = {p['path']: p['sha256'] for p in load(root / 'MANIFEST.sha256.json')['files']}
    manifest_path = training / 'result_manifest.json'
    pins = load(manifest_path)['sha256'] if manifest_path.is_file() else {}
    source_training = training if (training / 'models').is_dir() else public_training
    paths = sorted((source_training / 'models').glob('*.json'))
    if len(paths) != 24:
        raise ValueError('Expected exactly the 24 frozen030 model/condition JSON files')
    result, origins = {}, {}
    for path in paths:
        relative = path.relative_to(source_training).as_posix()
        public_path = public_training / 'models' / path.name
        public_relative = public_path.relative_to(root).as_posix()
        expected = pins.get(relative) if source_training == training and pins else software_pins.get(public_relative)
        if expected != sha(path):
            raise ValueError('Frozen model hash mismatch: ' + relative)
        m = load(path)
        if m['kind'] not in FAMILIES:
            raise ValueError('Unsupported frozen model kind')
        result[path.stem] = m
        origins[path.stem] = {'path': str(path), 'sha256': sha(path)}
    for name in PERCENTILES:
        path = Path(root) / 'paper037/new_diagnostics/quantization' / (name + '.json')
        pin = load(path.parent / 'MANIFEST035.json')['sha256'].get(path.name)
        if pin != sha(path):
            raise ValueError('Frozen percentile artifact hash mismatch: ' + name)
        result[name] = load(path)
        origins[name] = {'path': str(path), 'sha256': sha(path), 'frozen_posthoc_artifact': True}
    return result, origins, training


def canonical(raw):
    x = np.asarray(raw, dtype='<f4').copy()
    if x.ndim != 1 or x.shape != (8,) or not np.isfinite(x).all() or (x < 0).any():
        raise ValueError('Input must contain eight nonnegative finite float32 values')
    x[x == 0] = 0
    return x


def unique_records(records, excluded=()):
    seen = set(excluded)
    for raw, metadata in records:
        x = canonical(raw)
        key = x.tobytes()
        if key not in seen:
            seen.add(key)
            yield x, metadata


def collect_real(training, samples_root=None, fingerprints=None):
    """Balanced finite pool from saved samples; never masquerade as fresh data."""
    base = Path(samples_root).resolve() if samples_root else training
    if (base / 'training/samples').is_dir():
        base = base / 'training'
    if base.name == 'samples':
        base = base.parent
    records, sources = [], {}
    rng = np.random.default_rng(SEED)
    for role in ('A_fit', 'A_cal', 'B_fit_added', 'B_cal'):
        path = base / 'samples' / (role + '.npz')
        if not path.is_file():
            continue
        with np.load(path, allow_pickle=False) as data:
            if fingerprints is not None:
                expected = fingerprints['samples'][path.name]['arrays']
                if set(data.files) != set(expected):
                    raise ValueError('Saved sample array names differ: ' + str(path))
                for field, pin in expected.items():
                    array = np.ascontiguousarray(data[field])
                    if list(array.shape) != pin['shape'] or array.dtype.str != pin['dtype'] or hashlib.sha256(array.tobytes()).hexdigest() != pin['sha256_c_order']:
                        raise ValueError('Saved sample differs from published content fingerprint: ' + str(path) + ':' + field)
            raw = np.asarray(data['raw'], np.float32)
            labels = np.asarray(data['labels'])
            row_ids = data['row_ids'] if 'row_ids' in data else None
            if raw.ndim != 2 or raw.shape[1] != 8 or len(labels) != len(raw):
                raise ValueError('Malformed saved sample: ' + str(path))
            for label in (0, 1):
                candidates = np.flatnonzero(labels == label)
                selected = np.sort(rng.choice(candidates, min(2048, len(candidates)), replace=False))
                for i in selected:
                    meta = {'data_origin': 'TON_IoT_saved_sample', 'role': role,
                            'label': int(label), 'sample_index': int(i),
                            'source_row_id': int(row_ids[i]) if row_ids is not None else None}
                    records.append((raw[i], meta))
        sources[str(path)] = sha(path)
    if len(records) < 512:
        raise ValueError('Need saved/reconstructed samples (A_fit/A_cal/B_fit_added/B_cal). '
                         'Use --samples-root for reconstructed input arrays; no synthetic replacement is allowed.')
    # Round-robin strata prevents the first role/class from filling the panel.
    strata = defaultdict(list)
    for record in records:
        strata[(record[1]['role'], record[1]['label'])].append(record)
    ordered = []
    for i in range(max(map(len, strata.values()))):
        for key in sorted(strata):
            if i < len(strata[key]):
                ordered.append(strata[key][i])
    return list(unique_records(ordered)), sources


def boundary_records(models, pool, ref):
    raw = np.stack([x for x, _ in pool])
    records = []
    for family in FAMILIES:
        name = 'B_' + family
        m = models[name]
        _, label, score = ref.predict(m, raw, True)
        threshold = m['q_threshold'] if family == 'mlp_int8' else np.float32(m['threshold'])
        order = np.argsort(np.abs(score.astype(np.float64) - threshold), kind='stable')
        for i in order[:16]:
            records.append((raw[i], {**pool[i][1], 'selection': 'near_score_threshold', 'target_model': name}))
        zeros, ones = np.flatnonzero(label == 0), np.flatnonzero(label == 1)
        # A bracket is empirical: both actual endpoint decisions are checked.
        for i in range(min(8, len(zeros), len(ones))):
            lo = raw[zeros[i]].copy()
            hi = raw[ones[i]].copy()
            for _ in range(48):
                mid = ((lo.astype(np.float64) + hi.astype(np.float64)) * .5).astype(np.float32)
                if np.array_equal(mid, lo) or np.array_equal(mid, hi):
                    break
                mid_label = int(ref.predict(m, mid[None, :])[1][0])
                if mid_label:
                    hi = mid
                else:
                    lo = mid
            for side, point in [('normal_side', lo), ('attack_side', hi)]:
                records.append((point, {'data_origin': 'synthetic_boundary_probe', 'target_model': name,
                                        'selection': 'decision_bracket_bisection', 'side': side}))
            for feature in range(8):
                point = lo.copy()
                point[feature] = np.nextafter(point[feature], hi[feature], dtype=np.float32)
                records.append((point, {'data_origin': 'synthetic_boundary_probe', 'target_model': name,
                                        'selection': 'adjacent_float32', 'feature': feature}))
    return records


def make_panel(models, real_pool, ref, old_raw=None):
    excluded = {canonical(x).tobytes() for x in old_raw} if old_raw is not None else set()
    selected, seen = [], set(excluded)
    counts = Counter()

    def take(category, records, maximum):
        added = 0
        for x, meta in unique_records(records, seen):
            if added >= maximum:
                break
            seen.add(x.tobytes())
            selected.append({'raw': x.tolist(), 'category': category, **meta})
            added += 1
        counts[category] += added
        return added

    take('real_stratified', real_pool, 512)
    pool_raw = np.stack([x for x, _ in real_pool])
    maxima = np.maximum(pool_raw.max(0), 1.)
    rng = np.random.default_rng(SEED + 1)
    random_raw = np.expm1(rng.uniform(size=(1024, 8)) * np.log1p(maxima.astype(np.float64))).astype(np.float32)
    take('synthetic_random', ((x, {'data_origin': 'synthetic_range_probe', 'selection': 'uniform_log1p_pool_range'}) for x in random_raw), 256)
    ranges = [(TARGET, {'data_origin': 'synthetic_explicit_probe', 'selection': 'recurring_63byte_template'})]
    ranges.append((np.zeros(8, np.float32), {'data_origin': 'synthetic_range_probe', 'selection': 'zero'}))
    for level in ('float32_max', 'smallest_positive', 'observed_pool_max', 'one', 'twice_pool_max', 40., 63., 127., 128., 255., 256., 1e10):
        for feature in range(8):
            v = {'float32_max': float(np.finfo(np.float32).max), 'smallest_positive': float(np.nextafter(np.float32(0), np.float32(1))),
                 'observed_pool_max': float(maxima[feature]), 'one': 1., 'twice_pool_max': float(maxima[feature]) * 2.}.get(level, level)
            x = np.zeros(8, np.float32)
            x[feature] = v
            ranges.append((x, {'data_origin': 'synthetic_range_probe', 'selection': 'one_coordinate', 'feature': feature, 'level': level}))
    tree_ranges, quant_ranges = [], []
    for name, m in models.items():
        if m['kind'] == 'dt':
            for node in m['nodes']:
                if node['feature'] >= 0:
                    feature = int(node['feature'])
                    for direction in (-np.inf, np.inf):
                        x = pool_raw[0].copy()
                        x[feature] = max(0., np.nextafter(np.float32(node['threshold']), np.float32(direction)))
                        tree_ranges.append((x, {'data_origin': 'synthetic_range_probe', 'selection': 'tree_split_neighbor', 'target_model': name, 'feature': feature}))
        elif m['kind'] == 'mlp_int8':
            for feature in range(8):
                for code in (-126.5, -.5, .5, 126.5, 127.5):
                    z = code * float(m['input_scale']) * float(m['scale'][feature]) + float(m['mean'][feature])
                    if 0 <= z < 88:
                        x = pool_raw[0].copy()
                        x[feature] = np.float32(np.expm1(z))
                        quant_ranges.append((x, {'data_origin': 'synthetic_range_probe', 'selection': 'input_quantization_boundary', 'target_model': name, 'feature': feature, 'target_code': code}))
    # Guarantee each range category gets consideration before the budget fills.
    range_interleaved = []
    for i in range(max(map(len, (ranges, tree_ranges, quant_ranges)))):
        for group in (ranges, tree_ranges, quant_ranges):
            if i < len(group):
                range_interleaved.append(group[i])
    take('range_and_grid', range_interleaved, 128)
    boundaries = boundary_records(models, real_pool, ref)
    # Interleave target models so one model cannot consume the boundary budget.
    groups = defaultdict(list)
    for x, meta in boundaries:
        groups[meta['target_model']].append((x, meta))
    interleaved = []
    for i in range(max((len(v) for v in groups.values()), default=0)):
        for key in sorted(groups):
            if i < len(groups[key]):
                interleaved.append(groups[key][i])
    take('decision_boundary', interleaved, 128)
    if len(selected) < 1024:
        take('synthetic_fill_for_duplicate_shortfall', ((x, {'data_origin': 'synthetic_range_probe', 'selection': 'fixed_seed_duplicate_fill'}) for x in random_raw), 1024 - len(selected))
    if len(selected) != 1024:
        raise ValueError('Could not construct 1024 distinct additional inputs')
    raw = np.asarray([r['raw'] for r in selected], np.float32)
    coverage = {'additional_unique_vectors': len(raw), 'old_vectors_excluded': len(excluded),
                'category_counts': dict(counts), 'feature_min': raw.min(0).tolist(),
                'feature_max': raw.max(0).tolist(), 'feature_nonzero_counts': (raw != 0).sum(0).tolist(),
                'feature_distinct_counts': [int(len(np.unique(raw[:, j]))) for j in range(8)],
                'real_source_pool_unique_vectors': len(real_pool),
                'selection_subtype_counts': dict(Counter(r.get('selection', 'saved_sample') for r in selected)),
                'boundary_cases_are_targeted_not_random_detection_test': True,
                'recurring_template_in_additional_panel': bool(np.any(np.all(raw == TARGET, axis=1))),
                'universal_equivalence_proved': False}
    return selected, coverage


def pin_directory(directory):
    save(Path(directory) / 'manifest.json', {'sha256': {
        p.relative_to(directory).as_posix(): sha(p) for p in sorted(Path(directory).rglob('*'))
        if p.is_file() and p.name != 'manifest.json' and '__pycache__' not in p.parts}})


def verify_directory(directory):
    directory = Path(directory).resolve()
    for relative, digest in load(directory / 'manifest.json')['sha256'].items():
        path = (directory / relative).resolve()
        if not path.is_relative_to(directory) or not path.is_file() or sha(path) != digest:
            raise ValueError('Prepared artifact hash mismatch: ' + relative)


def prepare(args):
    root, out = Path(args.root).resolve(), Path(args.output).resolve()
    models, origins, training = frozen_models(root, args.prior_run)
    ref, train, codec, _ = modules(root)
    out.mkdir(parents=True, exist_ok=False)
    fingerprints = load(root / 'publication_tools/DATA_INPUT_FINGERPRINTS037.json')
    samples_root = args.samples_root
    possible = Path(samples_root).resolve() if samples_root else training
    available = any((possible / 'samples' / (role + '.npz')).is_file() for role in ('A_fit', 'A_cal', 'B_fit_added', 'B_cal'))
    if not available and args.data_root:
        reconstructed = out / 'reconstructed_inputs'
        reconstructed.mkdir()
        (reconstructed / 'samples').mkdir()
        save(out / 'RECONSTRUCTION_STARTED.json', {'operation': 'frozen030_input_reconstruction_without_fitting',
             'hardware_access_attempted': False, 'source_manifest_sha256': sha(root / 'research030/training/vendor/source_manifest.json')})
        sources = train.find_sources(root, args.data_root, False)
        protocol = load(root / 'research030/protocol/coverage_selection.json')
        arrays, support = train.prepare_data(sources, protocol, reconstructed, False)
        del arrays
        samples_root = reconstructed
        save(out / 'RECONSTRUCTION_COMPLETE.json', {'samples_root': str(reconstructed),
             'future_db': str(reconstructed / 'test_vectors.sqlite'), 'source_files': [{k: s[k] for k in ('file', 'sha256', 'bytes')} for s in sources],
             'protocol_sha256': sha(root / 'research030/protocol/coverage_selection.json'), 'models_retrained': False})
    real, sample_sources = collect_real(training, samples_root, fingerprints)
    old_path = training / 'hardware_vectors/B_mlp_int8.json'
    old_raw = load(old_path)['raw'] if old_path.is_file() else None
    if old_raw is None and samples_root:
        cached = Path(samples_root) / 'test_vectors.sqlite'
        if cached.is_file():
            with sqlite3.connect(cached.resolve().as_uri() + '?mode=ro', uri=True) as db:
                old_raw = [np.frombuffer(row[0], '<f4').tolist() for row in db.execute('SELECT key FROM vectors ORDER BY key LIMIT 258')]
    rows, coverage = make_panel(models, real, ref, old_raw)
    save(out / 'PROTOCOL_LOCK.json', {'stage': '039', 'operation': 'expanded_numerical_panel', 'seed': SEED,
        'input_selection': '512 round-robin sample role/class; 256 log-range random; 128 range/grid; 128 boundary; deterministic duplicate fill',
        'model_origins': origins, 'sample_origins': sample_sources, 'features': FEATURES,
        'probability_tolerance': TOLERANCE, 'label_tolerance': 0, 'calibration_or_model_tuning': False,
        'prior_test_exposure': 'post-review extension of previously explored study',
        'python': sys.version, 'numpy': np.__version__, 'host_platform': platform.platform(),
        'code_sha256': {str(p.relative_to(root)): sha(p) for p in [Path(__file__), root / 'research030/training/model030.py', root / 'research030/hardware_codec/codec030.py']}})
    raw = np.asarray([r['raw'] for r in rows], np.float32)
    save(out / 'panel.json', {'features': FEATURES, 'vectors': rows, 'coverage': coverage})
    comparisons = {}
    for name, m in models.items():
        save(out / 'models' / (name + '.json'), m)
        p, labels, score = ref.predict(m, raw, True)
        save(out / 'golden' / (name + '.json'), {'model': name, 'model_sha256': sha(out / 'models' / (name + '.json')),
            'probabilities': p.tolist(), 'labels': labels.tolist(), 'scores': score.tolist(),
            'measurement_origin': 'host_reference', 'hardware_access_attempted': False})
        codec.sign_envelope(m, 2, '039-validate')  # Validate ABI/size before board access.
        if 'compatible' in name or name in PERCENTILES:
            base = 'B_' + m['kind']
            bp, by = ref.predict(models[base], raw)
            comparisons[name] = {'reference': base, 'different_decisions': int((labels != by).sum()),
                                 'max_probability_abs_difference': float(np.max(np.abs(p.astype(np.float64) - bp))),
                                 'not_detection_quality': True}
    save(out / 'host_comparisons.json', comparisons)
    summary = {'status': 'prepared', 'stage': '039', 'command': 'prepare', 'measurement_origin': 'host_reference',
               'hardware_access_attempted': False, 'models': len(models), **coverage}
    save(out / 'summary.json', summary)
    pin_directory(out)
    return summary


def create_future_db(args, out, train):
    try:
        training = training_path(args.prior_run)
    except ValueError:
        prior = Path(args.prior_run).resolve()
        training = prior if prior.name == 'training' else prior / 'training'
    existing = Path(args.future_db).resolve() if args.future_db else training / 'test_vectors.sqlite'
    if existing.is_file():
        if not args.future_db:
            expected = load(training / 'result_manifest.json')['sha256'].get('test_vectors.sqlite') if (training / 'result_manifest.json').is_file() else None
            if expected is None or sha(existing) != expected:
                raise ValueError('Original future SQLite hash mismatch; use explicit --future-db for a reconstructed cache')
        return existing, {'cache': str(existing), 'sha256': sha(existing), 'mode': 'explicit_reconstructed_cache' if args.future_db else 'original_hash_verified_cache'}
    if not args.data_root:
        raise ValueError('Missing future SQLite and --data-root. Need all 23 original pinned TON CSVs.')
    sources = train.find_sources(Path(args.root), args.data_root, False)
    protocol = load(Path(args.root) / 'research030/protocol/coverage_selection.json')
    bounds = train.effective_intervals(protocol)
    path = out / 'future_vectors.sqlite'
    with sqlite3.connect(path) as db:
        db.executescript('CREATE TABLE vectors(key BLOB PRIMARY KEY,n0 INTEGER,n1 INTEGER) WITHOUT ROWID; '
                        'CREATE TABLE groups(key BLOB,day TEXT,kind TEXT,label INTEGER,n INTEGER,PRIMARY KEY(key,day,kind,label)) WITHOUT ROWID;')
        from datetime import datetime, timezone
        for source in sources:
            print('future cache:', source['file'], flush=True)
            for tokens, ts, labels, kinds, ids, duration in train.batches(source):
                raw, valid, _, _ = train.valid_numeric(tokens)
                valid &= np.isfinite(ts) & np.isfinite(duration) & (duration >= 0)
                raw, ts, labels, kinds, duration = (x[valid] for x in (raw, ts, labels, kinds, duration))
                mask = train.masks_for_intervals(ts, duration, bounds)['common_test']
                vectors, groups = {}, Counter()
                for x, t, y, kind in zip(raw[mask], ts[mask], labels[mask], kinds[mask]):
                    key = np.asarray(x, dtype='<f4').tobytes()
                    vectors.setdefault(key, [0, 0])[int(y)] += 1
                    day = datetime.fromtimestamp(float(t), timezone.utc).date().isoformat()
                    groups[(key, day, str(kind), int(y))] += 1
                db.executemany('INSERT INTO vectors VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET n0=n0+excluded.n0,n1=n1+excluded.n1', [(k, *v) for k, v in vectors.items()])
                db.executemany('INSERT INTO groups VALUES(?,?,?,?,?) ON CONFLICT(key,day,kind,label) DO UPDATE SET n=n+excluded.n', [(*k, n) for k, n in groups.items()])
            db.commit()
            stat = Path(source['path']).stat()
            if (stat.st_size, stat.st_mtime_ns) != (source['bytes'], source['mtime_ns']):
                raise ValueError('Source changed during future reconstruction: ' + source['file'])
    return path, {'mode': 'reconstructed_future_only', 'protocol_sha256': sha(Path(args.root) / 'research030/protocol/coverage_selection.json'),
                  'sources': [{k: s[k] for k in ('file', 'sha256', 'bytes')} for s in sources], 'sha256': sha(path)}


def metrics(mass):
    tn, fp, fn, tp = map(float, mass[:4])
    normal, attack = tn + fp, fn + tp
    fpr, recall = (fp / normal if normal else None), (tp / attack if attack else None)
    return {'normal_mass': normal, 'attack_mass': attack, 'FP_mass': fp, 'TP_mass': tp,
            'FPR': fpr, 'recall': recall, 'balanced_accuracy': (recall + 1 - fpr) / 2 if normal and attack else None}


def evaluate_cache(db_path, models, ref, qref, chunk=2048):
    names = list(models)
    refs = ('B_mlp_int8', 'B_mlp_float')
    totals = {w: np.zeros((len(names), 6), np.float64) for w in ('rows', 'vector_balanced', 'frequency_cap100')}
    days, kinds, clipping = {}, {}, {}
    count = rows_count = 0
    db = sqlite3.connect(Path(db_path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        cursor = db.execute('SELECT key,n0,n1 FROM vectors ORDER BY key')
        while True:
            batch = cursor.fetchmany(chunk)
            if not batch:
                break
            raw = np.asarray([np.frombuffer(r[0], '<f4') for r in batch], np.float32)
            n0 = np.asarray([r[1] for r in batch], np.float64)
            n1 = np.asarray([r[2] for r in batch], np.float64)
            n = n0 + n1
            if np.any(n <= 0) or np.any(n0 < 0) or np.any(n1 < 0):
                raise ValueError('Invalid future vector counts')
            predictions = {}
            for name, m in models.items():
                if m['kind'].startswith('mlp_int8'):
                    score, traces = qref.trace(m, raw)
                    predictions[name] = (score >= int(m['q_threshold'])).astype(np.uint8)
                    accum = clipping.setdefault(name, {})
                    for t in traces:
                        a = accum.setdefault(t['tensor'], {'elements_on_unique_vectors': 0, 'clipped_elements_on_unique_vectors': 0, 'unique_vectors_with_clipping': 0})
                        a['elements_on_unique_vectors'] += t['elements']
                        a['clipped_elements_on_unique_vectors'] += t['clipped_elements']
                        a['unique_vectors_with_clipping'] += t['rows_with_clipping']
                else:
                    predictions[name] = ref.predict(m, raw)[1]
            pred = np.column_stack([predictions[k] for k in names])
            changed_i8 = pred != predictions[refs[0]][:, None]
            changed_f32 = pred != predictions[refs[1]][:, None]
            atom = np.stack((n0[:, None] * (pred == 0), n0[:, None] * pred,
                             n1[:, None] * (pred == 0), n1[:, None] * pred,
                             n[:, None] * changed_i8, n[:, None] * changed_f32), axis=2)
            for weighting, weight in [('rows', np.ones(len(n))), ('vector_balanced', 1 / n), ('frequency_cap100', np.minimum(n, 100) / n)]:
                totals[weighting] += (atom * weight[:, None, None]).sum(0)
            lookup = {r[0]: i for i, r in enumerate(batch)}
            for first in range(0, len(batch), 500):
                keys = [r[0] for r in batch[first:first + 500]]
                placeholders = ','.join('?' for _ in keys)
                for key, day, kind, label, number in db.execute('SELECT key,day,kind,label,n FROM groups WHERE key IN (' + placeholders + ')', keys):
                    i = lookup[key]
                    a = np.zeros((len(names), 6), np.float64)
                    a[:, int(label) * 2] = number * (pred[i] == 0)
                    a[:, int(label) * 2 + 1] = number * pred[i]
                    a[:, 4] = number * changed_i8[i]
                    a[:, 5] = number * changed_f32[i]
                    days.setdefault(day, np.zeros_like(a))[:] += a
                    kinds.setdefault(kind, np.zeros_like(a))[:] += a
            count += len(batch)
            rows_count += int(n.sum())
            if count % 32768 == 0:
                print('future unique vectors:', count, flush=True)
        def report(values):
            result = {}
            for i, name in enumerate(names):
                m = metrics(values[i])
                total = m['normal_mass'] + m['attack_mass']
                result[name] = {**m, 'disagreement_vs_B_I8': float(values[i, 4] / total) if total else None,
                                'disagreement_vs_B_F32': float(values[i, 5] / total) if total else None}
            return result
        if days:
            if not np.allclose(np.stack(list(days.values())).sum(0), totals['rows'], rtol=0, atol=1e-6):
                raise ValueError('Future group/day counts do not match vector populations')
        elif rows_count:
            raise ValueError('Nonempty future vectors have no group/day metadata')
        return {'rows': rows_count, 'unique_vectors': count, 'weightings': {k: report(v) for k, v in totals.items()},
                'by_day_rows': {k: report(v) for k, v in days.items()}, 'by_type_rows': {k: report(v) for k, v in kinds.items()},
                'clipping_on_unique_vectors': clipping,
                'frequency_definition': 'Vector gets total weight 1 or min(frequency,100); conflicting labels retain proportional shares',
                'thresholds_reselected': False, 'confidence_intervals': None,
                'scope': 'Post-review evaluation of already fixed export artifacts; future period previously explored; not an untouched test'}
    finally:
        db.close()


def future(args):
    root, out = Path(args.root).resolve(), Path(args.output).resolve()
    models, origins, _ = frozen_models(root, args.prior_run)
    names = ['B_mlp_int8', 'B_mlp_float', 'mlp_int8_compatible_requantized', *PERCENTILES]
    selected = {k: models[k] for k in names}
    for name in ('export_per_channel_transferred', 'export_per_channel_recalibrated'):
        path = root / 'paper037/new_analysis' / (name + '.json')
        if load(path.parent / 'MANIFEST034.json')[path.name] != sha(path):
            raise ValueError('Frozen per-channel artifact hash mismatch: ' + name)
        selected[name] = load(path)
        origins[name] = {'path': str(path), 'sha256': sha(path)}
    ref, train, _, qref = modules(root)
    out.mkdir(parents=True, exist_ok=False)
    save(out / 'PROTOCOL_LOCK.json', {'stage': '039', 'command': 'future', 'models': {k: origins[k] for k in selected},
         'thresholds': {k: {'threshold': m['threshold'], 'q_threshold': m.get('q_threshold')} for k, m in selected.items()},
         'percentile': 99.9, 'tuning_on_future': False, 'expected_future_rows': 7462871, 'expected_future_unique_vectors': 3782505})
    try:
        path, provenance = create_future_db(args, out, train)
        save(out / 'input_provenance.json', provenance)
        result = evaluate_cache(path, selected, ref, qref)
        if result['rows'] != 7462871 or result['unique_vectors'] != 3782505:
            raise ValueError('Future population differs from frozen030; do not report this as the full original future test')
        save(out / 'evaluation.json', result)
        summary = {'status': 'complete', 'stage': '039', 'command': 'future', 'measurement_origin': 'host_offline',
                   'hardware_access_attempted': False, 'models_evaluated': len(selected), 'rows': result['rows'],
                   'unique_vectors': result['unique_vectors'], 'thresholds_reselected': False}
    except BaseException as exc:
        save(out / 'summary.json', {'status': 'failed', 'error': str(exc), 'hardware_access_attempted': False})
        raise
    save(out / 'summary.json', summary)
    pin_directory(out)
    return summary


def verify_template(root, base, family, codec):
    """Validate template identity and every source flash file before patching."""
    root, base = Path(root).resolve(), Path(base).resolve()
    metadata = load(base / 'metadata.json')
    required = ('ids_update_lab.bin', 'bootloader/bootloader.bin',
                'partition_table/partition-table.bin', 'ota_data_initial.bin', 'flash_args')
    if metadata.get('family') != family or metadata.get('policy') != 'bundle' or metadata.get('runtime_abi') != codec.ABI[family] or metadata.get('schema') != codec.SCHEMA.hex():
        raise ValueError('Template family/policy/ABI/schema metadata mismatch: ' + str(base))
    if metadata.get('revision') == '056' and metadata.get('chip') == 'esp32c3':
        if metadata.get('status') != 'compiled_not_hardware_validated' or metadata.get('optimization') != 'O2':
            raise ValueError('Revision056 template is not a verified compiled configuration')
        pins = {k.replace('\\', '/'): v for k, v in metadata.get('files_sha256', {}).items()}
        if any(name not in pins for name in required):
            raise ValueError('Revision056 template metadata does not pin all flashing inputs')
        for relative, digest in pins.items():
            path = (base / relative).resolve()
            if not path.is_relative_to(base) or not path.is_file() or sha(path) != digest:
                raise ValueError('Revision056 template file hash mismatch: ' + relative)
    else:
        raise ValueError('C3 experiment requires a revision056 esp32c3 template')
    image_info = codec.verify_image((base / 'ids_update_lab.bin').read_bytes())
    for key in ('image_sha256', 'image_size', 'elf_sha256', 'expected_build'):
        if image_info[key] != metadata.get(key):
            raise ValueError('Template image metadata mismatch: ' + key)
    return metadata


def build_mcu_artifacts(root, prepared, output, prebuilt_root, codec):
    """Preparation only; build one family-specific factory and monotonic packages."""
    panel = load(prepared / 'panel.json')
    families = {}
    for family in FAMILIES:
        names = [p.stem for p in sorted((prepared / 'models').glob('*.json')) if load(p)['kind'] == family]
        names = ['A_' + family] + [n for n in names if n != 'A_' + family]
        target = output / family
        target.mkdir(parents=True)
        versions = {}
        for version, name in enumerate(names, 1):
            model = load(prepared / 'models' / (name + '.json'))
            blob = codec.sign_envelope(model, version, '039-' + str(version))
            path = target / ('v%03d.sids' % version)
            path.write_bytes(blob)
            versions[str(version)] = {'model': name, 'path': path.relative_to(output).as_posix(),
                                      'identity': codec.envelope_metadata(blob)}
        base = prebuilt_root / (family + '_bundle')
        template_metadata = verify_template(root, base, family, codec)
        factory = target / 'factory'
        factory.mkdir()
        for name in ('bootloader/bootloader.bin', 'partition_table/partition-table.bin', 'ota_data_initial.bin', 'flash_args'):
            (factory / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(base / name, factory / name)
        image = codec.patch_image((base / 'ids_update_lab.bin').read_bytes(), (output / versions['1']['path']).read_bytes())
        (factory / 'ids_update_lab.bin').write_bytes(image)
        families[family] = {'versions': versions, 'image': codec.image_metadata(image),
                            'factory_dir': factory.relative_to(output).as_posix(),
                            'template_sha256': sha(base / 'ids_update_lab.bin'),
                            'template_metadata_sha256': sha(base / 'metadata.json'),
                            'template_revision': template_metadata.get('revision', '030'),
                            'optimization': template_metadata.get('optimization', 'Og'),
                            'phase_gpio': template_metadata.get('phase_gpio')}
    manifest = {'families': families, 'prepared_panel_sha256': sha(prepared / 'panel.json'),
                'prepared_manifest_sha256': sha(prepared / 'manifest.json'), 'vectors': len(panel['vectors'])}
    save(output / 'artifacts.json', manifest)
    pin_directory(output)
    return manifest


def validate_identity(reply, entry, family, build, event='status'):
    expected = {'event': event, 'version': entry['identity']['version'], 'policy': 'bundle',
                'bundle_sha256': entry['identity']['bundle_sha256']}
    if event == 'status':
        expected.update(ready=True, reason='ok', build=build, chip='esp32c3', feature_count=8,
                        runtime_abi=entry['identity']['runtime_abi'], schema=entry['identity']['schema'])
    for k, v in expected.items():
        if reply.get(k) != v or type(reply.get(k)) is not type(v):
            raise RuntimeError('Identity mismatch: %s=%r, expected %r' % (k, reply.get(k), v))


def mcu(args):
    if not args.provision:
        raise ValueError('MCU panel requires explicit --provision: installs family-specific laboratory firmware and clears only laboratory model state')
    root, prepared, out = Path(args.root).resolve(), Path(args.prepared).resolve(), Path(args.output).resolve()
    verify_directory(prepared)
    _, _, codec, _ = modules(root)
    hardware = module('revision039_hardware030', root / 'revision056/hardware/hardware056.py')
    api = module('revision039_evidence030', root / 'research030/tools/vendor/evidence_link.py')
    transport = module('revision039_serial030', root / 'research030/tools/vendor/serial_transport.py')
    hardware.board_mac(args.board_id)
    prebuilt = Path(args.prebuilt_root).resolve() if args.prebuilt_root else root / 'revision056/build/prebuilt/O2'
    out.mkdir(parents=True, exist_ok=False)
    summary = {'status': 'running', 'stage': '056', 'command': 'mcu', 'board_id': args.board_id,
               'hardware_access_attempted': False, 'measurement_origin': 'not_measured', 'models_completed': 0,
               'inferred_records': 0, 'label_mismatches': 0, 'probability_tolerance_exceeded': 0,
               'max_probability_abs_error': 0., 'physical_power_loss_tested': False, 'energy_measured': False,
               'integer_code_telemetry_available': False, 'integer_codes_compared': 0, 'integer_code_mismatches': 0,
               'numerical_disagreements_do_not_trigger_retuning': True, 'model_results': []}
    save(out / 'summary.json', summary)
    try:
        manifest = build_mcu_artifacts(root, prepared, out / 'artifacts', prebuilt, codec)
        panel_rows = load(prepared / 'panel.json')['vectors']
        raw = [r['raw'] for r in panel_rows]
        for family in FAMILIES:
            f = manifest['families'][family]
            session = out / family
            session.mkdir()
            # Reuse the reviewed provisioner, including ROM MAC check before any write.
            provisioning = {'root': out / 'artifacts', 'families': {family: {'policies': {'bundle': {'factory_dir': f['factory_dir']}}}}}
            summary['hardware_access_attempted'] = True
            save(out / 'summary.json', summary)
            hardware.provision(args, session, provisioning, family, 'bundle')
            evidence = api.Evidence(session)
            link = api.Link(transport, evidence, args.timeout)
            try:
                status = link.open(args.port)
                validate_identity(status, f['versions']['1'], family, f['image']['expected_build'])
                summary['measurement_origin'] = 'actual_mcu'
                for version_text, entry in f['versions'].items():
                    version = int(version_text)
                    evidence.phase = entry['model']
                    if version > 1:
                        blob = (out / 'artifacts' / entry['path']).read_bytes()
                        evidence.event('mutation_intent', command='UPDATE', envelope_sha256=hashlib.sha256(blob).hexdigest(), version=version)
                        reply = link.command('UPDATE ' + blob.hex(), {'update'})
                        if reply.get('accepted') is not True or reply.get('reason') != 'ok' or reply.get('version') != version:
                            raise RuntimeError('Package update was not accepted: ' + str(reply))
                        validate_identity(link.command('STATUS', {'status'}), entry, family, f['image']['expected_build'])
                    golden = load(prepared / 'golden' / (entry['model'] + '.json'))
                    errors, latencies, disagreements, exceeded = [], [], 0, 0
                    category_results = {}
                    for i, x in enumerate(raw):
                        reply = link.command('INFER ' + ','.join(format(float(v), '.9g') for v in x), {'inference'})
                        validate_identity(reply, entry, family, f['image']['expected_build'], 'inference')
                        probability, label = reply.get('probability'), reply.get('label')
                        if type(probability) not in (int, float) or not math.isfinite(probability) or not 0 <= probability <= 1 or type(label) is not int or label not in (0, 1):
                            raise RuntimeError('Malformed numerical inference response')
                        error = abs(float(probability) - float(golden['probabilities'][i]))
                        mismatch = label != golden['labels'][i]
                        latency = reply.get('latency_us')
                        if type(latency) is not int or latency < 0:
                            raise RuntimeError('Malformed inference latency counter')
                        code_mismatch = None
                        if family == 'mlp_int8' and 'q_score' in reply:
                            if type(reply['q_score']) is not int or not -127 <= reply['q_score'] <= 127:
                                raise RuntimeError('Malformed integer score telemetry')
                            code_mismatch = reply['q_score'] != int(golden['scores'][i])
                            summary['integer_code_telemetry_available'] = True
                            summary['integer_codes_compared'] += 1
                            summary['integer_code_mismatches'] += int(code_mismatch)
                        evidence.record({'index': i, 'raw': x, 'response': reply, 'expected_probability': golden['probabilities'][i],
                                         'expected_label': golden['labels'][i], 'label_mismatch': mismatch,
                                         'probability_abs_error': error, 'integer_code_mismatch': code_mismatch}, 'observations')
                        errors.append(error)
                        latencies.append(latency)
                        disagreements += int(mismatch)
                        exceeded += int(error > TOLERANCE)
                        summary['inferred_records'] += 1
                        summary['label_mismatches'] += int(mismatch)
                        summary['probability_tolerance_exceeded'] += int(error > TOLERANCE)
                        summary['max_probability_abs_error'] = max(summary['max_probability_abs_error'], error)
                        c = category_results.setdefault(panel_rows[i]['category'], {'inferred_records': 0, 'label_mismatches': 0, 'max_probability_abs_error': 0.})
                        c['inferred_records'] += 1
                        c['label_mismatches'] += int(mismatch)
                        c['max_probability_abs_error'] = max(c['max_probability_abs_error'], error)
                        if (i + 1) % 256 == 0:
                            print(f"{family}/{entry['model']}: {i + 1}/{len(raw)}", flush=True)
                    summary['models_completed'] += 1
                    summary['model_results'].append({'family': family, 'model': entry['model'], 'build': f['image']['expected_build'],
                        'inferred_records': len(raw), 'label_mismatches': disagreements, 'probability_tolerance_exceeded': exceeded,
                        'max_probability_abs_error': max(errors), 'inference_latency_us': {
                            'min': int(min(latencies)), 'median': float(np.median(latencies)),
                            'p95': float(np.quantile(latencies, .95)), 'max': int(max(latencies))},
                        'category_results': category_results, 'timing_scope': 'device inference counter; no transport time'})
                    evidence.event('model_panel_complete', model=entry['model'], label_mismatches=disagreements,
                                   probability_tolerance_exceeded=exceeded, max_probability_abs_error=max(errors))
                    save(out / 'summary.json', summary)
                # Verify persistence after the last candidate without changing it.
                link.allow_reconnect = True
                link.command('REBOOT', {'reboot'})
                boot = link.receive({'boot'})
                if boot.get('version') != int(next(reversed(f['versions']))):
                    raise RuntimeError('Unexpected version after reboot')
                validate_identity(link.command('STATUS', {'status'}), entry, family, f['image']['expected_build'])
                evidence.event('final_reboot_verified', version=entry['identity']['version'])
            finally:
                link.close()
                evidence.close()
        summary['status'] = 'complete'
        summary['all_numerical_checks_agree'] = (summary['label_mismatches'] == 0 and summary['probability_tolerance_exceeded'] == 0 and summary['integer_code_mismatches'] == 0)
    except BaseException as exc:
        summary.update(status='failed', error=str(exc))
        raise
    finally:
        save(out / 'summary.json', summary)
        pin_directory(out)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('prepare', 'future', 'mcu'):
        p = sub.add_parser(command)
        p.add_argument('--root', type=Path, required=True)
        p.add_argument('--output', type=Path, required=True, help='Fresh output directory; never overwritten')
        if command in ('prepare', 'future'):
            p.add_argument('--prior-run', type=Path, required=True)
            p.add_argument('--data-root', type=Path)
        if command == 'prepare':
            p.add_argument('--samples-root', type=Path, help='Optional reconstruction directory containing samples/')
        elif command == 'future':
            p.add_argument('--future-db', type=Path, help='Explicit independently reconstructed frozen future SQLite')
        else:
            p.add_argument('--prepared', type=Path, required=True)
            p.add_argument('--port', required=True)
            p.add_argument('--board-id', required=True)
            p.add_argument('--timeout', type=float, default=20.)
            p.add_argument('--prebuilt-root', type=Path)
            p.add_argument('--provision', action='store_true')
    args = parser.parse_args()
    output_existed = args.output.exists()
    try:
        if output_existed:
            raise ValueError('Output directory already exists; select a fresh directory: ' + str(args.output))
        result = {'prepare': prepare, 'future': future, 'mcu': mcu}[args.command](args)
        print(json.dumps(result, allow_nan=False), flush=True)
        return 0
    except Exception as exc:
        if not output_existed and args.output.is_dir() and not (args.output / 'summary.json').exists():
            save(args.output / 'summary.json', {'status': 'failed', 'stage': '039', 'command': args.command,
                'error': str(exc), 'hardware_access_attempted': False, 'measurement_origin': 'not_measured'})
        print('error: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
