#!/usr/bin/env python3
"""Independent CIC release experiment under the frozen 056 protocol.

Source CSVs and reconstructible arrays/databases remain local. This program
records failures, never reuses an output directory, and never contacts an MCU.
"""
from __future__ import annotations
import os
for _key in ('OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS', 'NUMEXPR_NUM_THREADS'):
    os.environ[_key] = '1'
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import sqlite3
import sys
import traceback
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = ROOT / 'revision056/protocol.json'
ROLES = ('A_fit', 'A_cal', 'B_fit_added', 'B_cal', 'common_test')
FEATURES = ('flow_duration', 'Header_Length', 'Rate', 'Tot sum', 'Min', 'Max', 'Std', 'IAT')
ATTACKS = frozenset(('DDoS-RSTFINFlood', 'DDoS-PSHACK_Flood', 'DDoS-SYN_Flood', 'DDoS-UDP_Flood',
    'DDoS-TCP_Flood', 'DDoS-ICMP_Flood', 'DDoS-SynonymousIP_Flood', 'DDoS-ACK_Fragmentation',
    'DDoS-UDP_Fragmentation', 'DDoS-ICMP_Fragmentation', 'DDoS-SlowLoris', 'DDoS-HTTP_Flood',
    'DoS-UDP_Flood', 'DoS-SYN_Flood', 'DoS-TCP_Flood', 'DoS-HTTP_Flood',
    'Mirai-greeth_flood', 'Mirai-greip_flood', 'Mirai-udpplain', 'Recon-PingSweep', 'Recon-OSScan',
    'Recon-PortScan', 'Recon-HostDiscovery', 'VulnerabilityScan', 'DNS_Spoofing', 'MITM-ArpSpoofing',
    'BrowserHijacking', 'Backdoor_Malware', 'XSS', 'Uploading_Attack', 'SqlInjection',
    'CommandInjection', 'DictionaryBruteForce'))


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(8 << 20), b''):
            h.update(b)
    return h.hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n', encoding='utf-8')


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def labels(values):
    values = np.asarray(values, dtype=str)
    unknown = set(values) - ATTACKS - {'BenignTraffic'}
    if unknown:
        raise ValueError('unknown CIC labels; do not infer labels by substrings: ' + repr(sorted(unknown)))
    return (values != 'BenignTraffic').astype(np.uint8)


def role_indices(raw):
    x = np.asarray(raw, dtype='<f4').copy()
    if x.ndim != 2 or x.shape[1] != 8 or not np.isfinite(x).all() or (x < 0).any():
        raise ValueError('role assignment requires eight finite nonnegative float32 values')
    x[x == 0] = 0
    buckets = np.fromiter((int.from_bytes(hashlib.sha256(b'ids056-role-v1:' + row.tobytes()).digest()[:8], 'little') % 100
                           for row in x), dtype=np.uint8, count=len(x))
    return np.searchsorted(np.array([35, 45, 65, 75]), buckets, side='right')


def verify_sources(data):
    manifest = json.loads((data / 'source_manifest.json').read_text())
    catalog = json.loads((data / 'catalog.json').read_text())
    downloader = load_module('download_cic056', Path(__file__).with_name('download_cic.py'))
    if manifest['protocol_sha256'] != sha(PROTOCOL) or catalog['protocol_sha256'] != sha(PROTOCOL):
        raise ValueError('source selection was frozen under a different protocol')
    if manifest['catalog_sha256'] != sha(data / 'catalog.json'):
        raise ValueError('catalog changed')
    selected = downloader.select_files(catalog['files'])
    if catalog['selected'] != selected or sorted(selected) != sorted(x['file'] for x in manifest['files']):
        raise ValueError('source shard selection differs from the frozen rule')
    for row in manifest['files']:
        p = data / row['file']
        if p.name != row['file'] or p.stat().st_size != row['bytes'] or sha(p) != row['sha256']:
            raise ValueError('source identity mismatch: ' + row['file'])
    return manifest


def prepare(data, output, train):
    manifest = verify_sources(data)
    save(output / 'source_manifest.json', manifest)
    save(output / 'catalog.json', json.loads((data / 'catalog.json').read_text()))
    samples = {r: {} for r in ROLES[:-1]}
    counts = {r: Counter() for r in ROLES}
    db = sqlite3.connect(output / 'test_vectors.sqlite')
    db.executescript('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA cache_size=-65536; '
                    'CREATE TABLE vectors(key BLOB PRIMARY KEY,n0 INTEGER,n1 INTEGER) WITHOUT ROWID; '
                    'CREATE TABLE groups(key BLOB,label INTEGER,kind TEXT,n INTEGER,PRIMARY KEY(key,label,kind)) WITHOUT ROWID;')
    audits = []
    for ordinal, source in enumerate(manifest['files']):
        p = data / source['file']
        before = (p.stat().st_size, p.stat().st_mtime_ns)
        audit = {'file': source['file'], 'source_rows': 0, 'invalid_feature_rows': 0, 'admitted_rows': 0}
        for frame in pd.read_csv(p, usecols=[*FEATURES, 'label'], chunksize=32768, on_bad_lines='error'):
            types = frame['label'].to_numpy(dtype=str)
            y = labels(types)
            with np.errstate(over='ignore', invalid='ignore'):
                raw = frame[list(FEATURES)].to_numpy(dtype=np.float32)
            valid = np.isfinite(raw).all(axis=1) & (raw >= 0).all(axis=1)
            ids = (np.uint64(ordinal) << np.uint64(32)) + np.arange(audit['source_rows'], audit['source_rows'] + len(raw), dtype=np.uint64)
            if audit['source_rows'] + len(raw) >= 2**32:
                raise ValueError('row ID capacity exceeded')
            audit['source_rows'] += len(raw)
            audit['invalid_feature_rows'] += int((~valid).sum())
            raw, y, types, ids = raw[valid], y[valid], types[valid], ids[valid]
            raw[raw == 0] = 0
            audit['admitted_rows'] += len(raw)
            assignment = role_indices(raw)
            for i, role in enumerate(ROLES):
                mask = assignment == i
                for kind in np.unique(types[mask]):
                    selected = mask & (types == kind)
                    c = int(kind != 'BenignTraffic')
                    counts[role][(c, str(kind))] += int(selected.sum())
                    if role == 'common_test':
                        continue
                    cap = (sys.maxsize if c == 0 else 100000) if role.endswith('_cal') else (100000 if c == 0 else 50000)
                    sampler = samples[role].setdefault((c, str(kind)), train.BottomK(cap))
                    sampler.add(raw[selected], ids[selected])
            test = assignment == 4
            vc, gc = {}, Counter()
            for x, c, kind in zip(raw[test], y[test], types[test]):
                key = np.asarray(x, dtype='<f4').tobytes()
                v = vc.setdefault(key, [0, 0]); v[int(c)] += 1
                gc[(key, int(c), str(kind))] += 1
            with db:
                db.executemany('INSERT INTO vectors VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET n0=n0+excluded.n0,n1=n1+excluded.n1',
                               [(k, *v) for k, v in vc.items()])
                db.executemany('INSERT INTO groups VALUES(?,?,?,?) ON CONFLICT(key,label,kind) DO UPDATE SET n=n+excluded.n',
                               [(k, c, t, n) for (k, c, t), n in gc.items()])
        if before != (p.stat().st_size, p.stat().st_mtime_ns):
            raise ValueError('input changed during scan')
        audits.append(audit)
        print(json.dumps({'phase': 'source_scanned', **audit}), flush=True)
    support = {role: {'normal': sum(n for (c, k), n in cc.items() if c == 0),
                      'attack': sum(n for (c, k), n in cc.items() if c == 1),
                      'by_type': {k: n for (c, k), n in sorted(cc.items())}} for role, cc in counts.items()}
    save(output / 'data_audit.json', {'sources': audits, 'roles': support, 'chronological': False,
          'same_vector_cross_role_overlap': 0, 'overlap_basis': 'deterministic role depends only on canonical admitted features',
          'capture_or_session_independence_established': False})
    db.execute('PRAGMA wal_checkpoint(TRUNCATE)'); db.close()
    for role, count in support.items():
        if min(count['normal'], count['attack']) < 1000:
            raise ValueError('prespecified class-support gate failed in ' + role)
    merged = {}
    for role in ('A_fit', 'B_fit_added'):
        for key, sampler in samples[role].items():
            target = merged.setdefault(key, train.BottomK(sampler.k))
            x, ids = sampler.arrays(); target.add(x, ids)
    for key, sampler in merged.items():
        sampler.n = sum(samples[r][key].n for r in ('A_fit', 'B_fit_added') if key in samples[r])
    samples['B_fit'] = merged
    arrays, sampling = {}, {}
    for role, strata in samples.items():
        xx, yy, ww, rr, smeta = [], [], [], [], []
        cls = [sum(s.n for (c, k), s in strata.items() if c == j) for j in (0, 1)]
        for (c, kind), sampler in sorted(strata.items()):
            x, ids = sampler.arrays()
            weight = sampler.n / len(ids) * (sum(cls) / (2 * cls[c]) if 'fit' in role else 1.)
            xx.append(x); yy.extend([c] * len(x)); ww.extend([weight] * len(x)); rr.append(ids)
            smeta.append({'label': c, 'type': kind, 'population_rows': sampler.n, 'sample_rows': len(ids)})
        x, y, w, ids = np.concatenate(xx), np.asarray(yy, np.uint8), np.asarray(ww, np.float64), np.concatenate(rr)
        order = np.argsort(ids); x, y, w, ids = x[order], y[order], w[order], ids[order]
        w /= w.mean(); arrays[role] = (x, y, w)
        np.savez_compressed(output / 'samples' / (role + '.npz'), raw=x, labels=y, weights=w, row_ids=ids)
        sampling[role] = {'rows': len(y), 'strata': smeta,
                         'array_sha256': {n: hashlib.sha256(a.tobytes()).hexdigest() for n, a in [('raw', x), ('labels', y), ('weights', w), ('row_ids', ids)]}}
    save(output / 'sampling.json', sampling)
    return arrays, support


def metrics(v):
    tn, fp, fn, tp, changed = map(float, v)
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (tn + fp) if tn + fp else None
    return {'tn': tn, 'fp': fp, 'fn': fn, 'tp': tp, 'changed': changed,
            'recall': recall, 'FPR': fpr,
            'balanced_accuracy': (recall + 1 - fpr) / 2 if recall is not None and fpr is not None else None,
            'decision_disagreement': changed / (tn + fp + fn + tp) if tn + fp + fn + tp else None}


def evaluate(models, output, train):
    names = list(models)
    reference_indices = [names.index('B_' + train.family_of(n)) for n in names]
    weightings = ('rows', 'vector_balanced', 'frequency_cap100')
    totals = {w: np.zeros((len(names), 5), np.float64) for w in weightings}
    by_type = defaultdict(lambda: {w: np.zeros((len(names), 5), np.float64) for w in weightings})
    max_probability_difference = np.zeros(len(names))
    db = sqlite3.connect(output / 'test_vectors.sqlite')
    cursor = db.execute('SELECT key,n0,n1 FROM vectors ORDER BY key')
    unique = 0
    while batch := cursor.fetchmany(2048):
        keys = [r[0] for r in batch]
        raw = np.asarray([np.frombuffer(k, '<f4') for k in keys], np.float32)
        predictions = [train.predict(models[n], raw) for n in names]
        probs = np.asarray([p for p, _ in predictions])
        pred = np.asarray([y for _, y in predictions])
        ref = pred[reference_indices]
        changed = pred != ref
        max_probability_difference = np.maximum(max_probability_difference, np.max(np.abs(probs - probs[reference_indices]), axis=1))
        n0, n1 = np.asarray([r[1:] for r in batch], np.float64).T
        n = n0 + n1
        weights = {'rows': np.ones(len(n)), 'vector_balanced': 1 / n, 'frequency_cap100': np.minimum(n, 100) / n}
        for weighting, factor in weights.items():
            totals[weighting] += np.column_stack(((~pred.astype(bool) * (n0 * factor)).sum(1),
                (pred * (n0 * factor)).sum(1), (~pred.astype(bool) * (n1 * factor)).sum(1),
                (pred * (n1 * factor)).sum(1), (changed * (n * factor)).sum(1)))
        key_index = {k: i for i, k in enumerate(keys)}
        groups = db.execute('SELECT key,label,kind,n FROM groups WHERE key>=? AND key<=? ORDER BY key', (keys[0], keys[-1])).fetchall()
        for key, label, kind, count in groups:
            i = key_index[key]
            col = pred[:, i]
            for weighting, factor in weights.items():
                mass = count * factor[i]
                v = by_type[kind][weighting]
                if label == 0:
                    v[:, 0] += (1-col) * mass; v[:, 1] += col * mass
                else:
                    v[:, 2] += (1-col) * mass; v[:, 3] += col * mass
                v[:, 4] += changed[:, i] * mass
        unique += len(batch)
        if unique % 102400 == 0:
            print(json.dumps({'phase': 'evaluate', 'unique_vectors': unique}), flush=True)
    db.close()
    rows = [{'model': name, 'reference': names[reference_indices[i]], 'weighting': w,
             **metrics(totals[w][i]), 'max_probability_abs_difference': float(max_probability_difference[i])}
            for i, name in enumerate(names) for w in weightings]
    types = [{'model': name, 'reference': names[reference_indices[i]], 'weighting': w, 'attack_type': kind, **metrics(mm[w][i])}
             for kind, mm in sorted(by_type.items()) for i, name in enumerate(names) for w in weightings]
    for filename, records in [('metrics.csv', rows), ('by_type.csv', types)]:
        with (output / filename).open('w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=list(records[0])); writer.writeheader(); writer.writerows(records)
    save(output / 'evaluation.json', {'status': 'complete', 'unique_test_vectors': unique, 'metrics': rows, 'by_type': types,
         'data_origin': 'CICIoT2023_selected_shards_056', 'chronological': False, 'hardware_accessed': False,
         'uncertainty': 'descriptive finite-corpus metrics; capture independence not established'})
    return unique, rows


def run(data, output):
    data, output = Path(data).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    for name in ('samples', 'models'):
        (output / name).mkdir()
    summary = {'status': 'running', 'protocol_sha256': sha(PROTOCOL), 'hardware_accessed': False,
               'measurement_origin': 'host_computation_on_source_dataset', 'started_utc': datetime.now(timezone.utc).isoformat()}
    save(output / 'summary.json', summary)
    try:
        protocol = json.loads(PROTOCOL.read_text())
        if protocol['external_data']['features'] != list(FEATURES):
            raise ValueError('feature contract differs from frozen protocol')
        sys.path.insert(0, str(ROOT / 'research030/training'))
        train = load_module('training_cic056', ROOT / 'research030/training/run_training030.py')
        train.FEATURES = list(FEATURES)
        save(output / 'protocol.json', protocol)
        save(output / 'environment.json', {'python': sys.version, 'platform': platform.platform(),
             'numpy': np.__version__, 'pandas': pd.__version__, 'feature_names_override_only': list(FEATURES),
             'fitting_code_sha256': sha(ROOT / 'research030/training/run_training030.py'),
             'reference_code_sha256': sha(ROOT / 'research030/training/model030.py'), 'runner_sha256': sha(Path(__file__)),
             'model_configuration': train.CONFIG})
        arrays, support = prepare(data, output, train)
        models = train.fit_models(arrays, output)
        for name, model in models.items():
            model['data_origin'] = 'CICIoT2023_selected_shards_056'
            model['feature_contract'] = {'features': list(FEATURES), 'source_units_unchanged': True}
            save(output / 'models' / (name + '.json'), model)
        unique, rows = evaluate(models, output, train)
        summary.update(status='complete', model_configurations=len(models), unique_test_vectors=unique,
                       test_rows=support['common_test']['normal'] + support['common_test']['attack'],
                       source_rows=sum(r['source_rows'] for r in json.loads((output / 'data_audit.json').read_text())['sources']),
                       new_MCU_experiment=False, test_tuning_performed=False)
    except BaseException as exc:
        summary.update(status='failed', error=f'{type(exc).__name__}: {exc}')
        (output / 'failure.txt').write_text(traceback.format_exc())
        raise
    finally:
        summary['finished_utc'] = datetime.now(timezone.utc).isoformat()
        save(output / 'summary.json', summary)
        save(output / 'result_manifest.json', {'sha256': {p.relative_to(output).as_posix(): sha(p)
             for p in sorted(output.rglob('*')) if p.is_file() and p.name != 'result_manifest.json'}})
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.data_root, args.output)
