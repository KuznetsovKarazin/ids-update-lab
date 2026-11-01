#!/usr/bin/env python3
"""Re-scan source CSVs and re-score frozen models without importing the CIC runner.

The original model030 numerical reference is shared; source parsing, role
assignment, grouping and metric accumulation are independently implemented here.
This is a computational audit, not independent capture or hardware evidence.
"""
import os
for name in ('OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS'):
    os.environ[name] = '1'
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'research030/training'))
from model030 import predict

def digest(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def main(data, result, output):
    protocol = json.loads((result / 'protocol.json').read_text())
    if protocol != json.loads((ROOT / 'revision056/protocol.json').read_text()):
        raise ValueError('protocol meaning changed')
    run_summary = json.loads((result / 'summary.json').read_text())
    if run_summary['protocol_sha256'] != digest(ROOT / 'revision056/protocol.json'):
        raise ValueError('frozen source protocol changed')
    manifest = json.loads((result / 'result_manifest.json').read_text())['sha256']
    for relative, sha in manifest.items():
        if digest(result / relative) != sha:
            raise ValueError('result hash mismatch: ' + relative)
    env = json.loads((result / 'environment.json').read_text())
    for key, file in [('runner_sha256', 'revision056/cic/run_cic.py'),
                      ('fitting_code_sha256', 'research030/training/run_training030.py'),
                      ('reference_code_sha256', 'research030/training/model030.py')]:
        if env[key] != digest(ROOT / file):
            raise ValueError('executed source changed: ' + file)
    features = protocol['external_data']['features']
    roles = protocol['external_data']['roles']
    counts = {r: Counter() for r in roles}
    grouped = Counter()
    rows = invalid = 0
    sources = json.loads((result / 'source_manifest.json').read_text())['files']
    for source in sources:
        path = data / source['file']
        if digest(path) != source['sha256']:
            raise ValueError('source hash mismatch')
        for frame in pd.read_csv(path, usecols=features + ['label'], chunksize=65536):
            x = frame[features].to_numpy(dtype='<f4')
            good = np.isfinite(x).all(1) & (x >= 0).all(1)
            rows += len(x); invalid += int((~good).sum())
            x = x[good]; x[x == 0] = 0
            for value, kind in zip(x, frame['label'].to_numpy(dtype=str)[good]):
                key = value.tobytes()
                bucket = int.from_bytes(hashlib.sha256(b'ids056-role-v1:' + key).digest()[:8], 'little') % 100
                role, = [r for r, (lo, hi) in roles.items() if lo <= bucket < hi]
                counts[role][kind] += 1
                if role == 'common_test':
                    grouped[key, kind] += 1
        print('rescanned', source['file'], flush=True)
    original = json.loads((result / 'data_audit.json').read_text())
    for role in roles:
        if dict(counts[role]) != original['roles'][role]['by_type']:
            raise ValueError('role/type count mismatch')
    with sqlite3.connect('file:' + str(result / 'test_vectors.sqlite') + '?mode=ro', uri=True) as db:
        saved = Counter({(key, kind): n for key, kind, n in db.execute('SELECT key,kind,n FROM groups')})
        if saved != grouped:
            raise ValueError('independently rebuilt test groups differ')
    vectors = defaultdict(list)
    for (key, kind), n in grouped.items():
        vectors[key].append((kind, n))
    metrics = pd.read_csv(result / 'metrics.csv').set_index(['model', 'weighting'])
    type_metrics = pd.read_csv(result / 'by_type.csv').set_index(['model', 'weighting', 'attack_type'])
    names = list(dict.fromkeys(metrics.index.get_level_values(0)))
    models = {n: json.loads((result / 'models' / (n + '.json')).read_text()) for n in names}
    totals = defaultdict(lambda: np.zeros(5))
    typed = defaultdict(lambda: np.zeros(5))
    keys = sorted(vectors)
    for offset in range(0, len(keys), 4096):
        block = keys[offset:offset+4096]
        x = np.array([np.frombuffer(key, '<f4') for key in block])
        decisions = {n: predict(m, x)[1] for n, m in models.items()}
        indices, kinds, populations, frequencies = [], [], [], []
        for i, key in enumerate(block):
            total = sum(n for kind, n in vectors[key])
            for kind, count in vectors[key]:
                indices.append(i); kinds.append(kind); populations.append(total); frequencies.append(count)
        indices = np.array(indices); kinds = np.array(kinds)
        attack = (kinds != 'BenignTraffic').astype(int)
        populations = np.array(populations); frequencies = np.array(frequencies)
        weight_arrays = {'rows': frequencies, 'vector_balanced': frequencies/populations,
                         'frequency_cap100': frequencies*np.minimum(populations, 100)/populations}
        masks = {kind: kinds == kind for kind in set(kinds)}
        for name in names:
            ref = metrics.loc[(name, 'rows'), 'reference']
            decision = decisions[name][indices].astype(int)
            changed = decision != decisions[ref][indices]
            cell = attack * 2 + decision
            for weighting, weights in weight_arrays.items():
                totals[name, weighting] += np.r_[np.bincount(cell, weights=weights, minlength=4), np.sum(weights[changed])]
                for kind, mask in masks.items():
                    typed[name, weighting, kind] += np.r_[np.bincount(cell[mask], weights=weights[mask], minlength=4), np.sum(weights[mask & changed])]
    for table, computed in [(metrics, totals), (type_metrics, typed)]:
        if len(table) != len(computed):
            raise ValueError('missing metric cells')
        for index, values in computed.items():
            expected = table.loc[index, ['tn', 'fp', 'fn', 'tp', 'changed']].to_numpy(dtype=float)
            if not np.allclose(values, expected, rtol=1e-12, atol=1e-7):
                raise ValueError('recomputed metric differs: ' + repr(index))
    report = dict(status='passed', source_rows=rows, invalid_feature_rows=invalid,
                  source_files=len(sources), test_rows=sum(grouped.values()),
                  unique_test_vectors=len(keys), models=len(models), aggregate_cells=len(totals),
                  type_cells=len(typed), protocol_sha256=run_summary['protocol_sha256'],
                  saved_protocol_json_sha256=digest(result / 'protocol.json'),
                  result_manifest_sha256=digest(result / 'result_manifest.json'),
                  audit_code_sha256=digest(__file__), source_rescan=True,
                  independent_role_group_and_confusion_accumulation=True,
                  shared_numerical_reference='research030/training/model030.py', hardware_accessed=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as f:
        json.dump(report, f, indent=2); f.write('\n')
    print(json.dumps(report), flush=True)

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('data', 'result', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args()
    main(args.data.resolve(), args.result.resolve(), args.output.resolve())
