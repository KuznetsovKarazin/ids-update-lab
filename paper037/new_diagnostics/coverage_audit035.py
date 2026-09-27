#!/usr/bin/env python3
"""Audit the input coverage of the frozen 258-vector MCU implementation checks.

This script inspects saved inputs only; it performs no new inference or MCU test.
Run from any directory; NumPy is the only external dependency.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from pathlib import Path
import numpy as np


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def feature_summary(raw: np.ndarray, names: list[str]) -> list[dict]:
    result = []
    for index, name in enumerate(names):
        x = raw[:, index]
        nonzero = x[x != 0]
        result.append({
            'feature': name, 'min': float(x.min()), 'max': float(x.max()),
            'median': float(np.median(x)),
            'nonzero_min': float(nonzero.min()) if len(nonzero) else None,
            'zero_count': int(np.count_nonzero(x == 0)),
            'zero_fraction': float(np.mean(x == 0)),
            'distinct_values': int(len(np.unique(x))),
        })
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[1]
    parser.add_argument('--training', type=Path, default=root / 'evidence_inputs' / 'training')
    parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    files = sorted((args.training / 'hardware_vectors').glob('*.json'))
    if not files:
        raise SystemExit('No saved hardware vectors found')
    model_path = args.training / 'models' / 'B_lr.json'
    names = json.loads(model_path.read_text())['feature_names']
    reference = json.loads(files[0].read_text())
    raw = np.asarray(reference['raw'], dtype='<f4')
    keys = [row.tobytes() for row in raw]
    per_file = []
    for path in files:
        obj = json.loads(path.read_text())
        x = np.asarray(obj['raw'], dtype='<f4')
        per_file.append({
            'path': str(path.relative_to(args.training)),
            'sha256': sha(path), 'model_id': obj['model_id'],
            'selection': obj['selection'], 'data_origin': obj['data_origin'],
            'shape': list(x.shape),
            'raw_sha256': hashlib.sha256(x.tobytes()).hexdigest(),
            'raw_exactly_equal_to_reference': bool(np.array_equal(x, raw)),
            'reference_positive_decisions': int(np.count_nonzero(np.asarray(obj['labels']) == 1)),
            'reference_probability_range': [float(min(obj['probabilities'])), float(max(obj['probabilities']))],
        })
    nz_counts, nz_freqs = np.unique(np.count_nonzero(raw, axis=1), return_counts=True)
    output = {
        'analysis': 'posthoc audit of frozen input selection; no new MCU test',
        'reference_file': per_file[0]['path'], 'files_checked': len(files),
        'all_files_have_identical_raw_inputs': all(x['raw_exactly_equal_to_reference'] for x in per_file),
        'n_inputs': len(raw), 'n_distinct_float32_vectors': len(set(keys)),
        'feature_names': names, 'selection': reference['selection'],
        'raw_byte_keys_are_sorted': keys == sorted(keys),
        'all_zero_vectors': int(np.count_nonzero(np.all(raw == 0, axis=1))),
        'nonzero_entries': int(np.count_nonzero(raw)),
        'total_entries': int(raw.size),
        'contains_B_cal_dominant_normal_template': bool(np.any(np.all(raw == np.asarray([0, 0, 0, 0, 1, 63, 0, 0], dtype='<f4'), axis=1))),
        'nonzero_features_per_vector': {str(int(k)): int(v) for k, v in zip(nz_counts, nz_freqs)},
        'features': feature_summary(raw, names), 'files': per_file,
        'model_feature_order_source': {'path': str(model_path.relative_to(args.training)), 'sha256': sha(model_path)},
        'saved_sample_comparisons': {},
    }
    for stem in ('B_cal', 'B_fit'):
        path = args.training / 'samples' / f'{stem}.npz'
        if not path.exists():
            continue
        with np.load(path) as z:
            x = np.asarray(z['raw'], dtype='<f4')
        output['saved_sample_comparisons'][stem] = {
            'path': str(path.relative_to(args.training)), 'sha256': sha(path),
            'n_rows': len(x), 'features': feature_summary(x, names),
            'all_zero_fraction': float(np.mean(np.all(x == 0, axis=1))),
            'scope': 'Descriptive contrast with the saved sample; not the future-test population.',
        }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'coverage_audit035.json').write_text(json.dumps(output, indent=2) + '\n')
    with (args.output / 'coverage_features035.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(output['features'][0]))
        writer.writeheader(); writer.writerows(output['features'])
    rows = []
    for f in output['features']:
        feat = f['feature'].replace('_', r'\_')
        low, high = f['min'], f['max']
        span = f'{low:g}' if low == high else f'{low:g}--{high:g}'
        rows.append(r'\texttt{' + feat + '} & ' + span + f" & {f['zero_count']}/258 & {100*f['zero_fraction']:.2f} & {f['distinct_values']}" + r' \\')
    table = r'''\begin{table}[H]
\caption{Raw-input coverage of the frozen MCU implementation checks. All 24 saved model and ablation input files contain the same 258 distinct vectors. The feature order follows the signed input contract.}
\label{tab:hardware-vector-coverage}
\centering\small
\begin{tabular}{lrrrr}
\toprule
Feature & Range & Zero inputs & Zero (\%) & Distinct values \\
\midrule
''' + '\n'.join(rows) + r'''
\bottomrule
\end{tabular}
\end{table}
'''
    (args.output / 'coverage_table035.tex').write_text(table)
    print(json.dumps({k: output[k] for k in ('files_checked', 'n_inputs', 'all_files_have_identical_raw_inputs', 'all_zero_vectors', 'nonzero_features_per_vector')}))


if __name__ == '__main__':
    main()
