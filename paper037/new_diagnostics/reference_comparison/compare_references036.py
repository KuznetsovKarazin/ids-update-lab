#!/usr/bin/env python3
"""Frozen B-F32/B-I8 and percentile-export agreement on saved B calibration.

No model, cutoff, quantization range, or fitting sample is changed here.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import platform
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vendor'))
import model030 as ref


def load(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def predict(model, raw):
    if model['kind'] != 'mlp_int8_per_channel':
        return ref.predict(model, raw, True)
    x = ref.preprocess(model, raw)
    q = np.clip(ref.round_away(np.asarray(x / np.float32(model['input_scale']), np.float32)), -127, 127).astype(np.int64)
    for index, layer in enumerate(model['layers']):
        accumulator = q @ np.asarray(layer['weights'], np.int64) + np.asarray(layer['bias'], np.int64)
        if np.abs(accumulator).max() > 2147483647:
            raise ValueError('int32 accumulator overflow')
        q = np.column_stack([
            np.clip(ref.round_shift_away(accumulator[:, j] * int(multiplier), int(shift)), -127, 127)
            for j, (multiplier, shift) in enumerate(zip(layer['multiplier'], layer['shift']))])
        if index < 2:
            q = np.maximum(q, 0)
    score = q[:, 0]
    probability = ref.sigmoid(score.astype(np.float32) * np.float32(model['layers'][-1]['output_scale']))
    return probability, (score >= int(model['q_threshold'])).astype(np.uint8), score


def pair_metrics(reference, candidate, labels, reference_name, candidate_name):
    changed = reference != candidate
    normal = labels == 0
    attack = labels == 1
    return {
        'reference': reference_name, 'candidate': candidate_name,
        'rows': len(labels), 'changed': int(changed.sum()),
        'changed_fraction': float(changed.mean()),
        'normal_rows': int(normal.sum()), 'attack_rows': int(attack.sum()),
        'normal_changed': int(changed[normal].sum()),
        'attack_changed': int(changed[attack].sum()),
        'reference_normal_candidate_attack': int(((reference == 0) & (candidate == 1)).sum()),
        'reference_attack_candidate_normal': int(((reference == 1) & (candidate == 0)).sum()),
        'both_normal': int(((reference == 0) & (candidate == 0)).sum()),
        'both_attack': int(((reference == 1) & (candidate == 1)).sum()),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=HERE.parents[1] / 'evidence_inputs/training')
    parser.add_argument('--exports', type=Path, default=HERE.parent / 'quantization')
    parser.add_argument('--previous-analysis', type=Path, default=HERE.parents[1] / 'new_analysis')
    parser.add_argument('--output', type=Path, default=HERE)
    args = parser.parse_args()
    source, exports, output = args.source.resolve(), args.exports.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    data_path = source / 'samples/B_cal.npz'
    data = np.load(data_path)
    raw, labels = data['raw'], data['labels']
    paths = {
        'B_F32': source / 'models/B_mlp_float.json',
        'B_I8': source / 'models/B_mlp_int8.json',
        'maxabs_transferred': source / 'models/mlp_int8_compatible_requantized.json',
        'maxabs_recalibrated': args.previous_analysis / 'export_per_tensor_recalibrated.json',
        'per_channel_transferred': args.previous_analysis / 'export_per_channel_transferred.json',
        'per_channel_recalibrated': args.previous_analysis / 'export_per_channel_recalibrated.json',
        'percentile999_transferred': exports / 'percentile999_transferred.json',
        'percentile999_recalibrated': exports / 'percentile999_recalibrated.json',
    }
    models = {name: load(path) for name, path in paths.items()}
    predictions = {}
    properties = {}
    for name, model in models.items():
        probabilities, decision, scores = predict(model, raw)
        predictions[name] = decision
        properties[name] = {
            'kind': model['kind'], 'probability_threshold': model['threshold'],
            'integer_cut': model.get('q_threshold'),
            'output_scale': model['layers'][-1].get('output_scale'),
            'decision_rule': 'float32 probability > float32 threshold' if model['kind'] == 'mlp_float' else 'integer logit code >= integer cut',
            'false_positives': int(decision[labels == 0].sum()),
            'true_positives': int(decision[labels == 1].sum()),
            'calibration_FPR': float(decision[labels == 0].mean()),
            'calibration_recall': float(decision[labels == 1].mean()),
        }
    pairs = [('B_F32', 'B_I8')]
    for name in ['maxabs_transferred', 'maxabs_recalibrated',
                 'per_channel_transferred', 'per_channel_recalibrated',
                 'percentile999_transferred', 'percentile999_recalibrated']:
        pairs.extend([('B_F32', name), ('B_I8', name)])
    rows = [pair_metrics(predictions[a], predictions[b], labels, a, b) for a, b in pairs]
    result = {
        'analysis': 'posthoc_frozen_representation_reference_comparison',
        'data': 'saved B_cal; same calibration rows used for the frozen model thresholds',
        'new_fitting': False, 'new_threshold_selection': False,
        'full_future_test_evaluated': False, 'new_MCU_experiment': False,
        'interpretation': 'B-F32 versus B-I8 includes quantized representation and separately calibrated representation-specific operating points; it does not isolate quantization error alone.',
        'calibration_rows': len(labels), 'normal_rows': int((labels == 0).sum()),
        'attack_rows': int((labels == 1).sum()),
        'models': properties, 'comparisons': rows,
        'source_sha256': {'B_cal.npz': digest(data_path), **{name: digest(path) for name, path in paths.items()}},
        'implementation_sha256': {'compare_references036.py': digest(Path(__file__)),
                                  'vendor/model030.py': digest(HERE / 'vendor/model030.py')},
        'python_version': platform.python_version(), 'numpy_version': np.__version__,
    }
    (output / 'reference_comparison036.json').write_text(json.dumps(result, indent=2) + '\n')
    with (output / 'reference_comparison036.csv').open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    table_rows = []
    for name in models:
        if name == 'B_F32':
            continue
        table_rows.append({'variant': name,
            'changed_vs_B_F32': int((predictions[name] != predictions['B_F32']).sum()),
            'changed_vs_B_F32_pct': 100 * float((predictions[name] != predictions['B_F32']).mean()),
            'changed_vs_B_I8': int((predictions[name] != predictions['B_I8']).sum()),
            'changed_vs_B_I8_pct': 100 * float((predictions[name] != predictions['B_I8']).mean())})
    with (output / 'table5_reference_columns036.csv').open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(table_rows[0]))
        writer.writeheader()
        writer.writerows(table_rows)
    np.savez_compressed(output / 'frozen_predictions036.npz', labels=labels, **predictions)
    # Internal invariants compare Boolean operations to class partitions and
    # the full two-by-two decision contingency table.
    for row in rows:
        assert row['normal_changed'] + row['attack_changed'] == row['changed']
        assert row['reference_normal_candidate_attack'] + row['reference_attack_candidate_normal'] == row['changed']
        assert row['both_normal'] + row['both_attack'] + row['changed'] == len(labels)
    print(json.dumps(rows, indent=2))


if __name__ == '__main__':
    main()
