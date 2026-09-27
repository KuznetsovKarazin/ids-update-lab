#!/usr/bin/env python3
"""Audit recurring calibration vectors without fitting or selecting models.

Run from any directory: python recurrence_audit035.py
Inputs are frozen 030 samples/models and the fixed 034 post-hoc models. This
script writes only recurrence_* files beside itself. It never modifies inputs.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import sys

import numpy as np

HERE = Path(__file__).resolve().parent
PAPER = HERE.parent
sys.path.insert(0, str(PAPER / 'new_analysis'))
import analyze_export034 as export


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_csv(path, rows):
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=PAPER/'evidence_inputs/training')
    args = parser.parse_args()
    source = args.source
    sample_path = source/'samples/B_cal.npz'
    data = np.load(sample_path)
    raw, labels = data['raw'], data['labels']
    unique, inverse, counts = np.unique(raw, axis=0, return_inverse=True, return_counts=True)
    normal = np.bincount(inverse, weights=labels == 0, minlength=len(unique))
    attack = np.bincount(inverse, weights=labels == 1, minlength=len(unique))
    weight_normal, weight_attack = normal/counts, attack/counts
    target = np.asarray([0, 0, 0, 0, 1, 63, 0, 0], np.float32)
    target_index, = np.flatnonzero((unique == target).all(axis=1))
    normal_n = int((labels == 0).sum())
    attack_n = int((labels == 1).sum())
    target_normal_n = int(normal[target_index])
    allowed = int(np.floor(.01*normal_n))
    source_paths = [sample_path, PAPER/'analysis/science_evidence.json']
    models = {p.stem: p for p in sorted((source/'models').glob('*.json'))}
    variants034 = ['B_original', 'export_per_tensor_transferred',
                   'export_per_tensor_recalibrated', 'export_per_channel_transferred',
                   'export_per_channel_recalibrated']
    for name in variants034:
        models[name] = PAPER/'new_analysis'/f'{name}.json'
    rows, details = [], {}
    for name, model_path in models.items():
        model = read(model_path)
        source_paths.append(model_path)
        if model['kind'] in ('mlp_int8', 'mlp_int8_per_channel'):
            probability, prediction, score = export.predq(model, unique)
        else:
            probability, prediction = export.ref.predict(model, unique)
            score = None
        fp = int(np.dot(prediction, normal))
        tp = int(np.dot(prediction, attack))
        row = {
            'model': name,
            'q_threshold': model.get('q_threshold', ''),
            'normal_rows': normal_n,
            'attack_rows': attack_n,
            'false_positives': fp,
            'true_positives': tp,
            'row_FPR': fp/normal_n,
            'row_recall': tp/attack_n,
            # Existing paper estimand: each vector has total mass one, with
            # proportional label shares when the same vector has both labels.
            'all_vector_weight_FPR': float(np.dot(prediction, weight_normal)/weight_normal.sum()),
            'all_vector_weight_recall': float(np.dot(prediction, weight_attack)/weight_attack.sum()),
            # Reviewer's alternative normal-only estimand: each distinct vector
            # occurring among normals has equal normal-class weight.
            'distinct_normal_vectors': int((normal > 0).sum()),
            'distinct_normal_FP_vectors': int(prediction[normal > 0].sum()),
            'normal_only_vector_FPR': float(prediction[normal > 0].mean()),
            'target_score': int(score[target_index]) if score is not None else '',
            'target_probability': float(probability[target_index]),
            'target_prediction': int(prediction[target_index]),
            'target_false_positives': target_normal_n*int(prediction[target_index]),
        }
        rows.append(row)
        if name in variants034:
            target_code = int(score[target_index])
            code_normal = int(normal[score == target_code].sum())
            code_attack = int(attack[score == target_code].sum())
            details[name] = dict(row, target_score_normal_rows=code_normal,
                                 target_score_attack_rows=code_attack)
    byname = {row['model']: row for row in rows}
    # Reproduce the key reviewer observations and the distinct weighting issue.
    assert (normal_n, attack_n, target_normal_n, allowed) == (2088, 100000, 380, 20)
    assert int(attack[target_index]) == 0
    assert byname['B_original']['target_score'] == 5
    assert byname['export_per_tensor_transferred']['target_score'] == 21
    assert byname['export_per_tensor_transferred']['false_positives'] == 421
    assert details['export_per_tensor_transferred']['target_score_normal_rows'] == 391
    assert byname['export_per_tensor_recalibrated']['q_threshold'] == 22
    assert byname['export_per_tensor_recalibrated']['true_positives'] == 23933
    assert (normal > 0).sum() == 1593
    assert byname['export_per_tensor_transferred']['distinct_normal_FP_vectors'] == 36
    conflicts = []
    for index in np.flatnonzero((normal > 0) & (attack > 0)):
        conflicts.append({'raw': unique[index].tolist(), 'normal_rows': int(normal[index]),
                          'attack_rows': int(attack[index]), 'normal_weight': float(weight_normal[index])})
    top_normal = []
    order = np.lexsort((np.arange(len(unique)), -normal))
    for rank, index in enumerate(order[:20], 1):
        top_normal.append({'rank_by_normal_frequency': rank, 'raw': unique[index].tolist(),
                           'normal_rows': int(normal[index]), 'attack_rows': int(attack[index])})
    evidence = read(PAPER/'analysis/science_evidence.json')
    future_top20 = {}
    for name in ('B_mlp_int8', 'mlp_int8_compatible_requantized'):
        metric = evidence['evaluation']['cohorts']['top20']['rows'][name]
        future_top20[name] = metric
    backdoor = []
    for name, metric in evidence['by_attack_type']['backdoor'].items():
        if name.startswith(('A_', 'B_')):
            backdoor.append({'model': name, 'attack_rows': int(metric['mass']),
                             'detected': int(metric['confusion_mass'][1][1]),
                             'recall': metric['recall']})
    findings = {
        'analysis': 'posthoc calibration recurrence audit; no fitting or threshold changes',
        'source_hashes': {str(p.relative_to(PAPER)) if p.is_relative_to(PAPER) else str(p): sha(p) for p in source_paths},
        'sample': {'rows': len(raw), 'unique_vectors': len(unique), 'normal_rows': normal_n,
                   'attack_rows': attack_n, 'distinct_normal_vectors': int((normal > 0).sum()),
                   'conflicting_vectors': len(conflicts), 'normal_vector_weight': float(weight_normal.sum())},
        'target': {'raw': target.tolist(), 'normal_rows': target_normal_n,
                   'attack_rows': int(attack[target_index]), 'normal_row_fraction': target_normal_n/normal_n,
                   'FP_budget_at_1pct': allowed, 'target_FP_budget_multiple': target_normal_n/allowed,
                   'share_of_transferred_export_FP': target_normal_n/byname['export_per_tensor_transferred']['false_positives']},
        'variants034': details,
        'weight_definitions': {
            'all_vector_weight_FPR': 'All calibration rows with vector v receive weight 1/n_v; mixed-label vectors retain proportional normal and attack masses. This is the estimand used in the paper.',
            'normal_only_vector_FPR': 'Each distinct vector occurring in normal calibration rows has normal-class weight one, irrespective of attacks with the same vector. This reproduces the reviewer 2.26% number.',
        },
        'conflicting_vectors': conflicts,
        'top20_calibration_normal_vectors': top_normal,
        'future_top20_aggregate': future_top20,
        'future_target_top20_membership': 'unknown: retained 030 outputs contain cohort aggregates, not the twenty raw keys; training/test_vectors.sqlite was excluded from original results archive',
        'backdoor_inference_scope': 'Class recalls are observed; class-specific unique-vector counts and concentration are not present in retained summaries. Near-binary recall across models does not prove that one/few vectors dominate this class.',
        'backdoor': backdoor,
    }
    (HERE/'recurrence_findings035.json').write_text(json.dumps(findings, indent=2)+'\n')
    write_csv(HERE/'recurrence_calibration_all035.csv', rows)
    write_csv(HERE/'recurrence_calibration_key035.csv', [byname[n] for n in variants034])
    write_csv(HERE/'recurrence_backdoor035.csv', backdoor)
    print(json.dumps({'status': 'complete', 'models': len(rows), 'reviewer_target_counts_verified': True,
                      'normal_only_vs_paper_weighting_differ': True, 'future_top20_membership_verified': False,
                      'physical_hardware_access': False}))


if __name__ == '__main__':
    main()
