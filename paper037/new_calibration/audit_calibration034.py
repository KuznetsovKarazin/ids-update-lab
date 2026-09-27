"""Recompute frozen calibration outcomes, then format descriptive supplements.

No fitting, threshold selection, or mutation of stage030 is performed.  The
prediction implementation below is independent of model030.py; numerical
operations follow the documented float32 and integer export contract.
"""
from pathlib import Path
import argparse
import csv
import hashlib
import json
import math
import numpy as np

HERE = Path(__file__).resolve().parent
BASE_MODELS = [f'{release}_{family}' for release in ('A', 'B')
               for family in ('lr', 'dt', 'mlp_float', 'mlp_int8')]
LABELS = {'lr':'LR', 'dt':'DT', 'mlp_float':'MLP-F32', 'mlp_int8':'MLP-I8'}
TYPE_ORDER = ['normal', 'ddos', 'backdoor', 'mitm', 'password', 'ransomware', 'xss']
TYPE_LABELS = {'normal': 'Normal', 'ddos': 'DDoS', 'backdoor': 'Backdoor',
               'mitm': 'MITM', 'password': 'Password', 'ransomware': 'Ransomware', 'xss': 'XSS'}

def sigmoid32(logit):
    z = np.asarray(logit, dtype=np.float32)
    result = np.empty_like(z)
    pos = z >= 0
    result[pos] = np.float32(1) / (np.float32(1) + np.exp(-z[pos]))
    ex = np.exp(z[~pos])
    result[~pos] = ex / (np.float32(1) + ex)
    return result

def affine32(inputs, weights, biases):
    weights = np.asarray(weights, dtype=np.float32)
    outputs = np.broadcast_to(np.asarray(biases, dtype=np.float32),
                              (inputs.shape[0], weights.shape[1])).copy()
    for j in range(inputs.shape[1]):
        outputs = np.asarray(outputs + inputs[:, j, None] * weights[j], dtype=np.float32)
    return outputs

def frozen_scores(model, raw):
    x = np.asarray(raw, dtype=np.float32)
    if model['kind'] == 'dt':
        # Traverse each subtree using a stack rather than the stage030 iterator.
        result = np.empty(len(x), dtype=np.float32)
        pending = [(0, np.arange(len(x)))]
        while pending:
            index, rows = pending.pop()
            node = model['nodes'][index]
            if node['feature'] < 0:
                result[rows] = np.float32(node['probability'])
            else:
                left = x[rows, node['feature']] <= np.float32(node['threshold'])
                if left.any(): pending.append((node['left'], rows[left]))
                if (~left).any(): pending.append((node['right'], rows[~left]))
        return result
    x = (np.log1p(x) - np.asarray(model['mean'], np.float32)) / np.asarray(model['scale'], np.float32)
    if model['kind'] == 'lr':
        z = affine32(x, np.asarray(model['weights'])[:, None], [model['bias']])
        return sigmoid32(z[:, 0])
    if model['kind'] == 'mlp_float':
        for i, layer in enumerate(model['layers']):
            x = affine32(x, layer['weights'], layer['bias'])
            if i != len(model['layers']) - 1: x = np.maximum(x, np.float32(0))
        return sigmoid32(x[:, 0])
    if model['kind'] == 'mlp_int8':
        scaled = np.asarray(x / np.float32(model['input_scale']), dtype=np.float32).astype(np.float64)
        q = np.clip(np.sign(scaled) * np.floor(np.abs(scaled) + 0.5), -127, 127).astype(np.int64)
        for i, layer in enumerate(model['layers']):
            accum = q @ np.asarray(layer['weights'], dtype=np.int64) + np.asarray(layer['bias'], dtype=np.int64)
            assert np.abs(accum).max() <= 2**31 - 1
            product = accum * layer['multiplier']
            shift = layer['shift']
            magnitude = (np.abs(product) + 2**(shift - 1)) // 2**shift
            q = np.clip(np.sign(product) * magnitude, -127, 127)
            if i != len(model['layers']) - 1: q = np.maximum(q, 0)
        return q[:, 0]
    raise ValueError(model['kind'])

def pretty_model(name):
    release, family = name.split('_', 1)
    return release + ' ' + LABELS[family]

def write_csv(path, rows):
    with path.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

def pct(value):
    return '---' if value is None else f'{100 * value:.3f}'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--training', type=Path,
                        default=HERE.parent/'evidence_inputs/training')
    parser.add_argument('--output', type=Path, default=HERE)
    args = parser.parse_args()
    src, out = args.training, args.output
    out.mkdir(parents=True, exist_ok=True)
    original = json.loads((src/'calibration.json').read_text())
    rows, source_hashes = [], {}
    for name in BASE_MODELS:
        model_path = src/'models'/f'{name}.json'
        sample_path = src/'samples'/f'{name[0]}_cal.npz'
        model = json.loads(model_path.read_text())
        with np.load(sample_path, allow_pickle=False) as data:
            scores = frozen_scores(model, data['raw'])
            labels = data['labels'].copy()
        integer = model['kind'] == 'mlp_int8'
        cut = int(model['q_threshold']) if integer else np.float32(model['threshold'])
        decisions = scores >= cut if integer else scores > cut
        normal, attack = labels == 0, labels == 1
        n0, n1 = int(normal.sum()), int(attack.sum())
        fp, tp = int(decisions[normal].sum()), int(decisions[attack].sum())
        boundary = cut - 1 if integer else cut
        tie_normal = int((scores[normal] == boundary).sum())
        tie_attack = int((scores[attack] == boundary).sum())
        allowed = math.floor(n0 * 0.01)
        original_row = original[name]
        assert fp/n0 == original_row['achieved_empirical_FPR'], name
        assert tp/n1 == original_row['attack_recall'], name
        assert n0 == original_row['normal_rows'] and n1 == original_row['attack_rows']
        assert fp <= allowed < fp + tie_normal, name
        row = dict(model=name, normal_rows=n0, attack_rows=n1,
                   allowed_false_positives=allowed, false_positives=fp,
                   true_positives=tp, empirical_FPR=fp/n0, attack_recall=tp/n1,
                   probability_threshold=model['threshold'],
                   integer_threshold_code=model.get('q_threshold'),
                   boundary_score=float(boundary), normal_tied_at_boundary=tie_normal,
                   attacks_tied_at_boundary=tie_attack,
                   normal_distinct_scores=int(len(np.unique(scores[normal]))),
                   all_distinct_scores=int(len(np.unique(scores))),
                   false_positives_if_boundary_ties_included=fp+tie_normal,
                   FPR_if_boundary_ties_included=(fp+tie_normal)/n0)
        rows.append(row)
        for path in (model_path, sample_path):
            source_hashes[str(path.relative_to(src))] = hashlib.sha256(path.read_bytes()).hexdigest()
    write_csv(out/'calibration_audit.csv', rows)
    audit = dict(status='complete', models_verified=8,
                 scope='Independent rescore of frozen calibration NPZ and exported models; no threshold changes.',
                 confidence_intervals_reported=False,
                 confidence_interval_reason='Thresholds were selected using these same normal scores and flow rows are not established independent Bernoulli trials. Ordinary fixed-threshold binomial intervals therefore do not establish future-FPR coverage.',
                 source_sha256=source_hashes, results=rows)
    (out/'calibration_audit.json').write_text(json.dumps(audit, indent=2)+'\n')
    table = [r'\begin{table}[H]', r'\caption{Frozen calibration operating points, recomputed from the stored samples. FP is the number of normal records predicted as attacks; TP is the number of detected attack records. The displayed probability threshold is rounded for readability. INT8 decisions use the exact integer code $q$ instead.}\label{tab:calibration}',
             r'\centering\small', r'\begin{tabular}{lrrrrr}', r'\toprule',
             r'Pipeline & FP / normal & FPR (\%) & TP / attacks & Recall (\%) & Threshold \\', r'\midrule']
    for row in rows:
        threshold = f"$q\\geq {row['integer_threshold_code']}$" if row['integer_threshold_code'] is not None else f"{row['probability_threshold']:.6f}"
        table.append(f"{pretty_model(row['model'])} & {row['false_positives']:,}/{row['normal_rows']:,} & {pct(row['empirical_FPR'])} & {row['true_positives']:,}/{row['attack_rows']:,} & {pct(row['attack_recall'])} & {threshold}" + r' \\')
    table += [r'\bottomrule', r'\end{tabular}', r'\end{table}']
    (out/'calibration_table.tex').write_text('\n'.join(table)+'\n')
    # Complete frozen aggregates, with confusion-cell consistency checks.
    for filename, dimension in [('by_day.json', 'day'), ('by_attack_type.json', 'traffic_type')]:
        content = json.loads((src/filename).read_text())
        source_hashes[filename] = hashlib.sha256((src/filename).read_bytes()).hexdigest()
        full_rows = []
        ordered_groups = sorted(content) if dimension == 'day' else [g for g in TYPE_ORDER if g in content]
        for group in ordered_groups:
            models = content[group]
            for name, result in models.items():
                cm = result['confusion_mass']
                tn, fp, fn, tp = (int(cm[0][0]), int(cm[0][1]), int(cm[1][0]), int(cm[1][1]))
                n0, n1 = tn+fp, fn+tp
                fpr = fp/n0 if n0 else None
                recall = tp/n1 if n1 else None
                assert fpr == result['FPR'] and recall == result['recall']
                full_rows.append({dimension: group, 'model': name, 'normal_rows': n0, 'attack_rows': n1,
                                  'TN': tn, 'FP': fp, 'FN': fn, 'TP': tp, 'recall': recall,
                                  'FPR': fpr, 'balanced_accuracy': result['balanced_accuracy'],
                                  'decision_disagreement_vs_B': result['decision_disagreement']})
        write_csv(out/f'{dimension}_all24.csv', full_rows)
        write_csv(out/f'{dimension}_completeAB.csv', [r for r in full_rows if r['model'] in BASE_MODELS])
    by_day = json.loads((src/'by_day.json').read_text())
    table = [r'\begin{longtable}{llrrr}', r'\caption{Daily row-weighted performance of all complete A and B pipelines. Values are percentages; BA denotes balanced accuracy.}\label{tab:daily-complete}\\',
             r'\toprule', r'Day (2019) & Pipeline & Recall & FPR & BA \\', r'\midrule', r'\endfirsthead',
             r'\toprule', r'Day (2019) & Pipeline & Recall & FPR & BA \\', r'\midrule', r'\endhead',
             r'\bottomrule', r'\endfoot']
    for day in sorted(by_day):
        models = by_day[day]
        for i, name in enumerate(BASE_MODELS):
            r = models[name]
            table.append(f"{day[5:] if i == 0 else ''} & {pretty_model(name)} & {pct(r['recall'])} & {pct(r['FPR'])} & {pct(r['balanced_accuracy'])}" + r' \\')
        table.append(r'\midrule')
    table += [r'\end{longtable}']
    (out/'daily_complete_table.tex').write_text('\n'.join(table)+'\n')
    types = json.loads((src/'by_attack_type.json').read_text())
    display_order = ['A_lr', 'B_lr', 'A_dt', 'B_dt', 'A_mlp_float', 'B_mlp_float', 'A_mlp_int8', 'B_mlp_int8']
    table = [r'\begin{table}[H]', r'\caption{Performance by traffic type for all complete pipelines. The normal row reports FPR; every attack row reports recall. All rates are row-weighted percentages. MITM denotes man-in-the-middle.}\label{tab:types-complete}',
             r'\centering\scriptsize\setlength{\tabcolsep}{3pt}', r'\begin{tabular}{lrrrrrrrrr}', r'\toprule',
             r'Type & Rows & LR A & LR B & DT A & DT B & MLP-F32 A & MLP-F32 B & MLP-I8 A & MLP-I8 B \\', r'\midrule']
    for kind in TYPE_ORDER:
        if kind not in types: continue
        models = types[kind]
        n = int(models['A_lr']['mass'])
        metric = 'FPR' if kind == 'normal' else 'recall'
        vals = ' & '.join(pct(models[name][metric]) for name in display_order)
        table.append(f'{TYPE_LABELS[kind]} & {n:,} & {vals}' + r' \\')
    table += [r'\bottomrule', r'\end{tabular}', r'\end{table}']
    (out/'attack_type_complete_table.tex').write_text('\n'.join(table)+'\n')
    (out/'source_sha256.json').write_text(json.dumps(source_hashes, indent=2)+'\n')
    print(json.dumps({'status':'complete','models_recomputed':len(rows),'output':str(out)}))

if __name__ == '__main__':
    main()
