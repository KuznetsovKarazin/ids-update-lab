#!/usr/bin/env python3
"""One fixed posthoc percentile quantizer; see POSTHOC_PLAN035.md.

This executable never changes frozen models or calibration samples. It exports
two additional host-only models with the same scalar-Q31 numerical contract.
"""
from __future__ import annotations
import argparse
import copy
import csv
import hashlib
import json
import math
import sys
from pathlib import Path
import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vendor'))
import model030 as ref
DEFAULT_SOURCE = HERE.parents[1] / 'evidence_inputs' / 'training'
TARGET = np.array([[0, 0, 0, 0, 1, 63, 0, 0]], np.float32)


def load(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extent(values, mode):
    absolute = np.abs(np.asarray(values, np.float32)).ravel()
    if mode == 'maxabs':
        return float(np.max(absolute, initial=0))
    if mode == 'percentile999':
        return float(np.percentile(absolute, 99.9, method='linear'))
    raise ValueError(mode)


def quantize(model, fit_raw, mode):
    """Original arithmetic with one explicit change to activation extents."""
    result = copy.deepcopy(model)
    result['kind'] = 'mlp_int8'
    result['q_threshold'] = 0
    x = ref.preprocess(model, fit_raw)
    sx = np.float32(max(extent(x, mode) / 127., 1e-8))
    result['input_scale'] = float(sx)
    ranges = [{'tensor': 'input', 'extent': extent(x, mode),
               'max_absolute': extent(x, 'maxabs'), 'scale': float(sx)}]
    layers = []
    for index, layer in enumerate(model['layers']):
        w = np.asarray(layer['weights'], np.float32)
        b = np.asarray(layer['bias'], np.float32)
        sw = np.float32(max(float(np.max(np.abs(w), initial=0)) / 127., 1e-8))
        y = ref.dense(x, w, b)
        if index < 2:
            y = np.maximum(y, np.float32(0))
        sy = np.float32(max(extent(y, mode) / 127., 1e-8))
        qw = np.clip(ref.round_away(w / sw), -127, 127).astype(np.int64)
        qb = ref.round_away(b / np.float32(sx * sw)).astype(np.int64)
        bound = np.abs(qb) + 127 * np.abs(qw).sum(axis=0)
        if np.any(bound > 2147483647):
            raise ValueError('Analytic int32 accumulator bound exceeded')
        mantissa, exponent = math.frexp(float(sx) * float(sw) / float(sy))
        multiplier = int(ref.round_away(mantissa * (1 << 31)))
        if multiplier == (1 << 31):
            multiplier >>= 1
            exponent += 1
        shift = 31 - exponent
        if not 1 <= shift <= 62:
            raise ValueError('Unsupported shift')
        # Include rounding offset, not just signed product, in this bound.
        product_bound = max(int(v) for v in bound) * multiplier
        if product_bound + (1 << (shift - 1)) > np.iinfo(np.int64).max:
            raise ValueError('Analytic int64 product/rounding bound exceeded')
        layers.append({'weights': qw.tolist(), 'bias': qb.tolist(),
                       'multiplier': multiplier, 'shift': shift,
                       'weight_scale': float(sw), 'output_scale': float(sy)})
        ranges.append({'tensor': f'layer_{index + 1}', 'extent': extent(y, mode),
                       'max_absolute': extent(y, 'maxabs'), 'scale': float(sy),
                       'accumulator_abs_bound': int(bound.max()),
                       'product_abs_bound': product_bound})
        x, sx = y, sy
    result['layers'] = layers
    result['quantization'] = {
        'weights': 'symmetric int8; per-tensor maximum absolute weight',
        'activation': 'symmetric int8; hidden ReLU; scalar layer grids',
        'range_source': 'B_fit only; absolute flattened float32 activations',
        'activation_range_rule': mode,
        'percentile': 99.9 if mode == 'percentile999' else None,
        'percentile_method': 'numpy linear' if mode == 'percentile999' else None,
        'rounding': 'nearest ties away from zero',
        'accumulator': 'int32 bounded; int64 Q31 product and rounding',
        'output': 'signed int8 logit; q_threshold may be 128'}
    result['host_only_diagnostic'] = True
    return result, ranges


def clip_count(codes):
    clipped = (codes < -127) | (codes > 127)
    return {'elements': int(codes.size), 'clipped_elements': int(clipped.sum()),
            'clipped_fraction': float(clipped.mean()),
            'rows_with_clipping': int(clipped.any(axis=1).sum()),
            'unclipped_code_min': int(codes.min()),
            'unclipped_code_max': int(codes.max())}


def trace(model, raw, keep_codes=False):
    x = ref.preprocess(model, raw)
    unbounded = ref.round_away(np.asarray(x / np.float32(model['input_scale']), np.float32))
    q = np.clip(unbounded, -127, 127).astype(np.int64)
    tensors = [{'tensor': 'input', **clip_count(unbounded),
                **({'codes': q.tolist(), 'float_values': x.tolist()} if keep_codes else {})}]
    for index, layer in enumerate(model['layers']):
        accumulator = q @ np.asarray(layer['weights'], np.int64) + np.asarray(layer['bias'], np.int64)
        if np.max(np.abs(accumulator), initial=0) > 2147483647:
            raise ValueError('Observed int32 overflow')
        if isinstance(layer['multiplier'], list):
            unbounded = np.column_stack([
                ref.round_shift_away(accumulator[:, k] * int(multiplier), int(shift))
                for k, (multiplier, shift) in enumerate(zip(layer['multiplier'], layer['shift']))])
        else:
            unbounded = ref.round_shift_away(accumulator * int(layer['multiplier']), int(layer['shift']))
        q = np.clip(unbounded, -127, 127)
        if index < 2:
            q = np.maximum(q, 0)
        effective_clipping = (unbounded > 127) | ((unbounded < -127) & (index == 2))
        tensors.append({'tensor': f'layer_{index + 1}', **clip_count(unbounded),
                        'effective_clipped_elements_after_relu': int(effective_clipping.sum()),
                        'effective_clipped_rows_after_relu': int(effective_clipping.any(axis=1).sum()),
                        'max_abs_accumulator': int(np.abs(accumulator).max()),
                        **({'codes': q.tolist(), 'accumulator': accumulator.tolist()} if keep_codes else {})})
    return q[:, 0], tensors


def predict(model, raw):
    if model['kind'] == 'mlp_int8':
        return ref.predict(model, raw, True)
    if model['kind'] != 'mlp_int8_per_channel':
        raise ValueError(model['kind'])
    score, _ = trace(model, raw)
    probability = ref.sigmoid(np.asarray(score, np.float32) * np.float32(model['layers'][-1]['output_scale']))
    decision = (score >= int(model['q_threshold'])).astype(np.uint8)
    return probability, decision, score


def metrics(pred, labels, weights):
    normal = labels == 0
    attack = labels == 1
    return {'FPR': float(np.sum(weights[normal] * pred[normal]) / weights[normal].sum()),
            'recall': float(np.sum(weights[attack] * pred[attack]) / weights[attack].sum())}


def recalibrate(model, raw, labels):
    result = copy.deepcopy(model)
    ref.calibrate(result, raw, labels, .01)
    return result


def numerical_fields(model):
    return {'input_scale': model['input_scale'], 'layers': model['layers']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=DEFAULT_SOURCE)
    parser.add_argument('--output', type=Path, default=HERE)
    parser.add_argument('--previous-analysis', type=Path, default=HERE.parents[1] / 'new_analysis')
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    fit = np.load(source / 'samples/B_fit.npz')
    cal = np.load(source / 'samples/B_cal.npz')
    raw, labels = cal['raw'], cal['labels']
    original = load(source / 'models/B_mlp_int8.json')
    float_model = load(source / 'models/mlp_float_compatible_first_layer.json')
    frozen = load(source / 'models/mlp_int8_compatible_requantized.json')
    gold = load(source / 'hardware_vectors/B_mlp_int8.json')
    check_raw = np.asarray(gold['raw'], np.float32)
    maxabs, maxabs_ranges = quantize(float_model, fit['raw'], 'maxabs')
    ref_maxabs = ref.quantize(float_model, fit['raw'])
    assert numerical_fields(maxabs) == numerical_fields(ref_maxabs), 'Maxabs algorithm differs from frozen reference'
    exact_reproduction = numerical_fields(maxabs) == numerical_fields(frozen)
    reproduction_differences = {}
    if maxabs['input_scale'] != frozen['input_scale']:
        reproduction_differences['input_scale'] = {
            'recomputed': maxabs['input_scale'], 'frozen': frozen['input_scale']}
    for index, (recomputed_layer, frozen_layer) in enumerate(zip(maxabs['layers'], frozen['layers'])):
        for key, value in recomputed_layer.items():
            if value != frozen_layer[key]:
                reproduction_differences[f'layer_{index + 1}.{key}'] = {
                    'recomputed': value, 'frozen': frozen_layer[key]}
    # Keep the original baseline immutable even if host floating-point range
    # recomputation differs slightly from its historical numerical artifact.
    maxabs_score_reproduction = {}
    for name, values in [('B_fit', fit['raw']), ('B_cal', raw), ('check258', check_raw), ('target', TARGET)]:
        _, _, reconstructed_codes = ref.predict(maxabs, values, True)
        _, _, frozen_codes = ref.predict(frozen, values, True)
        maxabs_score_reproduction[name] = {'n': len(values),
            'different_codes': int((reconstructed_codes != frozen_codes).sum()),
            'different_decisions_at_frozen_cut': int(((reconstructed_codes >= frozen['q_threshold']) != (frozen_codes >= frozen['q_threshold'])).sum())}
    candidate, candidate_ranges = quantize(float_model, fit['raw'], 'percentile999')
    candidate['q_threshold'] = ref.transfer_qthreshold(original, candidate)
    candidate['threshold'] = original['threshold']
    variants = {
        'B_original': original,
        'maxabs_transferred': frozen,
        'maxabs_recalibrated': recalibrate(frozen, raw, labels),
        'per_channel_transferred': load(args.previous_analysis / 'export_per_channel_transferred.json'),
        'per_channel_recalibrated': load(args.previous_analysis / 'export_per_channel_recalibrated.json'),
        'percentile999_transferred': candidate,
        'percentile999_recalibrated': recalibrate(candidate, raw, labels)}
    _, base_decision, _ = ref.predict(original, raw, True)
    _, base_check, _ = ref.predict(original, check_raw, True)
    unique, inverse, counts = np.unique(np.asarray(raw, np.float32), axis=0, return_inverse=True, return_counts=True)
    vector_weights = 1. / counts[inverse]
    target_mask = np.all(raw == TARGET[0], axis=1)
    rows, traces, saturation, tails = [], {}, {}, {}
    for name, model in variants.items():
        _, pred, code = predict(model, raw)
        _, check_pred, _ = predict(model, check_raw)
        row_metrics = metrics(pred, labels, np.ones(len(raw)))
        vector_metrics = metrics(pred, labels, vector_weights)
        changed = pred != base_decision
        record = {'variant': name, 'q_threshold': int(model['q_threshold']),
                  'input_scale': model['input_scale'],
                  'output_scale': model['layers'][-1]['output_scale'],
                  'normal_n': int((labels == 0).sum()), 'attack_n': int((labels == 1).sum()),
                  'false_positives': int(pred[labels == 0].sum()),
                  'true_positives': int(pred[labels == 1].sum()),
                  'calibration_FPR': row_metrics['FPR'], 'calibration_recall': row_metrics['recall'],
                  'equal_vector_FPR': vector_metrics['FPR'], 'equal_vector_recall': vector_metrics['recall'],
                  'changed_vs_B': int(changed.sum()), 'row_changed_fraction': float(changed.mean()),
                  'equal_vector_changed_fraction': float(np.sum(vector_weights * changed) / vector_weights.sum()),
                  'check_n': len(check_raw), 'check_changed_vs_B': int((check_pred != base_check).sum())}
        rows.append(record)
        p, target_pred, target_code = predict(model, TARGET)
        traced, tensors = trace(model, TARGET, True)
        assert np.array_equal(traced, target_code)
        traces[name] = {'raw': TARGET[0].tolist(), 'probability': float(p[0]),
                        'decision': int(target_pred[0]), 'code': int(target_code[0]),
                        'threshold_code': int(model['q_threshold']),
                        'dequantized_logit': float(target_code[0]) * model['layers'][-1]['output_scale'],
                        'tensors': tensors}
        for split_name, split_raw in [('B_fit', fit['raw']), ('B_cal', raw)]:
            traced, tensors = trace(model, split_raw)
            _, _, predicted = predict(model, split_raw)
            assert np.array_equal(traced, predicted), 'Trace/reference integer score mismatch'
            saturation[f'{name}:{split_name}'] = tensors
        tails[name] = {str(int(v)): {'normal': int(((code == v) & (labels == 0)).sum()),
                                   'attack': int(((code == v) & (labels == 1)).sum())}
                       for v in np.unique(code)}
        if name.startswith('percentile'):
            (output / f'{name}.json').write_text(json.dumps(model, indent=2) + '\n')
    files = [source / p for p in ['samples/B_fit.npz', 'samples/B_cal.npz',
             'models/B_mlp_int8.json', 'models/mlp_float_compatible_first_layer.json',
             'models/mlp_int8_compatible_requantized.json', 'hardware_vectors/B_mlp_int8.json']]
    result = {'analysis': 'posthoc_host_only_fixed_99.9_percentile',
              'full_test_evaluated': False, 'new_hardware_evaluated': False,
              'calibration_scope': 'resubstitution diagnostics; thresholds selected using normal B_cal rows',
              'percentile': 99.9, 'percentile_method': 'linear',
              'activation_ranges_source': 'B_fit only; float-network activations flattened across rows/channels',
              'weight_grid': 'per-tensor maxabs, unchanged rule',
              'maxabs_reproduces_reference_numeric_fields': True,
              'maxabs_reproduces_frozen_export_numeric_fields': exact_reproduction,
              'maxabs_recomputed_vs_frozen_field_differences': reproduction_differences,
              'maxabs_recomputed_vs_frozen_score_differences': maxabs_score_reproduction,
              'fitting_rows': len(fit['raw']), 'calibration_rows': len(raw),
              'calibration_unique_vectors': len(unique),
              'equal_vector_definition': 'each raw float32 vector total weight one; labels retain within-vector proportions',
              'equal_vector_normal_mass': float(vector_weights[labels == 0].sum()),
              'equal_vector_attack_mass': float(vector_weights[labels == 1].sum()),
              'check_vector_selection': gold['selection'],
              'target_calibration_occurrences': {'normal': int((target_mask & (labels == 0)).sum()),
                                                 'attack': int((target_mask & (labels == 1)).sum())},
              'ranges': {'maxabs': maxabs_ranges, 'percentile999': candidate_ranges},
              'rows': rows, 'target_vector': traces,
              'saturation': saturation, 'score_histograms': tails,
              'source_sha256': {str(path.relative_to(source)): sha(path) for path in files},
              'previous_analysis_sha256': {name: sha(args.previous_analysis / name) for name in
                  ['export_per_channel_transferred.json', 'export_per_channel_recalibrated.json']},
              'implementation_sha256': {'analyze_percentile035.py': sha(Path(__file__)),
                                        'vendor/model030.py': sha(HERE / 'vendor/model030.py'),
                                        'POSTHOC_PLAN035.md': sha(HERE / 'POSTHOC_PLAN035.md')},
              'numpy_version': np.__version__, 'python_version': sys.version}
    (output / 'percentile_diagnostics035.json').write_text(json.dumps(result, indent=2) + '\n')
    with (output / 'percentile_metrics035.csv').open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps({'output': str(output), 'rows': rows,
                      'target': {name: {k: value[k] for k in ['code', 'threshold_code', 'decision']}
                                 for name, value in traces.items()}}, indent=2))


if __name__ == '__main__':
    main()
