#!/usr/bin/env python3
"""Independently recompute every calibration decision by scalar-neuron loops."""
import argparse
import json
from pathlib import Path
import numpy as np

HERE = Path(__file__).resolve().parent


def independent_predict(model, raw):
    x = (np.log1p(np.asarray(raw, np.float32)).astype(np.float32) -
         np.asarray(model['mean'], np.float32)) / np.asarray(model['scale'], np.float32)
    if model['kind'] == 'mlp_float':
        for index, layer in enumerate(model['layers']):
            weights = np.asarray(layer['weights'], np.float32)
            columns = []
            for j, bias in enumerate(layer['bias']):
                column = np.full(len(x), bias, np.float32)
                for i in range(x.shape[1]):
                    column = (column + x[:, i] * weights[i, j]).astype(np.float32)
                columns.append(column)
            x = np.stack(columns, axis=1)
            if index < 2:
                x = np.maximum(x, np.float32(0))
        z = x[:, 0]
        probability = np.empty(len(z), np.float32)
        positive = z >= 0
        probability[positive] = np.float32(1) / (np.float32(1) + np.exp(-z[positive]).astype(np.float32))
        exp_z = np.exp(z[~positive]).astype(np.float32)
        probability[~positive] = exp_z / (np.float32(1) + exp_z)
        return (probability > np.float32(model['threshold'])).astype(np.uint8)
    scaled = (x / np.float32(model['input_scale'])).astype(np.float32).astype(np.float64)
    q = np.clip(np.sign(scaled) * np.floor(np.abs(scaled) + .5), -127, 127).astype(np.int64)
    for index, layer in enumerate(model['layers']):
        columns = []
        for j, bias in enumerate(layer['bias']):
            accumulator = np.full(len(q), bias, np.int64)
            for i in range(q.shape[1]):
                accumulator += q[:, i] * int(layer['weights'][i][j])
            assert np.abs(accumulator).max() <= 2147483647
            multiplier = layer['multiplier'][j] if isinstance(layer['multiplier'], list) else layer['multiplier']
            shift = int(layer['shift'][j] if isinstance(layer['shift'], list) else layer['shift'])
            product = accumulator * int(multiplier)
            # Signed rounding via magnitude, implemented independently of
            # the original reference's vectorized sign expression.
            magnitude = (np.abs(product) + 2 ** (shift - 1)) // 2 ** shift
            rounded = np.where(product < 0, -magnitude, magnitude)
            code = np.clip(rounded, -127, 127)
            columns.append(np.maximum(code, 0) if index < 2 else code)
        q = np.stack(columns, axis=1)
    return (q[:, 0] >= int(model['q_threshold'])).astype(np.uint8)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=HERE.parents[1] / 'evidence_inputs/training')
    parser.add_argument('--exports', type=Path, default=HERE.parent / 'quantization')
    parser.add_argument('--previous-analysis', type=Path, default=HERE.parents[1] / 'new_analysis')
    args = parser.parse_args()
    raw = np.load(args.source / 'samples/B_cal.npz')['raw']
    preserved = np.load(HERE / 'frozen_predictions036.npz')
    paths = {
        'B_F32': args.source / 'models/B_mlp_float.json',
        'B_I8': args.source / 'models/B_mlp_int8.json',
        'maxabs_transferred': args.source / 'models/mlp_int8_compatible_requantized.json',
        'maxabs_recalibrated': args.previous_analysis / 'export_per_tensor_recalibrated.json',
        'per_channel_transferred': args.previous_analysis / 'export_per_channel_transferred.json',
        'per_channel_recalibrated': args.previous_analysis / 'export_per_channel_recalibrated.json',
        'percentile999_transferred': args.exports / 'percentile999_transferred.json',
        'percentile999_recalibrated': args.exports / 'percentile999_recalibrated.json',
    }
    for name, path in paths.items():
        independent = independent_predict(json.loads(path.read_text()), raw)
        assert np.array_equal(independent, preserved[name]), name
    results = json.loads((HERE / 'reference_comparison036.json').read_text())
    for pair in results['comparisons']:
        assert np.count_nonzero(preserved[pair['reference']] != preserved[pair['candidate']]) == pair['changed']
    print('PASS: independent neuron-wise evaluation agrees on all 102088 calibration rows for each of eight frozen models (816704 decisions); all 13 pairwise disagreement counts match.')


if __name__ == '__main__':
    main()
