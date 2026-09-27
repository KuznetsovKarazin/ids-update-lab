"""Meaningful host numerical checks; no new IDS quality or MCU experiment."""
import copy
import importlib.util
from pathlib import Path
import numpy as np
import analyze_percentile035 as a


def test_percentile_and_rounding_contract():
    # Deliberately unsorted vector with noninteger 99.9th order interpolation.
    x = np.array([-10., 0., 1., 2.], np.float32)
    expected = 2. + .997 * (10. - 2.)
    # np.percentile retains float32 interpolation in the pinned NumPy version.
    assert abs(a.extent(x, 'percentile999') - expected) <= 2 * float(np.spacing(np.float32(expected)))
    assert a.extent(x, 'maxabs') == 10.
    assert np.array_equal(a.ref.round_away([-1.5, -.5, .5, 1.5]), [-2, -1, 1, 2])
    assert np.array_equal(a.ref.round_shift_away(np.array([-3, -1, 1, 3]), 1), [-2, -1, 1, 2])


def test_maxabs_reduction_and_scalar_implementation():
    source = a.DEFAULT_SOURCE
    float_model = a.load(source / 'models/mlp_float_compatible_first_layer.json')
    fit = np.load(source / 'samples/B_fit.npz')['raw']
    ours, _ = a.quantize(float_model, fit, 'maxabs')
    original = a.ref.quantize(float_model, fit)
    assert a.numerical_fields(ours) == a.numerical_fields(original)
    candidate = a.load(a.HERE / 'percentile999_transferred.json')
    rng = np.random.default_rng(3501)
    inputs = np.exp(rng.uniform(-20, 30, (1024, 8))).astype(np.float32)
    inputs[0] = 0
    inputs[1] = np.finfo(np.float32).max / 2
    # Independently execute one input/neuron at a time with Python integers;
    # this avoids NumPy matrix accumulation and its fixed-width overflow.
    def scalar_score(model, raw):
        z = a.ref.preprocess(model, raw[None, :])[0]
        def rounded(value):
            return (1 if value >= 0 else -1) * int(np.floor(abs(float(value)) + .5))
        def clip(value):
            return max(-127, min(127, value))
        q = [clip(rounded(np.float32(v / np.float32(model['input_scale'])))) for v in z]
        for index, layer in enumerate(model['layers']):
            updated = []
            for j, bias in enumerate(layer['bias']):
                accumulator = int(bias) + sum(int(q[i]) * int(layer['weights'][i][j]) for i in range(len(q)))
                assert abs(accumulator) <= 2147483647
                value = accumulator * int(layer['multiplier'])
                shift = int(layer['shift'])
                rounded_value = (1 if value >= 0 else -1) * ((abs(value) + (1 << (shift - 1))) >> shift)
                code = clip(rounded_value)
                updated.append(max(code, 0) if index < 2 else code)
            q = updated
        return q[0]
    expected = np.array([scalar_score(candidate, row) for row in inputs])
    _, _, actual = a.ref.predict(candidate, inputs, True)
    assert np.array_equal(actual, expected)


def test_calibration_cut_and_frozen_control_counts():
    cal = np.load(a.DEFAULT_SOURCE / 'samples/B_cal.npz')
    result = a.load(a.HERE / 'percentile_diagnostics035.json')
    for name in ['percentile999_transferred', 'percentile999_recalibrated']:
        model = a.load(a.HERE / f'{name}.json')
        _, labels, codes = a.ref.predict(model, cal['raw'], True)
        row = next(v for v in result['rows'] if v['variant'] == name)
        assert labels[cal['labels'] == 0].sum() == row['false_positives']
        assert labels[cal['labels'] == 1].sum() == row['true_positives']
        if name.endswith('recalibrated'):
            normal = codes[cal['labels'] == 0]
            allowed = int(np.floor(.01 * len(normal)))
            assert (normal >= model['q_threshold']).sum() <= allowed
            assert (normal >= model['q_threshold'] - 1).sum() > allowed
    # Existing per-channel code is checked against its independent 034 path.
    old_path = a.HERE.parents[1] / 'new_analysis/analyze_export034.py'
    spec = importlib.util.spec_from_file_location('old034', old_path)
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    for name in ['per_channel_transferred', 'per_channel_recalibrated']:
        model = a.load(a.HERE.parents[1] / 'new_analysis' / f'export_{name}.json')
        p, labels, codes = a.predict(model, cal['raw'])
        old_p, old_labels, old_codes = old.predq(model, cal['raw'])
        assert np.array_equal(p, old_p) and np.array_equal(labels, old_labels) and np.array_equal(codes, old_codes)


if __name__ == '__main__':
    test_percentile_and_rounding_contract()
    test_maxabs_reduction_and_scalar_implementation()
    test_calibration_cut_and_frozen_control_counts()
    print('PASS: percentile interpolation, ties-away rounding, maxabs algorithm reduction, 1024 broad-range independent scalar integer scores, calibration minimal cutoff, and inherited per-channel controls.')
