"""Synthetic regression fixtures, not TON or hardware observations.

Original software author: Oleksandr Kuznetsov.
"""
from __future__ import annotations
import copy
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock
import numpy as np

HERE = Path(__file__).resolve().parents[1]
WORKSPACE = HERE.parent
ROOT = Path(os.environ.get('IDS043_KIT_ROOT', str(WORKSPACE / 'revision040-kit'))).resolve()
LEGACY = Path(os.environ.get('IDS042_RUNNER', str(WORKSPACE / 'recovery042/run_numerics042.py'))).resolve()

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result

n = module('supplement043_tested', HERE / 'numerics043.py')
old = module('recovery042_reference_tested', LEGACY)
ref, train, codec, qref = n.modules(ROOT)


def selected_models():
    all_models, _, _ = n.frozen_models(ROOT, ROOT / 'paper037/evidence_inputs/training')
    names = ['B_mlp_int8', 'B_mlp_float', 'mlp_int8_compatible_requantized', *n.PERCENTILES]
    models = {key: all_models[key] for key in names}
    for name in ('export_per_channel_transferred', 'export_per_channel_recalibrated', 'export_per_tensor_recalibrated'):
        path = ROOT / 'paper037/new_analysis' / (name + '.json')
        if n.load(path.parent / 'MANIFEST034.json')[path.name] != n.sha(path):
            raise ValueError('Test requires pinned real frozen artifact: ' + name)
        models[name] = n.load(path)
    return models


def fixture_db(path):
    rng = np.random.default_rng(43042)
    raw = np.vstack((np.zeros((1, 8)), [[0, 0, 0, 0, 1, 63, 0, 0]],
                     np.expm1(rng.uniform(0, 18, (62, 8))))).astype('<f4')
    frequencies = [255, 256, 453, 65536, 2**32+7] + list(range(6, 65))
    rows = []
    with sqlite3.connect(path) as db:
        db.executescript('CREATE TABLE vectors(key BLOB PRIMARY KEY,n0 INTEGER,n1 INTEGER); '
                         'CREATE TABLE groups(key BLOB,day TEXT,kind TEXT,label INTEGER,n INTEGER);')
        for i, (x, f) in enumerate(zip(raw, frequencies)):
            key = x.tobytes(); n0 = f; n1 = (i+1) * 3
            rows.append((key, n0, n1))
            db.execute('INSERT INTO vectors VALUES(?,?,?)', (key, n0, n1))
            db.executemany('INSERT INTO groups VALUES(?,?,?,?,?)', [
                (key, 'd1' if i%2 else 'd2', 'normal', 0, n0),
                (key, 'd1' if i%2 else 'd2', 'attack', 1, n1)])
    return raw, rows


class SupplementNumericsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.models = selected_models()

    def test_q22_is_existing_pinned_artifact_and_only_threshold_differs(self):
        m = copy.deepcopy(self.models['export_per_tensor_recalibrated'])
        baseline = copy.deepcopy(self.models['mlp_int8_compatible_requantized'])
        self.assertEqual(m['q_threshold'], 22)
        self.assertEqual(baseline['q_threshold'], 10)
        # The source artifacts may contain diagnostic metadata; compare the
        # actual inference fields, including every integer network parameter.
        for key in ('kind', 'input_scale', 'mean', 'scale', 'layers'):
            self.assertEqual(m[key], baseline[key])

    def test_preserves_all_seven042_metrics_with_large_frequencies(self):
        with tempfile.TemporaryDirectory() as t:
            db = Path(t) / 'fixture.sqlite'
            raw, rows = fixture_db(db)
            before = n.sha(db)
            seven = {k: v for k, v in self.models.items() if k != 'export_per_tensor_recalibrated'}
            expected = old.evaluate_cache(db, seven, ref, qref, chunk=17)
            actual = n.evaluate_cache(db, self.models, ref, qref, chunk=17)
            self.assertEqual(n.sha(db), before)
            self.assertEqual(actual['rows'], sum(a+b for _, a,b in rows))
            self.assertEqual(actual['unique_vectors'], len(raw))
            for field in ('weightings', 'by_day_rows', 'by_type_rows'):
                for group in expected[field]:
                    for name in seven:
                        self.assertEqual(actual[field][group][name], expected[field][group][name])
            for name in seven:
                if name in expected['clipping_on_unique_vectors']:
                    for tensor, counts in expected['clipping_on_unique_vectors'][name].items():
                        for key, value in counts.items():
                            self.assertEqual(actual['clipping_on_unique_vectors'][name][tensor][key], value)
            self.assertFalse(actual['thresholds_reselected'])
            self.assertIsNone(actual['confidence_intervals'])

    def test_effective_clipping_matches_trace_and_excludes_hidden_negative_tail(self):
        with tempfile.TemporaryDirectory() as t:
            db = Path(t) / 'fixture.sqlite'
            raw, _ = fixture_db(db)
            result = n.evaluate_cache(db, self.models, ref, qref, chunk=17)
            excluded_negative_tail = False
            for name, model in self.models.items():
                if not model['kind'].startswith('mlp_int8'):
                    continue
                _, traces = qref.trace(model, raw)
                for trace in traces:
                    got = result['clipping_on_unique_vectors'][name][trace['tensor']]
                    effective_elements = trace.get('effective_clipped_elements_after_relu', trace['clipped_elements'])
                    effective_rows = trace.get('effective_clipped_rows_after_relu', trace['rows_with_clipping'])
                    self.assertEqual(got['effective_clipped_elements_on_unique_vectors'], effective_elements)
                    self.assertEqual(got['unique_vectors_with_effective_clipping'], effective_rows)
                    self.assertLessEqual(effective_elements, got['clipped_elements_on_unique_vectors'])
                    if trace['tensor'] in ('input', 'layer_3'):
                        self.assertEqual(effective_elements, got['clipped_elements_on_unique_vectors'])
                    elif effective_elements < got['clipped_elements_on_unique_vectors']:
                        excluded_negative_tail = True
            self.assertTrue(excluded_negative_tail)

    def test_new_comparator_metrics_equal_independent_direct_row_counts(self):
        with tempfile.TemporaryDirectory() as t:
            db = Path(t) / 'fixture.sqlite'
            raw, rows = fixture_db(db)
            result = n.evaluate_cache(db, self.models, ref, qref, chunk=1)
            model = self.models['export_per_tensor_recalibrated']
            predictions = ref.predict(model, raw)[1]
            expected_fp = sum(n0 * int(y) for (_, n0, n1), y in zip(rows, predictions))
            expected_tp = sum(n1 * int(y) for (_, n0, n1), y in zip(rows, predictions))
            got = result['weightings']['rows']['export_per_tensor_recalibrated']
            self.assertEqual(got['FP_mass'], expected_fp)
            self.assertEqual(got['TP_mass'], expected_tp)

    def test_future_selects_eight_fixed_artifacts_and_records_extension(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / 'out'
            args = n.SimpleNamespace(root=ROOT, prior_run=ROOT / 'paper037/evidence_inputs/training',
                                     output=out, future_db=None, data_root=None)
            def evaluation(path, models, reference, quantizer):
                self.assertEqual(set(models), set(self.models))
                self.assertEqual(models, self.models)
                return {'rows': 7462871, 'unique_vectors': 3782505, 'synthetic_mock': True}
            with mock.patch.object(n, 'create_future_db', return_value=(Path(t)/'mock.sqlite', {'synthetic_mock': True})), \
                    mock.patch.object(n, 'evaluate_cache', side_effect=evaluation):
                summary = n.future(args)
            self.assertEqual(summary['stage'], '043')
            self.assertEqual(summary['models_evaluated'], 8)
            lock = n.load(out/'PROTOCOL_LOCK.json')
            self.assertEqual(lock['thresholds']['export_per_tensor_recalibrated']['q_threshold'], 22)
            self.assertFalse(lock['tuning_on_future'])
            self.assertIn('after reviewing042', lock['design_scope'])
            n.verify_directory(out)


if __name__ == '__main__':
    unittest.main()
