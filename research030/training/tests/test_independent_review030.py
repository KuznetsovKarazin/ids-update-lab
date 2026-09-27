"""Independent checks for temporal boundaries, sampling, calibration and metrics.

All records are synthetic test fixtures. These are software checks, not IDS
quality measurements and not evidence from the MCU.
"""
import copy
import csv
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import model030 as model
import run_training030 as run


def lr(bias):
    return {
        'kind': 'lr', 'mean': [0.] * 8, 'scale': [1.] * 8,
        'weights': [0., 1., 0., 0., 0., 0., 0., 0.],
        'bias': bias, 'threshold': .5,
    }


class IndependentReview(unittest.TestCase):
    def test_temporal_margin_and_flow_containment(self):
        protocol = json.loads((ROOT.parent / 'protocol/coverage_selection.json').read_text())
        bounds = run.effective_intervals(protocol)
        atomic = ('A_fit', 'A_cal', 'B_fit_added', 'B_cal', 'common_test')
        timestamps, durations, expected = [], [], []
        for role in atomic:
            lo, hi = bounds[role][0]
            # Exclude the right edge, and exclude a flow ending exactly there.
            for ts, dur, answer in [
                (lo, 0., role), (lo - 1., 0., None),
                (hi - 1., 0., role), (hi, 0., None),
                (hi - 1., 1., None), (hi - 2., 1., role),
            ]:
                timestamps.append(ts); durations.append(dur); expected.append(answer)
        actual = run.masks_for_intervals(np.array(timestamps), np.array(durations), bounds)
        for i, answer in enumerate(expected):
            matches = [r for r in atomic if actual[r][i]]
            self.assertEqual(matches, [] if answer is None else [answer])
        first = run.epoch(protocol['intervals']['A_fit'][0][0])
        last = run.epoch(protocol['intervals']['common_test'][0][1])
        self.assertEqual(bounds['A_fit'][0][0], first)
        self.assertEqual(bounds['common_test'][0][1], last)
        self.assertEqual(bounds['A_cal'][0][0] - bounds['A_fit'][0][1], 120.)

    def test_bottom_k_does_not_depend_on_chunk_order(self):
        ids = np.arange(1000, dtype=np.uint64)
        x = np.repeat(ids[:, None].astype(np.float32), 8, axis=1)
        a = run.BottomK(37); a.add(x, ids)
        b = run.BottomK(37)
        permutation = np.random.default_rng(41).permutation(len(ids))
        for batch in np.array_split(permutation, 17):
            b.add(x[batch], ids[batch])
        xa, ia = a.arrays(); xb, ib = b.arrays()
        np.testing.assert_array_equal(ia, ib)
        np.testing.assert_array_equal(xa, xb)
        self.assertEqual(a.n, 1000); self.assertEqual(b.n, 1000)

    def test_merging_local_bottom_k_preserves_global_bottom_k(self):
        ids = np.arange(1500, dtype=np.uint64)
        x = np.repeat(ids[:, None].astype(np.float32), 8, axis=1)
        a = run.BottomK(53); a.add(x[:1000], ids[:1000])
        b = run.BottomK(53); b.add(x[1000:], ids[1000:])
        merged = run.BottomK(53)
        for child in (a, b): merged.add(*child.arrays())
        global_ = run.BottomK(53); global_.add(x, ids)
        np.testing.assert_array_equal(merged.arrays()[1], global_.arrays()[1])

    def test_float_calibration_ties_and_saturation(self):
        x = np.zeros((200, 8), np.float32)
        labels = np.array([0] * 100 + [1] * 100)
        for bias in (0., 80., -80.):
            m = lr(bias)
            report = model.calibrate(m, x, labels)
            probabilities, decisions = model.predict(m, x)
            self.assertTrue(np.isfinite(m['threshold']))
            self.assertLessEqual(m['threshold'], 1.)
            self.assertGreaterEqual(m['threshold'], 0.)
            self.assertEqual(report['achieved_empirical_FPR'], 0.)
            self.assertFalse(decisions.any())
            self.assertEqual(m['threshold'], float(probabilities[0]))

    def test_integer_threshold_transfer_preserves_units_and_endpoints(self):
        source = {'q_threshold': 20, 'layers': [{'output_scale': .5}]}
        target = {'layers': [{'output_scale': 2.}]}
        self.assertEqual(model.transfer_qthreshold(source, target), 5)
        source['q_threshold'] = 128
        self.assertEqual(model.transfer_qthreshold(source, target), 128)
        source['q_threshold'] = -127
        self.assertEqual(model.transfer_qthreshold(source, target), -127)
        for scale in (.125, float(np.float32(.0037)), float(np.float32(7.91))):
            target['layers'][0]['output_scale'] = scale
            source['layers'][0]['output_scale'] = scale
            for cut in range(-127, 129):
                source['q_threshold'] = cut
                self.assertEqual(model.transfer_qthreshold(source, target), cut)

    def test_grouped_metrics_equal_explicit_weighted_rows(self):
        models = {'A_lr': lr(-2.), 'B_lr': lr(-1.)}
        records = []
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            for child in ('models', 'hardware_vectors'): (out / child).mkdir()
            for name, m in models.items(): run.dump(out / 'models' / (name + '.json'), m)
            db = sqlite3.connect(out / 'test_vectors.sqlite')
            db.executescript(
                'CREATE TABLE vectors(key BLOB PRIMARY KEY,n0 INTEGER,n1 INTEGER);'
                'CREATE TABLE groups(key BLOB,day TEXT,kind TEXT,label INTEGER,n INTEGER);'
                'CREATE TABLE exposure(key BLOB PRIMARY KEY,mask INTEGER);'
            )
            for index in range(25):
                x = np.zeros(8, dtype='<f4'); x[1] = index
                n0, n1 = index + 1, 5 * (index + 1)
                day = '2019-04-26' if index % 2 == 0 else '2019-04-27'
                kind = ('scanning', 'ddos', 'password')[index % 3]
                db.execute('INSERT INTO vectors VALUES(?,?,?)', (x.tobytes(), n0, n1))
                if index < 15:
                    db.execute('INSERT INTO exposure VALUES(?,?)', (x.tobytes(), 1 if index < 10 else 2))
                db.executemany('INSERT INTO groups VALUES(?,?,?,?,?)', [
                    (x.tobytes(), day, 'normal', 0, n0),
                    (x.tobytes(), day, kind, 1, n1),
                ])
                records.append((x, n0, n1, index, kind))
            db.commit(); db.close()
            support = {
                'A_fit': {'types': {'normal': 100, 'scanning': 100}},
                'A_cal': {'types': {'normal': 100, 'scanning': 100}},
                'B_fit_added': {'types': {'normal': 100, 'ddos': 100}},
                'B_cal': {'types': {'normal': 100, 'ddos': 100}},
            }
            result = run.evaluate(models, support, out)
            report = json.loads((out / 'evaluation.json').read_text())
            self.assertEqual(result['test_rows'], 1950)
            self.assertEqual(result['test_unique_vectors'], 25)
            self.assertTrue(result['CI_suppressed'])
            for cohort in ('all', 'top20', 'remainder', 'seen_fit_vector', 'unseen_fit_vector',
                           'seen_fit_or_cal_vector', 'unseen_fit_or_cal_vector'):
                for weighting in ('rows', 'vector_balanced', 'frequency_cap100'):
                    for name, m in models.items():
                        expected = np.zeros(5)
                        for x, n0, n1, index, kind in records:
                            if cohort == 'top20' and index < 5: continue
                            if cohort == 'remainder' and index >= 5: continue
                            if cohort == 'seen_fit_vector' and index >= 10: continue
                            if cohort == 'unseen_fit_vector' and index < 10: continue
                            if cohort == 'seen_fit_or_cal_vector' and index >= 15: continue
                            if cohort == 'unseen_fit_or_cal_vector' and index < 15: continue
                            label = int(model.predict(m, x[None])[1][0])
                            ref = int(model.predict(models['B_lr'], x[None])[1][0])
                            n = n0 + n1
                            coefficient = (1. if weighting == 'rows' else
                                           1. / n if weighting == 'vector_balanced' else
                                           min(n, 100) / n)
                            expected[label] += n0 * coefficient
                            expected[2 + label] += n1 * coefficient
                            expected[4] += n * coefficient * (label != ref)
                        actual = report['cohorts'][cohort][weighting][name]
                        np.testing.assert_allclose(np.asarray(actual['confusion_mass']).ravel(), expected[:4])
                        self.assertAlmostEqual(actual['mass'], expected[:4].sum())
                        self.assertAlmostEqual(actual['decision_disagreement'], expected[4] / expected[:4].sum())

    def test_csv_preparation_keeps_calibration_and_test_out_of_fit(self):
        protocol = json.loads((ROOT.parent / 'protocol/coverage_selection.json').read_text())
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp); (out / 'samples').mkdir()
            path = out / 'synthetic_fixture.csv'
            rows = []
            attack_types = {'A_fit': 'scanning', 'A_cal': 'injection',
                            'B_fit_added': 'ddos', 'B_cal': 'ddos', 'common_test': 'password'}
            expected_ids = {}
            for role in run.ROLES:
                ts = run.epoch(protocol['intervals'][role][0][0]) + 120.
                expected_ids[role] = []
                for label in (0, 0, 1, 1):
                    row_id = len(rows); expected_ids[role].append(row_id)
                    x = [0., float(row_id + 1)] + [0.] * 6
                    rows.append(x + [ts, label, 'normal' if label == 0 else attack_types[role]])
            a_end = run.epoch(protocol['intervals']['A_fit'][0][1])
            # Valid features, but a flow crossing the effective upper bound.
            rows.append([120., 90.] + [0.] * 6 + [a_end - 90., 0, 'normal'])
            # Valid features with an event in the temporal guard interval.
            rows.append([0., 91.] + [0.] * 6 + [a_end, 0, 'normal'])
            # Non-numeric timestamp and negative duration underflowing to float32 -0.
            rows.append([0., 92.] + [0.] * 6 + ['invalid-time', 0, 'normal'])
            rows.append(['-1e-60', 93.] + [0.] * 6 + [a_end - 120., 0, 'normal'])
            with path.open('w', newline='') as f:
                writer = csv.writer(f); writer.writerow(model.FEATURES + ['ts', 'label', 'type']); writer.writerows(rows)
            stat = path.stat()
            source = {'path': str(path), 'file': path.name, 'ordinal': 0,
                      'bytes': stat.st_size, 'mtime_ns': stat.st_mtime_ns}
            arrays, support = run.prepare_data([source], protocol, out, subset=True)
            for role in run.ROLES:
                self.assertEqual(support[role]['class_counts'], [2, 2])
            ids = {}
            for role in ('A_fit', 'B_fit', 'A_cal', 'B_cal'):
                with np.load(out / 'samples' / (role + '.npz'), allow_pickle=False) as data:
                    ids[role] = set(map(int, data['row_ids']))
            self.assertEqual(ids['A_fit'], set(expected_ids['A_fit']))
            self.assertEqual(ids['B_fit'], set(expected_ids['A_fit'] + expected_ids['B_fit_added']))
            for role in ('A_cal', 'B_cal'):
                self.assertFalse(ids[role] & ids['A_fit']); self.assertFalse(ids[role] & ids['B_fit'])
            self.assertFalse(set(expected_ids['common_test']) & ids['B_fit'])
            summary = json.loads((out / 'temporal_support_after_purge.json').read_text())
            totals = summary['source_totals']
            self.assertEqual(totals['invalid_flow_metadata_with_valid_raw'], 2)
            self.assertEqual(totals['boundary_time_margin_excluded'], 1)
            self.assertEqual(totals['flow_crossing_effective_end_excluded'], 1)


if __name__ == '__main__': unittest.main()
