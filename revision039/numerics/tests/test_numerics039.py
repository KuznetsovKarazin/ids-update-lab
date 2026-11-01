"""Independent software checks; synthetic fixtures are not scientific results.

Original software author: Oleksandr Kuznetsov.
"""
import copy
import importlib.util
import json
from pathlib import Path
import sqlite3
import shutil
import sys
import tempfile
import unittest
import numpy as np

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / 'revision039/numerics/run_numerics039.py'
spec = importlib.util.spec_from_file_location('numerics039_tested', SCRIPT)
n = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = n
spec.loader.exec_module(n)
ref, train, codec, qref = n.modules(ROOT)


def fixtures():
    rng = np.random.default_rng(39)
    raw = np.expm1(rng.uniform(0, 12, (3000, 8))).astype(np.float32)
    models = {}
    for family in ('lr', 'dt', 'mlp_float'):
        m = codec.bootstrap(family)
        if family == 'lr':
            m.update(weights=[.1, -.1, .2, -.2, .3, -.3, .4, -.4], bias=0.)
        elif family == 'dt':
            m['nodes'] = [{'feature': 3, 'left': 1, 'right': 2, 'threshold': 50., 'probability': .5},
                          {'feature': -1, 'left': -1, 'right': -1, 'threshold': 0., 'probability': .1},
                          {'feature': -1, 'left': -1, 'right': -1, 'threshold': 0., 'probability': .9}]
        else:
            for layer in m['layers']:
                layer['weights'] = rng.normal(0, .2, np.asarray(layer['weights']).shape).astype(np.float32).tolist()
                layer['bias'] = rng.normal(0, .1, len(layer['bias'])).astype(np.float32).tolist()
        models['B_' + family] = m
    models['B_mlp_int8'] = ref.quantize(models['B_mlp_float'], raw)
    pool = [(x, {'data_origin': 'synthetic_software_fixture', 'role': 'B_cal', 'label': i % 2, 'source_row_id': i}) for i, x in enumerate(raw)]
    return models, pool


class NumericalKitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.models, cls.pool = fixtures()

    def test_panel_unique_all_features_and_old_exclusion(self):
        old = [self.pool[0][0], np.zeros(8, np.float32)]
        rows, coverage = n.make_panel(self.models, self.pool, ref, old)
        raw = np.asarray([r['raw'] for r in rows], '<f4')
        self.assertEqual(raw.shape, (1024, 8))
        self.assertEqual(len({x.tobytes() for x in raw}), 1024)
        self.assertNotIn(old[0].tobytes(), {x.tobytes() for x in raw})
        self.assertTrue(np.isfinite(raw).all())
        self.assertTrue((raw >= 0).all())
        self.assertTrue(all(x > 50 for x in coverage['feature_distinct_counts']))
        self.assertTrue(coverage['recurring_template_in_additional_panel'])
        self.assertFalse(coverage['universal_equivalence_proved'])

    def test_panel_is_deterministic_and_model_fields_unchanged(self):
        before = json.dumps(self.models, sort_keys=True)
        a, _ = n.make_panel(self.models, self.pool, ref)
        b, _ = n.make_panel(self.models, self.pool, ref)
        self.assertEqual(a, b)
        self.assertEqual(json.dumps(self.models, sort_keys=True), before)

    def test_invalid_inputs_and_signed_zero(self):
        for value in (-1., float('inf'), float('nan')):
            with self.assertRaises(ValueError):
                n.canonical([value] + [0.] * 7)
        self.assertEqual(n.canonical([-0.] * 8).tobytes(), np.zeros(8, '<f4').tobytes())

    def test_manifest_rejects_tamper(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            n.save(path / 'x.json', {'immutable': True})
            n.pin_directory(path)
            n.verify_directory(path)
            n.save(path / 'x.json', {'immutable': False})
            with self.assertRaises(ValueError):
                n.verify_directory(path)

    def test_conflicting_label_frequency_weights_and_two_references(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'data.sqlite'
            x, y = np.zeros(8, '<f4').tobytes(), np.ones(8, '<f4').tobytes()
            with sqlite3.connect(path) as db:
                db.executescript('CREATE TABLE vectors(key BLOB PRIMARY KEY,n0 INTEGER,n1 INTEGER); CREATE TABLE groups(key BLOB,day TEXT,kind TEXT,label INTEGER,n INTEGER);')
                db.executemany('INSERT INTO vectors VALUES(?,?,?)', [(x, 9, 1), (y, 0, 2)])
                db.executemany('INSERT INTO groups VALUES(?,?,?,?,?)', [(x, 'd1', 'normal', 0, 9), (x, 'd1', 'attack', 1, 1), (y, 'd2', 'attack', 1, 2)])
            i8 = codec.bootstrap('mlp_int8')
            i8['q_threshold'] = 0
            f32 = codec.bootstrap('mlp_float')
            candidate = copy.deepcopy(i8)
            candidate['q_threshold'] = 1
            result = n.evaluate_cache(path, {'B_mlp_int8': i8, 'B_mlp_float': f32, 'candidate': candidate}, ref, qref, chunk=1)
            self.assertEqual(result['rows'], 12)
            self.assertEqual(result['unique_vectors'], 2)
            self.assertEqual(result['weightings']['rows']['B_mlp_int8']['FPR'], 1.)
            self.assertEqual(result['weightings']['rows']['B_mlp_int8']['recall'], 1.)
            balanced = result['weightings']['vector_balanced']['B_mlp_int8']
            self.assertAlmostEqual(balanced['normal_mass'], .9)
            self.assertAlmostEqual(balanced['attack_mass'], 1.1)
            self.assertEqual(result['weightings']['rows']['candidate']['disagreement_vs_B_I8'], 1.)
            self.assertEqual(result['weightings']['rows']['candidate']['disagreement_vs_B_F32'], 0.)
            self.assertFalse(result['thresholds_reselected'])

    def test_identity_checks_reject_wrong_model_and_build(self):
        identity = codec.envelope_metadata(codec.sign_envelope(codec.bootstrap('lr'), 4, 'test'))
        entry = {'identity': identity}
        reply = {'event': 'inference', 'version': 4, 'policy': 'bundle', 'bundle_sha256': identity['bundle_sha256']}
        n.validate_identity(reply, entry, 'lr', 'some-build', 'inference')
        reply['bundle_sha256'] = '0' * 64
        with self.assertRaises(RuntimeError):
            n.validate_identity(reply, entry, 'lr', 'some-build', 'inference')

    def test_saved_model_export_has_fixed_percentile_cuts(self):
        for name, cutoff in [('percentile999_transferred', 30), ('percentile999_recalibrated', 27)]:
            model = n.load(ROOT / 'paper037/new_diagnostics/quantization' / (name + '.json'))
            self.assertEqual(model['q_threshold'], cutoff)
            envelope = codec.sign_envelope(model, 3, 'fixed039')
            self.assertEqual(codec.envelope_metadata(envelope)['runtime_abi'], 5)

    def test_mcu_artifacts_bind_all_published_models_and_monotonic_versions(self):
        models, _, _ = n.frozen_models(ROOT, ROOT / 'paper037/evidence_inputs/training')
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            prepared = directory / 'prepared'
            prepared.mkdir()
            for name, model in models.items():
                n.save(prepared / 'models' / (name + '.json'), model)
            n.save(prepared / 'panel.json', {'vectors': [{'raw': [0.] * 8}]})
            n.pin_directory(prepared)
            artifacts = n.build_mcu_artifacts(ROOT, prepared, directory / 'artifacts', ROOT / 'research030/prebuilt', codec)
            self.assertEqual(sum(len(f['versions']) for f in artifacts['families'].values()), 26)
            for family, info in artifacts['families'].items():
                self.assertEqual(list(map(int, info['versions'])), list(range(1, len(info['versions']) + 1)))
                self.assertEqual(info['versions']['1']['model'], 'A_' + family)
                self.assertEqual(info['image']['version'], 1)
                for entry in info['versions'].values():
                    blob = (directory / 'artifacts' / entry['path']).read_bytes()
                    self.assertEqual(codec.envelope_metadata(blob), entry['identity'])
            n.verify_directory(directory / 'artifacts')
            revised = ROOT / 'revision039/build/prebuilt/O2/lr_bundle'
            if (revised / 'metadata.json').is_file():
                n.verify_template(ROOT, revised, 'lr', codec)
                changed = directory / 'changed-template'
                shutil.copytree(revised, changed)
                image = changed / 'ids_update_lab.bin'
                contents = image.read_bytes()
                image.write_bytes(contents[:-1] + bytes([contents[-1] ^ 1]))
                with self.assertRaises(ValueError):
                    n.verify_template(ROOT, changed, 'lr', codec)


if __name__ == '__main__':
    unittest.main()
