"""Preservation checks. Original software author: Oleksandr Kuznetsov."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from copy import deepcopy

SPEC = importlib.util.spec_from_file_location('run043', Path(__file__).resolve().parents[1] / 'run043.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class TestSafety(unittest.TestCase):
    def fixture(self, root):
        source = root / 'source'; future = root / 'future'
        old_protocol = {'models': {str(i): {'sha256': str(i)} for i in range(7)},
                        'thresholds': {str(i): {'q_threshold': i, 'threshold': .5} for i in range(7)}}
        old_metrics = {'rows': 7462871, 'unique_vectors': 3782505,
                       'weightings': {'rows': {str(i): {'FPR': .1, 'recall': .2} for i in range(7)}},
                       'by_day_rows': {}, 'by_type_rows': {}, 'clipping_on_unique_vectors': {},
                       'thresholds_reselected': False}
        new_protocol = deepcopy(old_protocol)
        new_protocol['models'][M.ADDED] = {'sha256': 'frozen'}
        new_protocol['thresholds'][M.ADDED] = {'q_threshold': 22, 'threshold': .99}
        new_protocol['tuning_on_future'] = False
        new_metrics = deepcopy(old_metrics)
        new_metrics['weightings']['rows'][M.ADDED] = {'FPR': .01, 'recall': .1}
        M.save(source / 'pc/percentile-future/PROTOCOL_LOCK.json', old_protocol)
        M.save(source / 'pc/percentile-future/evaluation.json', old_metrics)
        M.save(future / 'PROTOCOL_LOCK.json', new_protocol)
        M.save(future / 'evaluation.json', new_metrics)
        M.save(future / 'summary.json', {'status': 'complete', 'models_evaluated': 8})
        return source, future

    def test_complete_comparison_and_changed_threshold_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, future = self.fixture(Path(tmp))
            result = M.compare_results(source, future)
            self.assertEqual(result['old_models_compared'], 7)
            protocol = M.load(future / 'PROTOCOL_LOCK.json')
            protocol['thresholds']['3']['q_threshold'] += 1
            M.save(future / 'PROTOCOL_LOCK.json', protocol)
            with self.assertRaises(ValueError): M.compare_results(source, future)

    def test_new_comparator_threshold_must_be_frozen(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, future = self.fixture(Path(tmp))
            protocol = M.load(future / 'PROTOCOL_LOCK.json')
            protocol['thresholds'][M.ADDED]['q_threshold'] = 21
            M.save(future / 'PROTOCOL_LOCK.json', protocol)
            with self.assertRaises(ValueError): M.compare_results(source, future)

    def test_additive_comparison(self):
        M.compare_tree({'x': {'a': 1., 'b': None}}, {'x': {'a': 1., 'b': None, 'c': 3}})

    def test_changed_or_missing_metric(self):
        for candidate in ({'x': 1.1}, {}, {'x': float('nan')}, {'x': True}):
            with self.assertRaises(ValueError):
                M.compare_tree({'x': 1.}, candidate)

    def test_pin_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = root / 'a'; p.write_text('old')
            pins = {'a': M.sha(p)}
            M.verify_pins(root, pins)
            p.write_text('new')
            with self.assertRaises(ValueError): M.verify_pins(root, pins)

    def test_unsafe_manifest_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            for path in ('../escape', '/absolute', 'a\\b'):
                with self.assertRaises(ValueError): M.under(Path(tmp), path)

    def test_output_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); protected = root / 'source'; protected.mkdir()
            for output in (protected, protected / 'new', root):
                with self.assertRaises(ValueError): M.check_output(output, [protected])
            M.check_output(root / 'fresh', [protected])

    def test_archive_inventories_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'results'; out.mkdir()
            (out / 'x.json').write_text('{"test": 1}')
            digest = M.sha(out / 'x.json')
            result = M.pack(out)
            self.assertEqual(M.sha(out / 'x.json'), digest)
            self.assertEqual(M.sha(Path(result['archive'])), result['sha256'])
            with zipfile.ZipFile(result['archive']) as z:
                manifest = json.loads(z.read('ARCHIVE_MANIFEST.json'))
                self.assertEqual(manifest['files'][0]['sha256'], digest)
                self.assertIsNone(z.testzip())


if __name__ == '__main__':
    unittest.main()
