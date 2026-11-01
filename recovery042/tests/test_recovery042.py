"""Recovery preservation tests using synthetic files, never scientific data.

Original software author: Oleksandr Kuznetsov.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'recover_pc042.py'
spec = importlib.util.spec_from_file_location('recovery042_test_target', SCRIPT)
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.source = self.base / 'source'
        self.source.mkdir()
        self.kit = self.base / 'kit'
        self.kit.mkdir()
        self.prior = self.base / 'prior'
        (self.prior / 'models').mkdir(parents=True)
        self.artifact = self.base / 'patch'
        self.artifact.mkdir()
        for name in R.COMPLETED:
            product = self.source / 'pc' / name
            R.save(product / 'summary.json', {'status': 'complete', 'data_origin': 'synthetic_test_fixture'})
            log = self.source / 'logs' / (name + '.log')
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text('synthetic fixture\n')
            R.save(self.source / 'steps' / (name + '.json'), {
                'name': name, 'status': 'complete', 'returncode': 0,
                'outputs_sha256': {'summary.json': R.sha(product / 'summary.json')},
                'log_sha256': R.sha(log)})
        R.save(self.source / 'steps/percentile-future.json', {'status': 'failed', 'returncode': 1})
        R.save(self.source / 'pc/percentile-future/summary.json', {'status': 'failed', 'error': 'Python integer 453 out of bounds for uint8'})
        self.lock = {'command': 'future', 'models': {'fixture': {'sha256': 'synthetic'}},
                     'thresholds': {'fixture': 0.5}, 'percentile': 99.9, 'tuning_on_future': False,
                     'expected_future_rows': 2, 'expected_future_unique_vectors': 2}
        R.save(self.source / 'pc/percentile-future/PROTOCOL_LOCK.json', self.lock)
        hashes, excluded = R.inventory(self.source)
        self.pins = {'sha256': hashes, 'excluded': excluded}
        R.save(self.artifact / 'expected_source041.json', self.pins)
        (self.artifact / 'run_numerics042.py').write_text('# synthetic fixture only\n')
        R.save(self.artifact / 'PATCH042.json', {'sha256': {
            'expected_source041.json': R.sha(self.artifact / 'expected_source041.json'),
            'run_numerics042.py': R.sha(self.artifact / 'run_numerics042.py')}})
        self.args = SimpleNamespace(source=self.source, kit=self.kit, output=self.base / 'output')
        self.report = {'source_files_sha256': hashes, 'imports': {n: {'status': 'verified_import'} for n in R.COMPLETED},
                       'prior_training': str(self.prior), 'ton_directory': str(self.base / 'data')}

    def tearDown(self):
        self.tmp.cleanup()

    def test_source_hash_drift_rejected(self):
        (self.source / 'logs/threshold.log').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'changed or incomplete'):
            R.verify_source(self.source, self.pins)

    def test_unexpected_noncache_file_rejected(self):
        (self.source / 'unexpected.txt').write_text('new')
        with self.assertRaisesRegex(ValueError, 'changed or incomplete'):
            R.verify_source(self.source, self.pins)

    def test_reconstructible_cache_is_inventoried(self):
        (self.source / 'pc/temporal-runs/test_vectors.sqlite').write_bytes(b'synthetic cache')
        hashes, excluded, receipts = R.verify_source(self.source, self.pins)
        self.assertEqual(hashes, self.pins['sha256'])
        self.assertEqual(len(excluded), 1)
        self.assertEqual(set(receipts), set(R.COMPLETED))

    def test_existing_output_never_inspected_or_changed(self):
        self.args.output.mkdir()
        sentinel = self.args.output / 'keep.txt'
        sentinel.write_text('untouched')
        with patch.object(R, 'inspect_recovery') as inspect:
            with self.assertRaisesRegex(ValueError, 'Fresh output'):
                R.run(self.args)
            inspect.assert_not_called()
        self.assertEqual(list(self.args.output.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_text(), 'untouched')

    def test_source_guard_failure_does_not_create_output(self):
        with patch.object(R, 'inspect_recovery', side_effect=ValueError('source changed')), patch.object(R, 'load_coordinator') as coord:
            with self.assertRaisesRegex(ValueError, 'source changed'):
                R.run(self.args)
            coord.assert_not_called()
        self.assertFalse(self.args.output.exists())

    def test_successful_synthetic_recovery_preserves_source(self):
        before = R.inventory(self.source)[0]
        packed = []
        def launch(argv, log, kit):
            self.assertEqual(argv[2], 'future')
            self.assertNotIn('mcu', argv)
            self.assertNotIn('run', argv)
            product = Path(argv[argv.index('--output') + 1])
            log.write_text('synthetic launcher only\n')
            R.save(product / 'summary.json', {'status': 'complete', 'command': 'future',
                   'hardware_access_attempted': False, 'data_origin': 'synthetic_test_fixture'})
            R.save(product / 'PROTOCOL_LOCK.json', self.lock)
            return 0
        fake = SimpleNamespace(pack=lambda out: packed.append(out) or {'archive': 'synthetic-test-only'})
        with patch.object(R, 'HERE', self.artifact), patch.object(R, 'inspect_recovery', return_value=self.report), patch.object(R, 'load_coordinator', return_value=fake):
            result = R.run(self.args, launcher=launch)
        self.assertTrue(result['pc_execution_complete'])
        self.assertFalse(result['all_reviewer_experiments_complete'])
        self.assertEqual(R.inventory(self.source)[0], before)
        self.assertEqual(R.inventory(self.args.output / 'source_evidence041')[0], before)
        self.assertEqual(packed, [self.args.output])

    def test_changed_future_threshold_rejected(self):
        product = self.base / 'altered-future'
        changed = dict(self.lock, thresholds={'fixture': 0.6})
        R.save(product / 'PROTOCOL_LOCK.json', changed)
        with self.assertRaisesRegex(RuntimeError, 'protocol changed: thresholds'):
            R.verify_future_binding(self.source, product)

    def test_failed_future_preserves_and_archives_partial(self):
        before = R.inventory(self.source)[0]
        def launch(argv, log, kit):
            log.write_text('synthetic failure\n')
            return 1
        packed = []
        fake = SimpleNamespace(pack=lambda out: packed.append(out) or {'archive': 'synthetic-test-only'})
        with patch.object(R, 'HERE', self.artifact), patch.object(R, 'inspect_recovery', return_value=self.report), patch.object(R, 'load_coordinator', return_value=fake):
            with self.assertRaisesRegex(RuntimeError, 'Future evaluation failed'):
                R.run(self.args, launcher=launch)
        self.assertEqual(R.inventory(self.source)[0], before)
        status = R.load(self.args.output / 'STATUS042.json')
        self.assertEqual(status['status'], 'failed')
        self.assertFalse(status['pc_execution_complete'])
        self.assertEqual(packed, [self.args.output])


if __name__ == '__main__':
    unittest.main()
