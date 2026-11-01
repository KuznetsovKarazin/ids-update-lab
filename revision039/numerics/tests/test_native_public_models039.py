"""Actual published model bytes against native C++, using synthetic inputs only.

Original software author: Oleksandr Kuznetsov.
"""
from pathlib import Path
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import numpy as np

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('n039_native', ROOT / 'revision039/numerics/run_numerics039.py')
n = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = n
spec.loader.exec_module(n)


class PublicModelNativeParity(unittest.TestCase):
    @unittest.skipUnless(shutil.which('g++'), 'Native C++ validation requires g++ and OpenSSL development headers')
    def test_all_26_published_models_random_extreme_and_template(self):
        ref, _, codec, _ = n.modules(ROOT)
        models, _, _ = n.frozen_models(ROOT, ROOT / 'paper037/evidence_inputs/training')
        # Validate the delivered revision, including its optional q_score API;
        # the unchanged030 harness remains source-compatible with this API.
        core = ROOT / 'revision039/firmware/components/ids_core'
        rng = np.random.default_rng(39001)
        raw = np.vstack((np.expm1(rng.uniform(0, 18, (256, 8))).astype(np.float32),
                         np.zeros((1, 8), np.float32), n.TARGET[None, :],
                         np.full((1, 8), np.finfo(np.float32).max, np.float32)))
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            exe = directory / 'native'
            command = ['g++', '-std=c++17', '-O2', '-ffp-contract=off', '-I', str(core / 'include'),
                       str(ROOT / 'research030/validation/native030.cpp'),
                       *[str(core / file) for file in ('ids_core.cpp', 'ids_tree.cpp', 'ids_mlp.cpp')], '-lcrypto', '-o', str(exe)]
            subprocess.run(command, check=True, capture_output=True)
            (directory / 'public.pem').write_bytes(codec.public_pem())
            for name, model in models.items():
                with self.subTest(model=name):
                    (directory / 'model.sids').write_bytes(codec.sign_envelope(model, 7, 'native039'))
                    result = subprocess.run([str(exe), str(directory / 'model.sids'), str(directory / 'public.pem')],
                                            input=raw.astype('<f4').tobytes(), capture_output=True, timeout=30, check=True)
                    rows = [json.loads(line) for line in result.stdout.splitlines()]
                    self.assertEqual(len(rows), len(raw))
                    self.assertTrue(all(row['ok'] for row in rows))
                    probability, labels = ref.predict(model, raw)
                    self.assertLessEqual(float(np.max(np.abs(np.asarray([row['p'] for row in rows]) - probability))), 2e-6)
                    np.testing.assert_array_equal([row['label'] for row in rows], labels)


if __name__ == '__main__':
    unittest.main()
