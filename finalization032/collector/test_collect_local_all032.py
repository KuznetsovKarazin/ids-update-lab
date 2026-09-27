import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile
import json
from unittest import mock

SPEC = importlib.util.spec_from_file_location('collector', Path(__file__).with_name('collect_local_all032.py'))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)

class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.put('runs/030/summary.json', '{"status":"failed","error":"original marker gate"}')

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, name, text):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def collect(self):
        result = C.collect(self.root, self.root / 'all032.zip', [], False)
        with zipfile.ZipFile(result['output']) as z:
            return result, z.namelist(), json.loads(z.read('COLLECTION_MANIFEST.json'))

    def test_preserves_sqlite_npz_recovery_code_and_failed_status(self):
        for n in ['runs/030/training/test_vectors.sqlite', 'runs/030/samples/A_fit.npz',
                  'runs/031/summary.json', 'recovery031/recover.py', 'preservation032/readme.md',
                  'finalization032/run.py']:
            self.put(n, 'data')
        result, names, manifest = self.collect()
        self.assertTrue(result['crc_and_member_sha256_verified'])
        self.assertIn('project/runs/030/training/test_vectors.sqlite', names)
        self.assertIn('project/runs/030/samples/A_fit.npz', names)
        self.assertIn('project/recovery031/recover.py', names)
        self.assertIn('project/finalization032/run.py', names)
        self.assertEqual(manifest['summary_index'][0]['reported_status'], 'failed')
        self.assertEqual(json.loads((self.root / 'runs/030/summary.json').read_text())['status'], 'failed')

    def test_dependencies_credentials_and_existing_archives_excluded(self):
        for n in ['.venv030/pkg.py', 'research030/.venv030/pkg.py', 'old.zip', 'runs/old.zip',
                  'research030/.env.custom', 'research030/credentials.json',
                  'research030/key.pem', 'research030/PUBLIC_DEVELOPMENT_ONLY_private.pem']:
            self.put(n, '-----BEGIN PRIVATE KEY-----\nnot-the-public-development-key')
        _, names, manifest = self.collect()
        self.assertFalse(any('pkg.py' in n for n in names))
        self.assertFalse(any('private.pem' in n or 'key.pem' in n or '.env.' in n for n in names))
        self.assertNotIn('project/old.zip', names)
        self.assertNotIn('project/runs/old.zip', names)
        self.assertTrue(any(e['reason'] == 'private_key' for e in manifest['excluded']))

    def test_public_development_key_exact_content_only(self):
        # Fixture located in workspace; packaged tests can use -- no secret value is printed.
        candidates = list(Path(__file__).resolve().parents)
        key = next((p / 'research030/hardware_codec/PUBLIC_DEVELOPMENT_ONLY_private.pem' for p in candidates
                    if (p / 'research030/hardware_codec/PUBLIC_DEVELOPMENT_ONLY_private.pem').exists()), None)
        if key is None:
            self.skipTest('Known public development key not alongside collector')
        target = self.put('research030/PUBLIC_DEVELOPMENT_ONLY_private.pem', key.read_text())
        self.assertEqual(C.digest(target), C.PUBLIC_TEST_KEY_SHA256)
        _, names, _ = self.collect()
        self.assertIn('project/research030/PUBLIC_DEVELOPMENT_ONLY_private.pem', names)

    def test_large_dataset_outside_runs_hash_only_but_runs_kept(self):
        for n in ['research030/source.csv', 'runs/030/raw.csv']:
            p = self.put(n, '')
            with p.open('wb') as f:
                f.truncate(32 * 1024 * 1024 + 1)
        _, names, m = self.collect()
        self.assertNotIn('project/research030/source.csv', names)
        self.assertIn('project/runs/030/raw.csv', names)
        self.assertTrue(any(e.get('sha256') and e['path'] == 'research030/source.csv' for e in m['excluded']))

    def test_explicit_full_dataset_mode_and_data_directory(self):
        for n in ['data/ton_full_v1/Network_dataset_1.csv', 'datasets/original.csv', 'ton_archive/source.csv']:
            p = self.put(n, '')
            with p.open('wb') as f:
                f.truncate(32 * 1024 * 1024 + 1)
        r = C.collect(self.root, self.root / 'full.zip', [], False, True)
        with zipfile.ZipFile(r['output']) as z:
            self.assertIn('project/data/ton_full_v1/Network_dataset_1.csv', z.namelist())
            self.assertIn('project/datasets/original.csv', z.namelist())
            self.assertIn('project/ton_archive/source.csv', z.namelist())
            self.assertTrue(json.loads(z.read('COLLECTION_MANIFEST.json'))['include_large_datasets'])

    def test_archive_exception_is_explicit(self):
        self.put('runs/unique-evidence.zip', 'fixture archive bytes')
        r = C.collect(self.root, self.root / 'with-old.zip', [], True)
        with zipfile.ZipFile(r['output']) as z:
            self.assertIn('project/runs/unique-evidence.zip', z.namelist())

    def test_existing_output_and_partial_never_overwritten(self):
        target = self.put('all032.zip', 'existing')
        with self.assertRaises(FileExistsError):
            self.collect()
        self.assertEqual(target.read_text(), 'existing')
        target.unlink()
        partial = self.put('all032.zip.partial', 'interrupted')
        with self.assertRaises(FileExistsError):
            self.collect()
        self.assertEqual(partial.read_text(), 'interrupted')

    def test_no_runs_or_path_escape_refused(self):
        (self.root / 'runs/030/summary.json').unlink()
        with self.assertRaises(ValueError):
            self.collect()
        with self.assertRaises(ValueError):
            C.collect(self.root, self.root / 'out.zip', ['../outside'], False)

    def test_changed_source_retains_partial_no_final_output(self):
        original = zipfile.ZipFile.open
        mutated = False
        def mutate(archive, name, mode='r', *args, **kwargs):
            nonlocal mutated
            result = original(archive, name, mode, *args, **kwargs)
            if mode == 'w' and not mutated:
                mutated = True
                self.put('runs/030/summary.json', '{"status":"new data"}')
            return result
        with mock.patch.object(zipfile.ZipFile, 'open', mutate):
            with self.assertRaises(RuntimeError):
                self.collect()
        self.assertFalse((self.root / 'all032.zip').exists())
        self.assertTrue((self.root / 'all032.zip.partial').exists())

    def test_competing_output_not_overwritten(self):
        original = C.os.link
        def competing(src, dst):
            Path(dst).write_text('competing output')
            return original(src, dst)
        with mock.patch.object(C.os, 'link', competing):
            with self.assertRaises(FileExistsError):
                self.collect()
        self.assertEqual((self.root / 'all032.zip').read_text(), 'competing output')
        self.assertTrue((self.root / 'all032.zip.partial').exists())

if __name__ == '__main__':
    unittest.main()
