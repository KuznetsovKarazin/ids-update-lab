"""Real signed ABI2 envelopes through the native shared C++ engine.

This is host validation, not MCU or physical power-loss evidence. Faults below
are software checkpoints and intentionally edited storage images.
"""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / 'fixtures'


class RealSignedStorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('g++'):
            raise unittest.SkipTest('g++ with OpenSSL development library required')
        cls.build = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.build.name) / 'native'
        core = ROOT / 'firmware/components/ids_core'
        subprocess.run(['g++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
                        '-ffp-contract=off', '-I' + str(core/'include'), '-I' + str(FIXTURES),
                        str(core/'ids_core.cpp'), str(core/'ids_tree.cpp'), str(core/'ids_protocol.cpp'),
                        str(ROOT/'firmware/native/main.cpp'), '-lcrypto', '-o', str(cls.binary)],
                       check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def process(self, store, *commands):
        result = subprocess.run([str(self.binary), '--store', str(store)],
                                input='\n'.join(commands)+'\n', text=True, capture_output=True)
        self.assertIn(result.returncode, (0, 75), result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]

    @staticmethod
    def update(name):
        return 'UPDATE ' + (FIXTURES / name).read_bytes().hex()

    def provision_B(self, store):
        events = self.process(store, self.update('release-B.sids'), 'STATUS')
        self.assertTrue(events[-1]['ready'])
        self.assertEqual(events[-1]['version'], 2)
        return events

    def test_six_checkpoint_recovery_uses_selector_not_slot_marker(self):
        points = ('after_erase', 'after_write', 'after_verify', 'after_slot_commit',
                  'after_journal_body', 'after_commit')
        for point in points:
            with self.subTest(point=point), tempfile.TemporaryDirectory() as temp:
                store = Path(temp)
                self.provision_B(store)
                self.process(store, 'ARM_FAIL ' + point, self.update('release-restored_B.sids'))
                status = self.process(store, 'STATUS')[-1]
                self.assertTrue(status['ready'], status)
                self.assertEqual(status['version'], 8 if point == 'after_commit' else 2)
                if point != 'after_commit':
                    status = self.process(store, self.update('release-restored_B.sids'), 'STATUS')[-1]
                    self.assertEqual(status['version'], 8)

    def test_partial_erase_old_marker_survives_but_active_B_recovers(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Path(temp)
            self.provision_B(store)
            old = store/'ids_a.bin'
            before = old.read_bytes()
            # A targeted subset of NOR 0->1 transitions destroys the signed
            # envelope while preserving the old commit word and its length.
            torn = before[:80] + b'\xff' * 96 + before[176:]
            old.write_bytes(torn)
            self.assertEqual(before[:8], torn[:8])
            status = self.process(store, 'STATUS')[-1]
            self.assertTrue(status['ready'], status)
            self.assertEqual(status['version'], 2)

    def test_corrupt_authoritative_B_fails_closed_without_factory_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Path(temp)
            self.provision_B(store)
            selected = store/'ids_b.bin'
            raw = bytearray(selected.read_bytes()); raw[90] ^= 1; selected.write_bytes(raw)
            status = self.process(store)[0]
            self.assertFalse(status['ready'])
            self.assertEqual(status['reason'], 'selected_slot_invalid')

    def test_missing_first_selector_after_factory_write_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Path(temp)
            self.process(store)
            (store/'ids_meta0.bin').write_bytes(b'\xff' * 4096)
            status = self.process(store)[0]
            self.assertFalse(status['ready'])
            self.assertEqual(status['reason'], 'unprovisioned_dirty_store')

    def test_missing_journal_file_is_not_silently_recreated(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Path(temp)
            self.provision_B(store)
            (store/'ids_meta0.bin').unlink()
            result = subprocess.run([str(self.binary), '--store', str(store)],
                                    input='STATUS\n', text=True, capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('incomplete store', result.stderr)
            self.assertFalse((store/'ids_meta0.bin').exists())

    def test_unacknowledged_slot_commit_does_not_activate_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Path(temp)
            self.provision_B(store)
            self.process(store, 'ARM_FAIL after_slot_commit', self.update('release-restored_B.sids'))
            status = self.process(store, 'STATUS')[-1]
            self.assertEqual(status['version'], 2)
            self.assertTrue(status['ready'])


if __name__ == '__main__':
    unittest.main()
