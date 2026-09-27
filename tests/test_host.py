"""Meaningful wire/training boundary checks; no MCU claims are made here."""
from dataclasses import replace
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host"))
import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ids_update_lab.artifacts import equivalent_release, export_header, generate_demo
from ids_update_lab.package import (ENVELOPE_MAGIC, Model, PackageError, UpdateState,
    canonical_json, contract_hash, infer, infer_many, new_contract, parse_payload, sign, verify)


class WireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public = cls.key.public_key()
        cls.contract = new_contract(["x", "y"], ["unit", "unit"])
        cls.schema = contract_hash(cls.contract)
        cls.a = Model(1, "A", cls.schema, (0., 0.), (1., 1.), (1., -.25), -.1)
        cls.b = equivalent_release(cls.a)
        cls.envelope_a, cls.envelope_b = sign(cls.a, cls.key), sign(cls.b, cls.key)

    def raw_signed(self, payload):
        signature = self.key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        return struct.pack("<8sII", ENVELOPE_MAGIC, len(payload), len(signature)) + payload + signature

    def test_roundtrip_and_fixed_lengths(self):
        model = verify(self.envelope_a, self.public, self.schema, 2)
        self.assertEqual(model.payload(), self.a.payload())
        self.assertEqual(len(self.envelope_a), 16 + 80 + 24 + 256)

    def test_tampered_signature_payload_and_trailing_bytes(self):
        for index in (20, len(self.envelope_a) - 1):
            corrupted = bytearray(self.envelope_a); corrupted[index] ^= 1
            with self.assertRaises(PackageError):
                verify(corrupted, self.public)
        for corrupted in (self.envelope_a + b"\0", self.envelope_a[:-1], self.envelope_a[:15]):
            with self.assertRaises(PackageError):
                verify(corrupted, self.public)

    def test_wrong_key(self):
        wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(PackageError):
            verify(self.envelope_a, wrong.public_key())

    def test_signed_wrong_schema_and_abi(self):
        wrong = replace(self.b, schema=contract_hash(new_contract(["y", "x"], ["unit", "unit"])))
        with self.assertRaises(PackageError):
            verify(sign(wrong, self.key), self.public, self.schema, 2)
        payload = bytearray(self.b.payload()); struct.pack_into("<I", payload, 12, 99)
        with self.assertRaises(PackageError):
            verify(self.raw_signed(payload), self.public, self.schema, 2)

    def test_signed_nonfinite_negative_scale_and_bad_identifier(self):
        for offset, value in ((72, float("nan")), (76, float("inf")), (88, 0.0), (88, -1.0)):
            payload = bytearray(self.b.payload()); struct.pack_into("<f", payload, offset, value)
            with self.assertRaises(PackageError):
                verify(self.raw_signed(payload), self.public)
        payload = bytearray(self.b.payload()); payload[56:72] = b"A\0garbage".ljust(16, b"\0")
        with self.assertRaises(PackageError):
            verify(self.raw_signed(payload), self.public)

    def test_nonfinite_raw_and_float32_overflow_rejected(self):
        for raw in ([float("nan"), 1], [float("inf"), 1], [1e99, 0], [1]):
            with self.assertRaises(PackageError):
                infer(self.a, raw)

    def test_scalar_and_vectorized_golden_agree(self):
        data = np.random.default_rng(7).normal(size=(100, 2)).astype(np.float32)
        probability, labels = infer_many(self.a, data)
        for i, row in enumerate(data):
            p, label = infer(self.a, row)
            self.assertEqual(float(probability[i]), p)
            self.assertEqual(labels[i], label)

    def test_equivalent_bundle_and_stale_preprocessing_effect(self):
        data = np.array([[x, y] for x in np.linspace(-1, 1, 21) for y in [-1, 0, 1]], dtype=np.float32)
        pa, ya = infer_many(self.a, data)
        pb, yb = infer_many(self.b, data)
        _, stale = infer_many(self.b, data, self.a)
        self.assertTrue(np.array_equal(ya, yb))
        self.assertLess(float(np.max(np.abs(pa - pb))), 2e-6)
        self.assertGreater(int(np.sum(yb != stale)), 0)

    def test_replay_and_mixed_version_baseline(self):
        bundle = UpdateState(self.envelope_a, self.public, self.schema, 2)
        model_only = UpdateState(self.envelope_a, self.public, self.schema, 2, model_only=True)
        for state in [bundle, model_only]:
            state.update(self.envelope_b)
            for old in [self.envelope_a, self.envelope_b]:
                with self.assertRaises(PackageError):
                    state.update(old)
        self.assertNotEqual(bundle.infer([0, 0])[1], model_only.infer([0, 0])[1])

    def test_rejected_update_leaves_active_unchanged(self):
        state = UpdateState(self.envelope_a, self.public, self.schema, 2)
        corrupted = bytearray(self.envelope_b); corrupted[-1] ^= 1
        with self.assertRaises(PackageError):
            state.update(corrupted)
        self.assertEqual(state.active.version, 1)
        self.assertEqual(state.infer([0, 0]), infer(parse_payload(self.a.payload()), [0, 0]))

    def test_schema_canonical_order_and_semantic_validation(self):
        reordered = dict(reversed(list(self.contract.items())))
        self.assertEqual(contract_hash(reordered), self.schema)
        self.assertNotEqual(contract_hash(new_contract(["y", "x"], ["unit", "unit"])), self.schema)
        with self.assertRaises(PackageError):
            contract_hash({**self.contract, "untrusted_extra": "x"})
        with self.assertRaises(PackageError):
            new_contract(["x", "x"], ["unit", "unit"])

    def test_demo_provenance_cannot_be_exported_as_ton(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "demo"
            generate_demo(output, self.key)
            with self.assertRaises(PackageError):
                export_header(output / "release-A.sids", output / "public.pem", output / "feature_contract.json",
                    Path(temp) / "model.h", Path(temp) / "metadata", "TON_IoT")
            export_header(output / "release-A.sids", output / "public.pem", output / "feature_contract.json",
                Path(temp) / "model.h", Path(temp) / "metadata", "synthetic_plumbing")
            self.assertIn("kFactoryVersion = 1", (Path(temp) / "model.h").read_text())


class GroupSplitTests(unittest.TestCase):
    def test_duplicates_do_not_cross_and_class_conflicts_rejected(self):
        from ids_update_lab.training import grouped_split
        unique = np.arange(100, dtype=np.float32).reshape(-1, 1)
        x = np.repeat(unique, 3, axis=0)
        y = np.repeat(np.arange(100) % 2, 3)
        rows, groups, labels, assignment = grouped_split(x, y, 5)
        sets = [set(groups[index]) for index in rows.values()]
        self.assertFalse(sets[0] & sets[1] or sets[0] & sets[2] or sets[1] & sets[2])
        self.assertEqual(sum(map(len, rows.values())), len(x))
        y[1] = 1
        with self.assertRaises(PackageError):
            grouped_split(x, y, 5)

    def test_target_identifier_allowlist_guard(self):
        from ids_update_lab.training import check_feature_names
        check_feature_names(["duration", "src_bytes"])
        for name in ["label", "type", "src_ip", "attack_type", "target_score", "timestamp"]:
            with self.assertRaises(PackageError):
                check_feature_names([name])


if __name__ == "__main__":
    unittest.main()
