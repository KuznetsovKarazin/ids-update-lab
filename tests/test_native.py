"""Shared C++ core integration on native host; these are NOT MCU measurements."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE = ROOT / "build/native/ids_update_native"
FIXTURES = ROOT / "examples/instrumented_synthetic"


@unittest.skipUnless(EXECUTABLE.is_file(), "native executable absent; run bash tools/build_native.sh")
class NativeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ids-native-test-")
        self.addCleanup(self.temporary.cleanup)
        self.store = Path(self.temporary.name)
        self.package_a = (FIXTURES / "release-A.sids").read_bytes()
        self.package_b = (FIXTURES / "release-B.sids").read_bytes()

    def run_native(self, *commands, model_only=False, expected_code=0):
        args = [str(getattr(self, "executable", EXECUTABLE)), "--store", str(self.store)]
        if model_only:
            args.append("--model-only")
        result = subprocess.run(args, input="\n".join(commands) + "\n", text=True,
                                capture_output=True, timeout=20, check=False)
        self.assertEqual(result.returncode, expected_code, result.stderr + result.stdout)
        return [json.loads(line) for line in result.stdout.splitlines() if line]

    def install_b(self):
        events = self.run_native("UPDATE " + self.package_b.hex())
        update = next(event for event in events if event["event"] == "update")
        self.assertTrue(update["accepted"])
        self.assertEqual(update["version"], 2)
        self.assertEqual(update["timing_schema"], 2)
        self.assertTrue(update["timing_measured"])
        self.assertEqual(update["timing_executed_mask"], 63)
        timing = update["timing_us"]
        stages = ("candidate_verify", "erase", "body_write", "readback", "readback_verify", "commit")
        self.assertTrue(all(isinstance(timing[key], int) and timing[key] >= 0 for key in (*stages, "total")))
        self.assertLessEqual(sum(timing[key] for key in stages), timing["total"])
        self.assertLessEqual(timing["total"], update["latency_us"])

    def test_normal_update_persists_across_processes(self):
        self.install_b()
        events = self.run_native("STATUS")
        self.assertTrue(events[0]["ready"])
        self.assertEqual(events[0]["version"], 2)
        self.assertEqual(events[-1]["policy"], "bundle")

    def test_each_interruption_checkpoint_requires_process_restart(self):
        for checkpoint, expected_version in (("after_erase", 1), ("after_write", 1),
                                             ("after_verify", 1), ("after_commit", 2)):
            with self.subTest(checkpoint=checkpoint):
                with tempfile.TemporaryDirectory(prefix="ids-checkpoint-") as directory:
                    previous = self.store
                    self.store = Path(directory)
                    try:
                        events = self.run_native("ARM_FAIL " + checkpoint,
                                                 "UPDATE " + self.package_b.hex(), expected_code=75)
                        self.assertEqual(events[-1]["event"], "fault_checkpoint")
                        self.assertEqual(events[-1]["checkpoint"], checkpoint)
                        self.assertEqual(events[-1]["fault_kind"], "software_restart")
                        rebooted = self.run_native("STATUS")
                        self.assertTrue(rebooted[0]["ready"])
                        self.assertEqual(rebooted[0]["version"], expected_version)
                    finally:
                        self.store = previous

    def test_signature_tamper_rejected_without_changing_active_model(self):
        damaged = bytearray(self.package_b)
        damaged[40] ^= 1
        events = self.run_native("UPDATE " + damaged.hex(), "STATUS")
        update = next(event for event in events if event["event"] == "update")
        self.assertFalse(update["accepted"])
        self.assertEqual(update["reason"], "signature")
        self.assertEqual(update["timing_executed_mask"], 1)
        self.assertEqual(update["timing_us"]["erase"], 0)
        self.assertEqual(events[-1]["version"], 1)
        self.assertTrue(events[-1]["ready"])

    def test_replay_and_downgrade_rejected(self):
        self.install_b()
        events = self.run_native("UPDATE " + self.package_a.hex(), "UPDATE " + self.package_b.hex())
        updates = [event for event in events if event["event"] == "update"]
        self.assertEqual(len(updates), 2)
        for update in updates:
            self.assertFalse(update["accepted"])
            self.assertEqual(update["reason"], "replay_or_downgrade")
            self.assertEqual(update["version"], 2)

    def test_nonfinite_and_wrong_feature_count_inputs_rejected(self):
        events = self.run_native("INFER nan,0", "INFER inf,0", "INFER -inf,0", "INFER 0", "INFER 0,0")
        errors = [event for event in events if event["event"] == "error"]
        self.assertEqual([event["reason"] for event in errors],
                         ["nonfinite_input", "nonfinite_input", "nonfinite_input", "input_count"])
        self.assertEqual(events[-1]["event"], "inference")

    def test_committed_slot_corruption_fails_closed_with_old_valid_slot(self):
        self.install_b()
        path = self.store / "ids_b.bin"
        data = bytearray(path.read_bytes())
        data[8 + 40] ^= 1
        path.write_bytes(data)
        events = self.run_native("STATUS", "INFER 0,0")
        self.assertFalse(events[0]["ready"])
        self.assertEqual(events[0]["reason"], "committed_slot_invalid")
        self.assertEqual(events[-1]["reason"], "not_ready")

    def test_uncommitted_candidate_ignored_if_old_slot_valid(self):
        self.run_native("STATUS")
        data = bytearray(b"\xff" * 65536)
        data[4:8] = struct.pack("<I", len(self.package_b))
        data[8:8 + len(self.package_b)] = self.package_b
        (self.store / "ids_b.bin").write_bytes(data)
        boot = self.run_native("STATUS")[0]
        self.assertTrue(boot["ready"])
        self.assertEqual(boot["version"], 1)

    def test_non_erased_store_without_valid_slot_never_falls_back_to_factory(self):
        (self.store / "ids_a.bin").write_bytes(b"\x00" + b"\xff" * 65535)
        (self.store / "ids_b.bin").write_bytes(b"\xff" * 65536)
        boot = self.run_native("STATUS")[0]
        self.assertFalse(boot["ready"])
        self.assertEqual(boot["reason"], "corrupt_store_no_valid_slot")

    def test_model_only_stores_original_signed_envelope(self):
        events = self.run_native("UPDATE " + self.package_b.hex(), "INFER 0,0", model_only=True)
        update = next(event for event in events if event["event"] == "update")
        self.assertTrue(update["accepted"])
        self.assertEqual(events[-1]["policy"], "model_only_factory_preprocess")
        raw = (self.store / "ids_b.bin").read_bytes()
        self.assertEqual(raw[8:8 + len(self.package_b)], self.package_b)
        self.assertEqual(self.run_native("STATUS", model_only=True)[0]["version"], 2)

    def test_compiled_model_only_matches_all_63_vectors_including_boundary(self):
        # This runtime check uses a fresh host-only key/header. It does not
        # require the unavailable historical compatible-control signing key
        # and does not replace any frozen package or measured firmware image.
        from dataclasses import replace
        import importlib.util
        import os
        import sys
        from cryptography.hazmat.primitives.asymmetric import rsa

        sys.path.insert(0, str(ROOT / "host"))
        from ids_update_lab.artifacts import export_header, generate_demo
        from ids_update_lab.package import infer, sign, verify

        directory = Path(self.temporary.name) / "compatible-host-only"
        directory.mkdir()
        fixtures = directory / "fixtures"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        generate_demo(fixtures, key)
        a, b = [verify((fixtures / f"release-{letter}.sids").read_bytes(), key.public_key())
                for letter in "AB"]
        spec = importlib.util.spec_from_file_location(
            "compatible_reference030", ROOT / "research030/training/model030.py")
        reference = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reference)
        def parameters(model):
            return {"weights": model.weights, "bias": model.bias,
                    "mean": model.means, "scale": model.scales,
                    "threshold": model.threshold}
        converted = reference.compatible_lr(parameters(a), parameters(b))
        compiled = replace(b, means=tuple(converted["mean"]),
                           scales=tuple(converted["scale"]),
                           weights=tuple(converted["weights"]), bias=converted["bias"])
        packages = {letter: sign(replace(compiled, version=version,
                                         release=f"synthetic-{letter}c"), key)
                    for letter, version in (("B", 2), ("C", 3))}
        export_header(fixtures / "release-A.sids", fixtures / "public.pem",
                      fixtures / "feature_contract.json", directory / "model_contract.h",
                      directory / "metadata", "synthetic_plumbing")
        self.executable = directory / "ids_update_native"
        subprocess.run([
            os.environ.get("CXX", "g++"), "-std=c++17", "-O2", "-ffp-contract=off",
            "-I" + str(directory),
            "-I" + str(ROOT / "firmware/components/ids_core/include"),
            str(ROOT / "firmware/components/ids_core/ids_core.cpp"),
            str(ROOT / "firmware/components/ids_core/ids_protocol.cpp"),
            str(ROOT / "firmware/native/main.cpp"), "-lcrypto", "-o", str(self.executable)
        ], capture_output=True, text=True, timeout=60, check=True)
        del key
        rows = [json.loads(line) for line in (fixtures / "golden.jsonl").read_text().splitlines() if line.strip()]
        self.assertEqual(len(rows), 63)
        self.assertTrue(any(row["expected_B"]["probability"] == 0.5 for row in rows))
        for row in rows:
            probability, label = infer(compiled, row["raw"], preprocessing=a)
            self.assertEqual(label, row["expected_B"]["label"])
            self.assertLessEqual(abs(probability - row["expected_B"]["probability"]), 2e-6)
        commands = []
        for letter in "BC":
            commands.append("UPDATE " + packages[letter].hex())
            commands.extend("INFER " + ",".join(format(float(v), ".9g") for v in row["raw"]) for row in rows)
        events = self.run_native(*commands, model_only=True)
        updates = [event for event in events if event["event"] == "update"]
        self.assertEqual([event["version"] for event in updates], [2, 3])
        self.assertTrue(all(event["accepted"] for event in updates))
        inference = [event for event in events if event["event"] == "inference"]
        self.assertEqual(len(inference), 126)
        for event, row in zip(inference, rows * 2):
            expected = row["expected_B"]
            self.assertEqual(event["label"], expected["label"])
            self.assertLessEqual(abs(event["probability"] - expected["probability"]), 2e-6)
        self.assertEqual(self.run_native("STATUS", model_only=True)[0]["version"], 3)

    def test_bounded_line_and_embedded_control_are_rejected(self):
        events = self.run_native("X" * 1300, "STA\x00TUS", "STATUS")
        self.assertEqual(events[1]["reason"], "line_too_long")
        self.assertEqual(events[2]["reason"], "invalid_control_character")
        self.assertEqual(events[3]["event"], "status")


if __name__ == "__main__":
    unittest.main()
