"""Host-only reuse campaign mocks; no MCU, flash or power-loss evidence."""
from collections import deque
import contextlib
from dataclasses import replace
import importlib.util
import io
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("stage_timing_pilot_tool", ROOT / "tools/run_stage_timing_pilot.py")
PILOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PILOT)
from ids_update_lab.artifacts import generate_demo
from ids_update_lab.package import generate_keys, infer, sign, verify, load_public


class StageTimingPilotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ids-reuse-host-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = generate_keys(self.root / "keys")
        experiment = generate_demo(self.root / "experiment", self.key)
        b = verify((experiment / "release-B.sids").read_bytes(), load_public(experiment / "public.pem"))
        self.c = replace(b, version=3, release="synthetic-C")
        (self.root / "C.sids").write_bytes(sign(self.c, self.key))
        image = bytearray(288)
        image[0] = 0xE9
        struct.pack_into("<I", image, 32, 0xABCD5432)
        image[48:50] = b"1\0"
        image[144:152] = b"v5.3.2\0\0"
        image[176:208] = bytes([1]) * 32
        image.extend((experiment / "release-A.sids").read_bytes())
        (self.root / "A.bin").write_bytes(image)
        self.args = SimpleNamespace(port="HOST_MOCK_ONLY", experiment=experiment, release_c=self.root / "C.sids",
            firmware_bin=self.root / "A.bin", output=self.root / "campaign", board_id="HOST_MOCK_ONLY", trials=2, timeout=.03)
        self.context = PILOT.preflight(self.args)
        self.restore_commands = []
        self.transports = []
        self.history = []
        self.release = 0

    def execute(self, mode="normal"):
        owner = self
        class FakeTransport:
            def __init__(self, port, on_read):
                self.on_read = on_read
                self.queue = deque()
                self.received_bytes = 0
                self.writes = []
                self.closed = False
                owner.transports.append(self)
                owner.history.append("open")
            def status(self, event="status"):
                index = owner.release
                model = owner.context["models"][index]
                identity = owner.context["identity"]
                build = f"esp-idf-{identity['idf_version']};app=1;elf={identity['elf_sha256'][:9]}"
                if mode == "wrong_build":
                    build = build[:-9] + "deadbeef0"
                return {"event": event, "ready": True, "reason": "ok", "policy": "whole_firmware" if mode == "wrong_policy" else owner.context["policy"],
                    "chip": "esp32s3", "schema": owner.context["schema"], "feature_count": 2,
                    "timing_schema": 1 if mode == "old_timing_schema" else 2, "crypto_context": "shared_warm",
                    "crypto_key_setup_us": 10, "crypto_first_verify_us": 20,
                    "data_origin": "synthetic_plumbing", "version": index + 1, "release": model.release,
                    "bundle_sha256": owner.context["payload_hashes"][index], "build": build, "active_slot": 1 if index == 1 else 0}
            def emit(self, response):
                line = json.dumps(response)
                data = (line + "\n").encode()
                self.received_bytes += len(data)
                self.on_read(data)
                self.queue.append(line)
            def write(self, line):
                self.writes.append(line)
                if not line:
                    return
                command, _, tail = line.partition(" ")
                if command == "STATUS":
                    self.emit(self.status())
                elif command == "INFER":
                    probability, label = infer(owner.context["models"][owner.release], [float(x) for x in tail.split(",")])
                    self.emit({**self.status(), "event": "inference", "probability": probability, "label": label, "latency_us": 10})
                elif command == "UPDATE":
                    package = bytes.fromhex(tail)
                    target = owner.context["envelopes"].index(package)
                    if target != owner.release + 1:
                        raise AssertionError("unexpected update sequence")
                    owner.release = target
                    if mode == "lost_C_ack" and target == 2:
                        return
                    self.emit({"event": "update", "accepted": True, "reason": "ok", "ready": True,
                        "version": target + 1, "policy": owner.context["policy"], "latency_us": 100,
                        "timing_schema": 2, "timing_measured": True, "timing_executed_mask": 63,
                        "timing_us": {"candidate_verify": 10, "erase": 50 if mode == "bad_timing_sum" else 10,
                            "body_write": 10, "readback": 10, "readback_verify": 10, "commit": 10, "total": 70}})
                elif command == "REBOOT":
                    self.emit({"event": "reboot", "fault_kind": "software_restart"})
                    if mode != "missing_boot":
                        self.emit(self.status("boot"))
                else:
                    raise AssertionError("unexpected command " + command)
            def readline(self, timeout):
                if self.queue:
                    return self.queue.popleft()
                time.sleep(min(timeout, .001))
                return None
            def take_pending_fragment(self):
                return b""
            def close(self):
                self.closed = True
                owner.history.append("close")
        original_sync = PILOT.synchronize_serial
        def fast_sync(transport, record, timeout):
            return original_sync(transport, record, timeout, startup_wait=0, quiet_period=.001)
        def fake_esptool(command, *, stdout, stderr, text, timeout, check):
            self.assertTrue(all(transport.closed for transport in self.transports))
            self.assertEqual(command[-3:], ["erase_region", "0x3b0000", "0x20000"])
            self.assertNotIn("write_flash", command)
            self.restore_commands.append(command)
            self.history.append("erase")
            owner.release = 0
            if mode == "erase_failure":
                stdout.write("simulated transport failure\n")
                return SimpleNamespace(returncode=2)
            stdout.write("Chip is ESP32-S3\nMAC: a0:f2:62:eb:b5:58\nErase completed successfully\n")
            return SimpleNamespace(returncode=0)
        with patch.object(PILOT, "SerialTransport", FakeTransport), patch.object(PILOT, "synchronize_serial", fast_sync), \
             patch.object(PILOT.subprocess, "run", fake_esptool), contextlib.redirect_stdout(io.StringIO()):
            return PILOT.run(self.args)

    def campaign_summary(self):
        return json.loads((self.args.output / "campaign_summary.json").read_text())

    def test_two_trials_restore_only_closed_port_and_prove_slot_reuse(self):
        summary = self.execute()
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["completed_trials"], 2)
        self.assertEqual(summary["accepted_updates"], 4)
        self.assertEqual(summary["inferred_records"], 378)
        self.assertEqual(self.history, ["open", "close", "erase", "open", "close", "erase", "open", "close"])
        self.assertEqual(len(self.restore_commands), 2)
        for index in (1, 2):
            trial = self.args.output / f"trial-{index:03d}"
            result = json.loads((trial / "summary.json").read_text())
            self.assertEqual(result["inferred_records"], 189)
            self.assertTrue(result["reboot_verified"])
            self.assertTrue(result["post_reboot_probe_passed"])
            rows = [json.loads(x) for x in (trial / "observations.jsonl").read_text().splitlines()]
            self.assertEqual([sum(row["phase"] == phase for row in rows) for phase in ("before", "after_first", "after_reuse")], [63, 63, 63])
            events = [json.loads(x) for x in (trial / "events.jsonl").read_text().splitlines()]
            updates = [row for row in events if row.get("command_kind") == "UPDATE"]
            self.assertEqual([row["destination_state"] for row in updates], ["explicitly_erased", "previously_committed_release_A"])
            self.assertEqual([row["destination_slot"] for row in updates], [1, 0])
            self.assertTrue((trial / "restore.log").is_file())

    def test_changed_C_numbers_fail_before_any_output_device_or_erase(self):
        self.args.release_c.write_bytes(sign(replace(self.c, bias=self.c.bias + .5), self.key))
        with self.assertRaisesRegex(ValueError, "copy B numerical"):
            self.execute()
        self.assertFalse(self.args.output.exists())
        self.assertFalse(self.transports)
        self.assertFalse(self.restore_commands)

    def test_wrong_policy_is_rejected_before_first_erase(self):
        with self.assertRaisesRegex(RuntimeError, "BUNDLE"):
            self.execute("wrong_policy")
        self.assertFalse(self.restore_commands)
        self.assertEqual(self.campaign_summary()["attempted_trials"], 0)
        self.assertEqual(self.campaign_summary()["status"], "incomplete")
        self.assertEqual(self.campaign_summary()["accepted_updates"], 0)
        self.assertEqual(self.campaign_summary()["inferred_records"], 0)
        self.assertEqual(self.campaign_summary()["completed_restores"], 0)
        self.assertTrue((self.args.output / "preflight_transcript.jsonl").is_file())

    def test_wrong_build_is_rejected_before_first_erase(self):
        with self.assertRaisesRegex(RuntimeError, "application build differs"):
            self.execute("wrong_build")
        self.assertFalse(self.restore_commands)

    def test_first_failed_C_stops_campaign_without_retry_or_second_restore(self):
        with self.assertRaisesRegex(RuntimeError, "not retried"):
            self.execute("lost_C_ack")
        self.assertEqual(len(self.restore_commands), 1)
        self.assertEqual(sum(line.startswith("UPDATE ") for line in self.transports[-1].writes), 2)
        self.assertNotIn("REBOOT", self.transports[-1].writes)
        self.assertFalse((self.args.output / "trial-002").exists())
        failed = json.loads((self.args.output / "trial-001/summary.json").read_text())
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["accepted_updates"], 1)
        self.assertEqual(failed["inferred_records"], 126)
        events = [json.loads(x) for x in (self.args.output / "trial-001/events.jsonl").read_text().splitlines()]
        self.assertTrue(any(row.get("action") == "candidate_C" and "error" in row for row in events))
        self.assertEqual(self.campaign_summary()["status"], "incomplete")
        self.assertEqual(self.campaign_summary()["accepted_updates"], 1)
        self.assertEqual(self.campaign_summary()["inferred_records"], 126)
        self.assertEqual(self.campaign_summary()["completed_restores"], 1)

    def test_erase_failure_preserves_failed_trial_without_opening_runtime(self):
        with self.assertRaisesRegex(RuntimeError, "restore failed"):
            self.execute("erase_failure")
        self.assertEqual(len(self.transports), 1)
        self.assertEqual(len(self.restore_commands), 1)
        self.assertEqual(self.campaign_summary()["attempted_trials"], 1)
        self.assertTrue((self.args.output / "trial-001/summary.json").exists())

    def test_missing_post_reuse_boot_does_not_pass_persistence(self):
        with self.assertRaisesRegex(RuntimeError, "timeout waiting.*boot"):
            self.execute("missing_boot")
        failed = json.loads((self.args.output / "trial-001/summary.json").read_text())
        self.assertEqual(failed["accepted_updates"], 2)
        self.assertFalse(failed["reboot_verified"])
        self.assertEqual(len(self.restore_commands), 1)

    def test_existing_campaign_cannot_be_overwritten_or_resumed(self):
        self.args.output.mkdir()
        marker = self.args.output / "keep.txt"
        marker.write_text("original")
        with self.assertRaises(FileExistsError):
            self.execute()
        self.assertEqual(marker.read_text(), "original")
        self.assertFalse(self.transports)
        self.assertFalse(self.restore_commands)


    def test_old_schema_rejected_before_erase(self):
        with self.assertRaisesRegex(RuntimeError, "timing_schema=2"):
            self.execute("old_timing_schema")
        self.assertFalse(self.restore_commands)

    def test_invalid_stage_sum_stops_before_success_count_or_next_update(self):
        with self.assertRaisesRegex(RuntimeError, "stage sum"):
            self.execute("bad_timing_sum")
        self.assertEqual(self.campaign_summary()["accepted_updates"], 1)
        self.assertEqual(self.campaign_summary()["timing_validated_updates"], 0)
        self.assertEqual(len(self.restore_commands), 1)
        self.assertEqual(sum(line.startswith("UPDATE ") for line in self.transports[-1].writes), 1)

    def test_naive_model_only_fixture_is_rejected_before_output(self):
        self.args.policy = "model_only_factory_preprocess"
        with self.assertRaisesRegex(ValueError, "factory-compatible provenance"):
            self.execute()
        self.assertFalse(self.args.output.exists())
        self.assertFalse(self.transports)

    def compatible_metadata(self):
        path = self.args.experiment / "provenance.json"
        provenance = json.loads(path.read_text())
        provenance.update(update_semantics="factory_preprocessing_compatible", probabilities_preserved=True,
            threshold_adjustment_logit=0,
            fixed_factory_A_payload_sha256=hashlib.sha256(self.context["envelopes"][0][16:-256]).hexdigest(),
            compatibility_source_B_payload_sha256=hashlib.sha256(self.context["envelopes"][1][16:-256]).hexdigest())
        return path, provenance

    def test_model_only_metadata_cannot_hide_stale_preprocessing(self):
        self.args.policy = "model_only_factory_preprocess"
        path, provenance = self.compatible_metadata()
        path.write_text(json.dumps(provenance))
        with self.assertRaisesRegex(ValueError, "preprocessing incompatible"):
            self.execute()
        self.assertFalse(self.args.output.exists())

    def test_compatible_model_only_uses_same_timing_and_runtime_gates(self):
        self.args.policy = "model_only_factory_preprocess"
        path, provenance = self.compatible_metadata()
        for index, letter in ((2, "B"), (3, "C")):
            envelope = sign(replace(self.context["models"][0], version=index, release="synthetic-" + letter), self.key)
            target = self.args.experiment / "release-B.sids" if letter == "B" else self.args.release_c
            target.write_bytes(envelope)
            provenance["package_sha256"][f"release-{letter}.sids"] = hashlib.sha256(envelope).hexdigest()
        path.write_text(json.dumps(provenance))
        self.context = PILOT.preflight(self.args)
        result = self.execute()
        self.assertEqual(result["policy"], "model_only_factory_preprocess")
        self.assertEqual(result["timing_validated_updates"], 4)
        self.assertEqual(result["status"], "complete")

    def test_real_instrumented_compatible_artifacts_preflight_without_hardware(self):
        fixture = ROOT / "examples/instrumented_compatible"
        firmware = ROOT / "prebuilt/instrumented_v2/model_only/ids_update_lab.bin"
        required = [firmware] + [fixture / name for name in (
            "public.pem", "feature_contract.json", "provenance.json", "golden.jsonl",
            "release-A.sids", "release-B.sids", "release-C.sids")]
        if not all(path.is_file() for path in required):
            self.skipTest("complete historical cross-compiled compatible fixtures are not installed")
        args = SimpleNamespace(**vars(self.args))
        args.policy = "model_only_factory_preprocess"
        args.experiment, args.release_c, args.firmware_bin = fixture, fixture / "release-C.sids", firmware
        context = PILOT.preflight(args)
        self.assertEqual(context["policy"], args.policy)
        self.assertEqual(len(context["rows"]), 63)
        self.assertFalse(args.output.exists())


if __name__ == "__main__":
    unittest.main()
