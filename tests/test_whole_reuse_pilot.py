"""Instrumented whole-reuse host mocks. Synthetic descriptors are not bootable."""
from collections import deque
import contextlib
from dataclasses import replace
import hashlib
import importlib.util
import io
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
sys.path.insert(0, str(ROOT / "tools"))
import run_whole_reuse_pilot as PILOT
from ids_update_lab.artifacts import generate_demo
from ids_update_lab.package import generate_keys, infer, sign, verify, load_public


class WholeReuseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ids-instrumented-whole-mock-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        key = generate_keys(self.root / "keys")
        experiment = generate_demo(self.root / "experiment", key)
        model_b = verify((experiment / "release-B.sids").read_bytes(), load_public(experiment / "public.pem"))
        c_path = experiment / "release-C.sids"
        c_path.write_bytes(sign(replace(model_b, version=3, release="synthetic-C"), key))
        for index, letter in enumerate("ABC", 1):
            image = bytearray(288)
            image[0] = 0xE9
            struct.pack_into("<I", image, 32, 0xABCD5432)
            image[48:50] = str(index).encode() + b"\0"
            image[144:152] = b"v5.3.2\0\0"
            image[176:208] = bytes([index]) * 32
            image.extend((experiment / f"release-{letter}.sids").read_bytes())
            path = self.root / f"{letter}.bin"
            path.write_bytes(image)
            if index > 1:
                with contextlib.redirect_stdout(io.StringIO()):
                    PILOT.firmware_ota.prepare(SimpleNamespace(image=path, factory_envelope=experiment / f"release-{letter}.sids",
                        private_key=self.root / "keys/private.pem", public_key=experiment / "public.pem",
                        max_image_bytes=0x1d0000, out=self.root / f"artifact-{letter}"))
        entries = [("nvs", 1, 2, 0x9000, 0x4000), ("otadata", 1, 0, 0xd000, 0x2000),
            ("ota_0", 0, 16, 0x10000, 0x1d0000), ("ota_1", 0, 17, 0x1e0000, 0x1d0000),
            ("ids_a", 1, 64, 0x3b0000, 0x10000), ("ids_b", 1, 65, 0x3c0000, 0x10000)]
        table = b"".join(struct.pack("<HBBII16sI", 0x50aa, kind, subtype, offset, size, name.encode(), 0)
            for name, kind, subtype, offset, size in entries)
        table += b"\xeb\xeb" + b"\xff" * 14 + hashlib.md5(table).digest()
        (self.root / "partitions.bin").write_bytes(table.ljust(3072, b"\xff"))
        (self.root / "ota.bin").write_bytes(b"\xff" * 8192)
        self.args = SimpleNamespace(port="HOST_MOCK_ONLY", board_id="HOST_MOCK_ONLY", experiment=experiment,
            release_c=c_path, factory_bin=self.root / "A.bin", artifact_b=self.root / "artifact-B", artifact_c=self.root / "artifact-C",
            partition_table=self.root / "partitions.bin", ota_data=self.root / "ota.bin", output=self.root / "campaign", trials=2, timeout=.025)
        self.context = PILOT.preflight(self.args)
        self.transports, self.restores = [], []
        self.release = 0

    def execute(self, mode="normal"):
        owner = self
        class FakeTransport:
            def __init__(self, port, on_read):
                self.on_read, self.received_bytes = on_read, 0
                self.queue, self.writes = deque(), []
                self.closed = False
                owner.transports.append(self)
            def emit(self, response):
                line = json.dumps(response)
                self.queue.append(line)
                raw = (line + "\n").encode()
                self.received_bytes += len(raw)
                self.on_read(raw)
            def status(self, event="status"):
                i = owner.release
                identity = owner.context["identities"][i]
                return {"event": event, "ready": True, "reason": "ok", "policy": "bundle" if mode == "wrong_policy" else "whole_firmware",
                    "chip": "esp32s3", "schema": owner.context["schema"], "feature_count": 2, "data_origin": "synthetic_plumbing",
                    "version": i + 1, "release": owner.context["models"][i].release, "bundle_sha256": owner.context["payload_hashes"][i],
                    "build": f"esp-idf-v5.3.2;app={i+1};elf=" + ("deadbeef0" if mode == "wrong_build" else identity['elf_sha256'][:9]), "active_slot": -1,
                    "timing_schema": 1 if mode == "old_schema" else 2, "crypto_context": "shared_warm",
                    "crypto_key_setup_us": 1, "crypto_first_verify_us": 5}
            def write(self, line):
                self.writes.append(line)
                if not line:
                    return
                command, _, tail = line.partition(" ")
                if command == "STATUS":
                    self.emit(self.status())
                elif command == "INFER":
                    p, label = infer(owner.context["models"][owner.release], [float(x) for x in tail.split(",")])
                    self.emit({**self.status(), "event": "inference", "probability": p, "label": label, "latency_us": 7})
                elif command == "FW_BEGIN":
                    metadata = PILOT.firmware_ota.META.unpack(bytes.fromhex(tail.split()[0]))
                    self.target, self.size = metadata[1] - 1, metadata[2]
                    if self.target != owner.release + 1:
                        raise AssertionError("unexpected target version")
                    self.written, self.count = 0, 0
                    self.emit({"event": "fw_begin", "ok": True, "version": self.target + 1, "size": self.size,
                        "timing_schema": 2, "crypto_context": "shared_warm", "signature_verify_us": 2,
                        "partition_prepare_us": 3, "begin_us": 6})
                elif command == "FW_CHUNK":
                    offset, raw = tail.split()
                    if int(offset) != self.written:
                        raise AssertionError("chunk offset sent twice or out of order")
                    self.written += len(bytes.fromhex(raw))
                    self.count += 1
                    if mode == "lost_ack":
                        return
                    self.emit({"event": "fw_chunk", "ok": True, "offset": self.written, "timing_schema": 2,
                        "write_us": 2, "hash_us": 1, "chunk_us": 4, "write_sum_us": self.count * 2,
                        "hash_sum_us": self.count + (1 if mode == "bad_chunk_sum" else 0),
                        "chunk_sum_us": self.count * 4, "chunk_count": self.count})
                elif command == "FW_END":
                    self.emit({"event": "fw_ready", "ok": True, "version": self.target + 1, "bytes": self.written,
                        "reboot_required": True, "timing_schema": 2, "begin_us": 6, "write_sum_us": self.count * 2,
                        "hash_sum_us": self.count, "chunk_sum_us": self.count * 4, "chunk_count": self.count,
                        "finalize_us": 5, "device_active_us": 11 + self.count * 4 + (1 if mode == "bad_ready_total" else 0)})
                elif command == "REBOOT":
                    self.emit({"event": "reboot", "fault_kind": "software_restart"})
                    owner.release = self.target
                    if mode != "missing_boot":
                        self.emit(self.status("boot"))
                else:
                    raise AssertionError("unexpected command " + command)
            def readline(self, timeout):
                if self.queue:
                    return self.queue.popleft()
                time.sleep(min(timeout, .001))
                return None
            def close(self):
                self.closed = True
            def take_pending_fragment(self):
                return b""
        original = PILOT.component.synchronize_serial
        def quick_sync(transport, record, timeout):
            return original(transport, record, timeout, startup_wait=0, quiet_period=.001)
        def fake_esptool(command, *, stdout, stderr, text, timeout, check):
            self.assertTrue(all(t.closed for t in self.transports))
            self.restores.append(command)
            if "write_flash" in command:
                self.assertIn("no_reset", command)
                for address in ("0x8000", "0xd000", "0x10000"):
                    self.assertIn(address, command)
                stdout.write("Hash of data verified\n")
            else:
                self.assertEqual(command[-3:], ["erase_region", "0x1e0000", "0x1d0000"])
                self.assertIn("hard_reset", command)
                stdout.write("Erase completed successfully\n")
                self.release = 0
            return SimpleNamespace(returncode=0)
        with patch.object(PILOT.component, "SerialTransport", FakeTransport), patch.object(PILOT.component, "synchronize_serial", quick_sync), \
             patch.object(PILOT.subprocess, "run", fake_esptool), contextlib.redirect_stdout(io.StringIO()):
            return PILOT.run(self.args)

    def result(self):
        return json.loads((self.args.output / "campaign_summary.json").read_text())

    def test_two_complete_trials_account_chunks_activation_and_no_negative(self):
        result = self.execute()
        self.assertEqual((result["completed_trials"], result["accepted_updates"], result["timing_validated_updates"], result["boot_verified_updates"], result["inferred_records"]), (2, 4, 4, 4, 378))
        self.assertEqual(len(self.restores), 4)
        for transport in self.transports[1:]:
            self.assertEqual(transport.writes.count("REBOOT"), 2)
            self.assertEqual(transport.writes.count("FW_END"), 2)
            self.assertEqual(sum(line.startswith("FW_BEGIN ") for line in transport.writes), 2)
        events = [json.loads(line) for line in (self.args.output / "trial-001/events.jsonl").read_text().splitlines()]
        transfers = [row for row in events if row.get("action", "").endswith("_transfer")]
        self.assertEqual([row["destination_state"] for row in transfers], ["explicitly_erased", "previously_accepted_release_A"])
        self.assertTrue(all(row["device_active_us"] == row["begin_us"] + row["chunk_sum_us"] + row["finalize_us"] for row in transfers))

    def test_wrong_policy_stops_before_flash_or_erase(self):
        with self.assertRaisesRegex(RuntimeError, "whole-firmware"):
            self.execute("wrong_policy")
        self.assertFalse(self.restores)

    def test_old_schema_stops_before_flash_or_erase(self):
        with self.assertRaisesRegex(RuntimeError, "timing_schema=2"):
            self.execute("old_schema")
        self.assertFalse(self.restores)

    def test_wrong_build_stops_before_flash_or_erase(self):
        with self.assertRaisesRegex(RuntimeError, "build differs"):
            self.execute("wrong_build")
        self.assertFalse(self.restores)

    def test_bad_chunk_cumulative_stops_before_end_or_retry(self):
        with self.assertRaisesRegex(RuntimeError, "cumulative hash_sum_us"):
            self.execute("bad_chunk_sum")
        self.assertEqual(self.result()["accepted_updates"], 0)
        self.assertEqual(len(self.restores), 2)
        self.assertNotIn("FW_END", self.transports[-1].writes)
        self.assertEqual(sum(line.startswith("FW_CHUNK ") for line in self.transports[-1].writes), 1)

    def test_bad_ready_timing_keeps_acceptance_but_does_not_claim_timing_or_boot(self):
        with self.assertRaisesRegex(RuntimeError, "device_active_us"):
            self.execute("bad_ready_total")
        result = self.result()
        self.assertEqual((result["accepted_updates"], result["timing_validated_updates"], result["boot_verified_updates"]), (1, 0, 0))
        self.assertNotIn("REBOOT", self.transports[-1].writes)

    def test_missing_boot_preserves_selected_image_without_claiming_runtime(self):
        with self.assertRaisesRegex(RuntimeError, "timeout waiting.*boot"):
            self.execute("missing_boot")
        self.assertEqual((self.result()["accepted_updates"], self.result()["boot_verified_updates"], self.result()["inferred_records"]), (1, 0, 63))
        self.assertEqual(self.transports[-1].writes.count("REBOOT"), 1)
        self.assertEqual(len(self.restores), 2)

    def test_lost_ack_never_retries_chunk_or_second_trial(self):
        with self.assertRaisesRegex(RuntimeError, "not retried"):
            self.execute("lost_ack")
        self.assertEqual(sum(line.startswith("FW_CHUNK ") for line in self.transports[-1].writes), 1)
        self.assertFalse((self.args.output / "trial-002").exists())

    def test_partition_or_ota_tamper_fails_before_output(self):
        self.args.ota_data.write_bytes(b"\0" + b"\xff" * 8191)
        with self.assertRaisesRegex(ValueError, "initial OTA data"):
            self.execute()
        self.assertFalse(self.args.output.exists())
        self.assertFalse(self.transports)


if __name__ == "__main__":
    unittest.main()
