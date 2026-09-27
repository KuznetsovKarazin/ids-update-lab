"""Host control-flow tests with synthetic USB responses, NOT MCU measurements.

The small signed images mimic ESP app_desc offsets; they are not bootable ESP
images. These tests exercise the host gates and evidence accounting only.
"""
from collections import deque
import contextlib
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
SPEC = importlib.util.spec_from_file_location("whole_pilot_tool", ROOT / "tools/run_whole_firmware_pilot.py")
PILOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PILOT)
REPORT_SPEC = importlib.util.spec_from_file_location("whole_report_tool", ROOT / "tools/summarize_runs.py")
REPORT = importlib.util.module_from_spec(REPORT_SPEC)
REPORT_SPEC.loader.exec_module(REPORT)
from ids_update_lab.artifacts import generate_demo
from ids_update_lab.package import generate_keys, infer


class FakeUsb:
    def __init__(self, context, mode, **kwargs):
        if kwargs["port"] is not None:
            raise AssertionError("must configure DTR/RTS before opening")
        self.context, self.mode = context, mode
        self.port = None
        self.dtr = self.rts = True
        self.timeout = kwargs["timeout"]
        self.queue = bytearray(b'{"event":"boot","release"')
        self.writes = []
        self.release = 0
        self.transfers = 0
        self.closed = False

    def open(self):
        if self.dtr or self.rts:
            raise AssertionError("DTR/RTS asserted at open")

    @property
    def in_waiting(self):
        return len(self.queue)

    def read(self, size):
        # Split frames deliberately so production SerialTransport must assemble.
        chunk = bytes(self.queue[:min(size, 23)])
        del self.queue[:len(chunk)]
        if not chunk:
            time.sleep(min(self.timeout, .001))
        return chunk

    def flush(self):
        pass

    def close(self):
        self.closed = True

    def status(self, event="status"):
        model = self.context["models"][self.release]
        identity = self.context["identities"][self.release]
        build = f"esp-idf-{identity['idf_version']};app={model.version};elf={identity['elf_sha256'][:9]}"
        if self.mode == "wrong_B_identity" and self.release == 1:
            build = build[:-9] + "deadbeef0"
        return {"event": event, "ready": True, "reason": "ok", "version": model.version,
            "release": model.release, "schema": self.context["schema"], "feature_count": len(model.means),
            "policy": "whole_firmware", "chip": "esp32s3", "build": build,
            "data_origin": self.context["origin"], "active_slot": -1,
            "bundle_sha256": hashlib.sha256(self.context["envelopes"][self.release][16:-256]).hexdigest()}

    def emit(self, response):
        self.queue.extend((json.dumps(response) + "\r\n").encode("ascii"))

    def write(self, data):
        self.writes.append(data)
        line = data.decode("ascii").strip()
        if not line:
            return len(data)
        command, _, tail = line.partition(" ")
        if command == "STATUS":
            self.emit(self.status())
        elif command == "INFER":
            probability, label = infer(self.context["models"][self.release], [float(x) for x in tail.split(",")])
            self.emit({**self.status(), "event": "inference", "probability": probability, "label": label,
                       "latency_us": 10, "free_heap": 320000})
        elif command == "FW_BEGIN":
            if self.release == 1:
                if self.mode == "replay_accept":
                    self.emit({"event": "fw_begin", "ok": True, "version": 2, "size": len(self.context["image"])})
                else:
                    self.emit({"event": "fw_error", "ok": False, "error": "non_monotonic_version"})
            else:
                self.transfers += 1
                self.image = bytearray()
                self.emit({"event": "fw_begin", "ok": True, "version": 2, "size": len(self.context["image"]),
                           "signature_verify_us": 11, "partition_prepare_us": 12})
        elif command == "FW_CHUNK":
            raw_offset, raw_chunk = tail.split(" ")
            if int(raw_offset) != len(self.image):
                raise AssertionError("host chunk ordering failed")
            self.image.extend(bytes.fromhex(raw_chunk))
            if self.mode == "lost_chunk_ack":
                return len(data)
            offset = len(self.image) + (1 if self.mode == "bad_chunk_offset" else 0)
            self.emit({"event": "fw_chunk", "ok": True, "offset": offset})
        elif command == "FW_END":
            matched = hashlib.sha256(self.image).digest() == hashlib.sha256(self.context["image"]).digest()
            if matched or self.mode == "negative_false_accept":
                self.emit({"event": "fw_ready", "ok": True, "version": 2, "bytes": len(self.image),
                           "finalize_us": 13, "reboot_required": True})
            else:
                self.emit({"event": "fw_error", "ok": False, "error": "image_sha256"})
                if self.mode == "changed_after_negative":
                    self.release = 1
        elif command == "REBOOT":
            self.emit({"event": "reboot", "fault_kind": "software_restart"})
            self.release = 1
            if self.mode != "missing_boot":
                self.emit(self.status("boot"))
        else:
            raise AssertionError("unexpected command: " + command)
        return len(data)


class WholeFirmwarePilotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ids-whole-host-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        key = generate_keys(self.root / "keys")
        experiment = generate_demo(self.root / "experiment", key)
        for version, letter in enumerate("AB", 1):
            image = bytearray(288)
            image[0] = 0xE9
            struct.pack_into("<I", image, 32, 0xABCD5432)
            image[48:50] = str(version).encode() + b"\0"
            image[144:152] = b"v5.3.2\0\0"
            image[176:208] = bytes([version]) * 32
            image.extend((experiment / f"release-{letter}.sids").read_bytes())
            (self.root / f"{letter}.bin").write_bytes(image)
        with contextlib.redirect_stdout(io.StringIO()):
            PILOT.firmware_ota.prepare(SimpleNamespace(image=self.root / "B.bin", factory_envelope=experiment / "release-B.sids",
                private_key=self.root / "keys/private.pem", public_key=experiment / "public.pem",
                max_image_bytes=0x1D0000, out=self.root / "artifact"))
        self.args = SimpleNamespace(port="HOST_MOCK_ONLY", experiment=experiment,
            factory_bin=self.root / "A.bin", artifact=self.root / "artifact", output=self.root / "run",
            board_id="HOST_MOCK_ONLY", timeout=.04)
        self.context = PILOT.preflight(self.args)
        self.devices = []

    def execute(self, mode="normal"):
        def factory(**kwargs):
            device = FakeUsb(self.context, mode, **kwargs)
            self.devices.append(device)
            return device
        original_sync = PILOT.synchronize_serial
        def fast_sync(transport, record, timeout):
            return original_sync(transport, record, timeout, startup_wait=0, quiet_period=.001)
        fake_serial = SimpleNamespace(Serial=factory, SerialException=OSError)
        with patch.dict(sys.modules, {"serial": fake_serial}), patch.object(PILOT, "synchronize_serial", fast_sync), contextlib.redirect_stdout(io.StringIO()):
            return PILOT.run(self.args)

    def summary(self):
        return json.loads((self.args.output / "summary.json").read_text())

    def test_nominal_requires_negative_boot_inference_replay_and_reports_126_primary(self):
        summary = self.execute()
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["inferred_records"], 126)
        for gate in ("negative_control_passed", "transfer_completed", "reboot_issued", "boot_verified", "replay_rejected"):
            self.assertIs(summary[gate], True)
        device = self.devices[0]
        self.assertTrue(device.closed)
        self.assertEqual(device.writes.count(b"REBOOT\n"), 1)
        self.assertEqual(sum(x.startswith(b"INFER ") for x in device.writes), 127)
        self.assertEqual(device.transfers, 2)
        transcript = [json.loads(x) for x in (self.args.output / "transcript.jsonl").read_text().splitlines()]
        self.assertTrue(any(x.get("phase") == "startup_fragment" for x in transcript))
        self.assertTrue(any(x.get("direction") == "rx_bytes" for x in transcript))
        report = REPORT.summarize_run(self.args.output)
        self.assertFalse(report["has_report_errors"], report["report_errors"])
        self.assertEqual(report["prediction_rows"], 126)
        self.assertEqual(report["candidate_B_wire_bytes"], summary["valid_update_tx_wire_bytes"])
        self.assertGreater(report["update_wire_bytes"], report["candidate_B_wire_bytes"] * 2)
        self.assertTrue(any(x.get("event") == "fw_ready" for x in report["update_outcomes"]))

    def test_artifact_tamper_fails_before_output_or_device(self):
        image = self.args.artifact / "image.bin"
        data = bytearray(image.read_bytes())
        data[-1] ^= 1
        image.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "metadata does not describe"):
            self.execute()
        self.assertFalse(self.args.output.exists())
        self.assertFalse(self.devices)

    def test_corrupted_image_false_acceptance_stops_before_valid_transfer(self):
        with self.assertRaisesRegex(RuntimeError, "corrupted image was not rejected"):
            self.execute("negative_false_accept")
        self.assertFalse(self.summary()["negative_control_passed"])
        self.assertEqual(self.devices[0].transfers, 1)
        self.assertNotIn(b"REBOOT\n", self.devices[0].writes)

    def test_state_change_after_rejected_image_fails(self):
        with self.assertRaisesRegex(RuntimeError, "unexpected release A status"):
            self.execute("changed_after_negative")
        self.assertFalse(self.summary()["negative_control_passed"])
        self.assertEqual(self.devices[0].transfers, 1)

    def test_wrong_ack_offset_is_not_accepted(self):
        with self.assertRaisesRegex(RuntimeError, "acknowledged offset"):
            self.execute("bad_chunk_offset")
        writes = self.devices[0].writes
        self.assertEqual(sum(x.startswith(b"FW_CHUNK ") for x in writes), 1)
        self.assertNotIn(b"FW_END\n", writes)

    def test_lost_chunk_ack_never_retries_mutating_command(self):
        with self.assertRaisesRegex(RuntimeError, "command is not retried"):
            self.execute("lost_chunk_ack")
        self.assertEqual(sum(x.startswith(b"FW_CHUNK ") for x in self.devices[0].writes), 1)
        self.assertEqual(self.summary()["status"], "failed")

    def test_fw_ready_does_not_establish_boot_success(self):
        with self.assertRaisesRegex(RuntimeError, "timeout waiting.*boot"):
            self.execute("missing_boot")
        summary = self.summary()
        self.assertTrue(summary["transfer_completed"])
        self.assertFalse(summary["boot_verified"])
        self.assertEqual(summary["inferred_records"], 63)
        self.assertEqual(self.devices[0].writes.count(b"REBOOT\n"), 1)
        self.assertNotIn(b"FW_ABORT\n", self.devices[0].writes)

    def test_wrong_B_build_is_rejected_before_post_update_inference(self):
        with self.assertRaisesRegex(RuntimeError, "runtime build differs"):
            self.execute("wrong_B_identity")
        self.assertFalse(self.summary()["boot_verified"])
        self.assertEqual(self.summary()["inferred_records"], 63)

    def test_replay_acceptance_fails_even_after_successful_B_boot(self):
        with self.assertRaisesRegex(RuntimeError, "timeout waiting"):
            self.execute("replay_accept")
        summary = self.summary()
        self.assertTrue(summary["boot_verified"])
        self.assertFalse(summary["replay_rejected"])
        self.assertEqual(summary["inferred_records"], 126)
        self.assertEqual(summary["status"], "failed")

    def test_existing_output_is_never_overwritten(self):
        self.args.output.mkdir()
        sentinel = self.args.output / "keep.txt"
        sentinel.write_text("original evidence")
        with self.assertRaises(FileExistsError):
            self.execute()
        self.assertEqual(sentinel.read_text(), "original evidence")
        self.assertFalse(self.devices)


if __name__ == "__main__":
    unittest.main()
