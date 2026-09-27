"""Host-only whole-image tooling tests.

The fixture only mimics ESP image/app-desc offsets. It is NOT a valid ESP image,
does NOT exercise esp_ota_end, and is NOT evidence of an MCU or power-loss run.
The serial fake verifies host response handling, not device implementation.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("firmware_ota_tool", ROOT / "tools/firmware_ota.py")
OTA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OTA)
from cryptography.exceptions import InvalidSignature
from ids_update_lab.package import generate_keys, Model, sign


class FirmwareOtaHostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ids-fw-host-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = generate_keys(self.root / "keys")
        self.model = Model(2, "host-test-only", bytes(range(32)), (0.,), (1.,), (1.,), 0.)
        self.envelope = sign(self.model, self.key)
        (self.root / "factory.sids").write_bytes(self.envelope)
        image = bytearray(80)
        image[0] = 0xE9
        struct.pack_into("<I", image, 32, 0xABCD5432)
        image[48:50] = b"2\0"
        self.image = bytes(image) + self.envelope
        (self.root / "image.bin").write_bytes(self.image)
        self.args = argparse.Namespace(image=self.root / "image.bin",
            factory_envelope=self.root / "factory.sids", private_key=self.root / "keys/private.pem",
            public_key=self.root / "keys/public.pem", max_image_bytes=0x1D0000,
            out=self.root / "prepared")

    def prepare(self):
        with contextlib.redirect_stdout(io.StringIO()):
            OTA.prepare(self.args)
        return self.args.out

    def test_prepared_manifest_binds_image_and_factory_without_private_key(self):
        output = self.prepare()
        _, metadata, signature, info = OTA.validate_artifact(output)
        self.assertEqual((len(metadata), len(signature)), (84, 256))
        self.assertEqual(info["version"], 2)
        self.assertFalse((output / "private.pem").exists())
        self.assertFalse(json.loads((output / "manifest.json").read_text())["hardware_measurement"])

    def test_image_tamper_is_rejected_before_transport(self):
        output = self.prepare()
        altered = bytearray(self.image)
        altered[-1] ^= 1
        (output / "image.bin").write_bytes(altered)
        with self.assertRaisesRegex(ValueError, "metadata does not describe"):
            OTA.validate_artifact(output)

    def test_metadata_version_tamper_invalidates_signature(self):
        output = self.prepare()
        data = bytearray((output / "metadata.bin").read_bytes())
        data[8] = 3
        (output / "metadata.bin").write_bytes(data)
        with self.assertRaises(InvalidSignature):
            OTA.validate_artifact(output)

    def test_image_descriptor_version_must_match_factory(self):
        image = bytearray(self.image)
        image[48] = ord("3")
        self.args.image.write_bytes(image)
        with self.assertRaisesRegex(ValueError, "PROJECT_VER does not match"):
            self.prepare()
        self.assertFalse(self.args.out.exists())

    def test_exact_factory_envelope_must_exist_once(self):
        self.args.image.write_bytes(self.image + self.envelope)
        with self.assertRaisesRegex(ValueError, "exactly once"):
            self.prepare()

    def test_existing_evidence_directory_is_not_overwritten(self):
        output = self.prepare()
        before = (output / "manifest.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(before, (output / "manifest.json").read_bytes())

    def serial_fake(self, falsely_accept=False):
        schema = self.model.schema.hex()
        class FakeSerial:
            def __init__(self, **kwargs):
                self.queue = bytearray()
                self.is_open = False
                self.image = bytearray()
            def open(self): self.is_open = True
            def close(self): self.is_open = False
            def flush(self): pass
            def read(self, length):
                data = bytes(self.queue[:length])
                del self.queue[:length]
                return data
            def write(self, data):
                command = data.decode().strip().split()
                if command[0] == "STATUS":
                    reply = dict(event="status", ready=True, policy="whole_firmware",
                                 version=1, schema=schema, release="A", bundle_sha256="fixed")
                elif command[0] == "FW_BEGIN":
                    self.meta = OTA.META.unpack(bytes.fromhex(command[1]))
                    reply = dict(event="fw_begin", ok=True, version=self.meta[1], size=self.meta[2])
                elif command[0] == "FW_CHUNK":
                    if int(command[1]) != len(self.image):
                        raise AssertionError("host sent unordered chunk")
                    self.image += bytes.fromhex(command[2])
                    reply = dict(event="fw_chunk", ok=True, offset=len(self.image))
                elif command[0] == "FW_END":
                    if falsely_accept or hashlib.sha256(self.image).digest() == self.meta[3]:
                        reply = dict(event="fw_ready", ok=True, version=self.meta[1], bytes=len(self.image))
                    else:
                        reply = dict(event="fw_error", ok=False, error="image_sha256")
                elif command[0] == "FW_ABORT":
                    reply = dict(event="fw_abort", ok=True)
                else:
                    raise AssertionError("unexpected host command")
                self.queue.extend((json.dumps(reply) + "\n").encode())
                return len(data)
        return types.SimpleNamespace(Serial=FakeSerial)

    def send_args(self, negative):
        return argparse.Namespace(artifact=self.prepare(), port="HOST_MOCK_ONLY", baud=115200,
            out=self.root / "mock-evidence", timeout=1., chunk_bytes=256, negative_image_hash=negative)

    def test_mock_serial_negative_requires_rejection_and_unchanged_state(self):
        args = self.send_args(True)
        with patch.dict(sys.modules, {"serial": self.serial_fake()}), contextlib.redirect_stdout(io.StringIO()):
            OTA.send(args)
        result = json.loads((args.out / "summary.json").read_text())
        self.assertTrue(result["negative_control_passed"])
        self.assertFalse(result["completed"])
        self.assertFalse(result["boot_verified"])
        self.assertFalse(result["reboot_issued"])

    def test_mock_serial_detects_false_acceptance(self):
        args = self.send_args(True)
        with patch.dict(sys.modules, {"serial": self.serial_fake(falsely_accept=True)}):
            with self.assertRaisesRegex(RuntimeError, "accepted a deliberately corrupted"):
                OTA.send(args)
        self.assertFalse(json.loads((args.out / "summary.json").read_text())["completed"])

    def test_mock_serial_success_does_not_claim_successful_boot(self):
        args = self.send_args(False)
        with patch.dict(sys.modules, {"serial": self.serial_fake()}), contextlib.redirect_stdout(io.StringIO()):
            OTA.send(args)
        result = json.loads((args.out / "summary.json").read_text())
        self.assertTrue(result["completed"])
        self.assertFalse(result["boot_verified"])
        self.assertFalse(result["reboot_issued"])


if __name__ == "__main__":
    unittest.main()
