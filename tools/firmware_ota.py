#!/usr/bin/env python3
"""Prepare/send authenticated whole-image OTA for the controlled ESP32-S3 baseline.

No hardware access occurs in prepare/inspect. send requires an explicit serial
port. No key is generated here, no eFuse is touched, and no automatic reboot is
issued. Outputs use new directories; existing evidence is never overwritten.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host"))
from ids_update_lab.package import load_private, load_public, verify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

META = struct.Struct("<8sII32sI32s")
MAGIC = b"SIDSFW1\0"
MAX_CHUNK = 256
assert META.size == 84


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_new(path: Path, data: bytes) -> None:
    with path.open("xb") as f:
        f.write(data)


def image_version(image: bytes) -> int:
    # ESP-IDF application binary: image header (24) + first segment header (8),
    # then esp_app_desc_t. Its version field starts 16 bytes into app_desc.
    if len(image) < 80 or image[0] != 0xE9 or struct.unpack_from("<I", image, 32)[0] != 0xABCD5432:
        raise ValueError("not an ESP-IDF application image with app_desc in its first segment")
    field = image[48:80]
    if b"\0" not in field:
        raise ValueError("application version is not terminated")
    raw = field.split(b"\0", 1)[0]
    if not raw.isdigit() or raw.startswith(b"0") or len(raw) > 10:
        raise ValueError("PROJECT_VER must be the positive decimal factory bundle version")
    version = int(raw)
    if not 1 <= version <= 0xFFFFFFFF:
        raise ValueError("PROJECT_VER is outside uint32")
    return version


def prepare(args) -> None:
    image = args.image.read_bytes()
    envelope = args.factory_envelope.read_bytes()
    private = load_private(args.private_key)
    public = load_public(args.public_key)
    if private.public_key().public_numbers() != public.public_numbers():
        raise ValueError("private/public key mismatch")
    model = verify(envelope, public)
    if image_version(image) != model.version:
        raise ValueError("image PROJECT_VER does not match the verified factory envelope")
    # Ensure that the artifact actually embeds this exact, signed factory model.
    # The firmware also checks factory validation and version at every boot.
    if image.count(envelope) != 1:
        raise ValueError("image must embed the exact supplied factory envelope exactly once")
    if not len(image) <= args.max_image_bytes:
        raise ValueError("image exceeds --max-image-bytes")
    metadata = META.pack(MAGIC, model.version, len(image), hashlib.sha256(image).digest(), 1, model.schema)
    signature = private.sign(metadata, padding.PKCS1v15(), hashes.SHA256())
    manifest = {
        "format": "ids-update-lab-whole-firmware-v1",
        "created_utc": now(), "version": model.version, "runtime_abi": 1,
        "image_size": len(image), "image_sha256": sha256(image),
        "metadata_sha256": sha256(metadata), "signature_sha256": sha256(signature),
        "feature_contract_sha256": model.schema.hex(),
        "factory_envelope_sha256": sha256(envelope),
        "authentication": "RSA-2048-PKCS1-v1_5-SHA256 over exact 84-byte metadata",
        "trust_boundary": "trusted running firmware; no ROM-rooted secure boot claim",
        "hardware_measurement": False,
    }
    args.out.mkdir(parents=True, exist_ok=False)
    for name, data in (("image.bin", image), ("metadata.bin", metadata), ("signature.bin", signature),
                       ("factory.sids", envelope), ("public.pem", public.public_bytes(
                           serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))):
        write_new(args.out / name, data)
    write_new(args.out / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    print(json.dumps({"prepared": str(args.out), **manifest}, indent=2))


def validate_artifact(directory: Path):
    image = (directory / "image.bin").read_bytes()
    metadata = (directory / "metadata.bin").read_bytes()
    signature = (directory / "signature.bin").read_bytes()
    public = load_public(directory / "public.pem")
    if len(metadata) != META.size or len(signature) != 256:
        raise ValueError("metadata/signature size mismatch")
    public.verify(signature, metadata, padding.PKCS1v15(), hashes.SHA256())
    magic, version, length, digest, abi, schema = META.unpack(metadata)
    if magic != MAGIC or abi != 1 or not version or length != len(image) or digest != hashlib.sha256(image).digest():
        raise ValueError("metadata does not describe the image")
    if image_version(image) != version:
        raise ValueError("embedded PROJECT_VER mismatch")
    envelope = (directory / "factory.sids").read_bytes()
    model = verify(envelope, public, schema)
    if model.version != version or image.count(envelope) != 1:
        raise ValueError("embedded factory envelope mismatch")
    return image, metadata, signature, {"version": version, "image_size": length,
        "image_sha256": digest.hex(), "feature_contract_sha256": schema.hex()}


def send(args) -> None:
    import serial  # optional dependency; only required for explicit hardware action
    image, metadata, signature, info = validate_artifact(args.artifact)
    args.out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    result = {"started_utc": now(), "port": args.port, "baud": args.baud, **info,
              "hardware_attempted": True, "completed": False, "boot_verified": False,
              "reboot_issued": False, "chunk_bytes": args.chunk_bytes,
              "negative_control": "image_sha256" if args.negative_image_hash else None}
    if args.negative_image_hash:
        # Corrupt one byte after local artifact validation. Preserve the ESP
        # header so that final streamed-digest rejection is the expected stage.
        image = image[:-1] + bytes([image[-1] ^ 1])
        result["transmitted_image_sha256"] = sha256(image)
    with (args.out / "serial.jsonl").open("x", encoding="utf-8") as log:
        def record(kind, payload):
            log.write(json.dumps({"utc": now(), "elapsed_s": time.monotonic()-started,
                                  "kind": kind, **payload}) + "\n")
            log.flush()
        link = serial.Serial(port=None, baudrate=args.baud, timeout=0.2, write_timeout=args.timeout)
        # Avoid intentional automatic reset through RTS/DTR; USB-UART drivers can
        # still transiently toggle lines on open, which is recorded in raw RX.
        link.dtr = False
        link.rts = False
        link.port = args.port
        def command(line: str, event: str, expected_error=None):
            record("tx", {"command": line})
            link.write((line + "\n").encode("ascii"))
            link.flush()
            deadline = time.monotonic() + args.timeout
            buffered = bytearray()
            while time.monotonic() < deadline:
                data = link.read(1)
                if not data:
                    continue
                if data != b"\n":
                    buffered.extend(data)
                    if len(buffered) > 8192:
                        record("rx_overlong", {"bytes": len(buffered)})
                        buffered.clear()
                    continue
                raw = bytes(buffered).decode("utf-8", errors="replace").rstrip("\r")
                buffered.clear()
                record("rx", {"line": raw})
                try:
                    reply = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(reply, dict):
                    continue
                if reply.get("event") == "fw_error":
                    if expected_error is not None and reply.get("error") == expected_error and reply.get("ok") is False:
                        return reply
                    raise RuntimeError("device rejected transfer: " + str(reply.get("error")))
                if reply.get("event") == event and (reply.get("ok") is True or event == "status"):
                    if expected_error is not None:
                        raise RuntimeError("device accepted a deliberately corrupted image")
                    return reply
            raise TimeoutError("no expected response: " + event)
        try:
            link.open()
            before = command("STATUS", "status")
            result["before_status"] = before
            if before.get("ready") is not True or before.get("policy") != "whole_firmware":
                raise RuntimeError("device is not a ready whole-firmware baseline")
            if before.get("schema") != info["feature_contract_sha256"] or not isinstance(before.get("version"), int) or before["version"] >= info["version"]:
                raise RuntimeError("device schema/version incompatible with update")
            begin = command("FW_BEGIN " + metadata.hex() + " " + signature.hex(), "fw_begin")
            if begin.get("version") != info["version"] or begin.get("size") != len(image):
                raise RuntimeError("unexpected FW_BEGIN acknowledgment")
            result["begin_reply"] = begin
            for offset in range(0, len(image), args.chunk_bytes):
                chunk = image[offset:offset+args.chunk_bytes]
                reply = command(f"FW_CHUNK {offset} {chunk.hex()}", "fw_chunk")
                if reply.get("offset") != offset+len(chunk):
                    raise RuntimeError("unexpected acknowledged offset")
            ready = command("FW_END", "fw_ready", "image_sha256" if args.negative_image_hash else None)
            if args.negative_image_hash:
                after = command("STATUS", "status")
                result["after_status"] = after
                if after.get("ready") is not True or any(after.get(k) != before.get(k) for k in ("version", "release", "bundle_sha256", "schema", "policy")):
                    raise RuntimeError("detector state changed after image-hash rejection")
                result["negative_control_passed"] = True
            else:
                if ready.get("version") != info["version"] or ready.get("bytes") != len(image):
                    raise RuntimeError("unexpected final acknowledgment")
                result["completed"] = True
            result["device_reply"] = ready
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
            if link.is_open:
                try:
                    command("FW_ABORT", "fw_abort")
                except Exception as abort_exc:
                    result["abort_error"] = str(abort_exc)
            raise
        finally:
            link.close()
            result["elapsed_s"] = time.monotonic()-started
            result["finished_utc"] = now()
            write_new(args.out / "summary.json", (json.dumps(result, indent=2) + "\n").encode())
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare", help="sign metadata; no device access")
    p.add_argument("--image", type=Path, required=True)
    p.add_argument("--factory-envelope", type=Path, required=True)
    p.add_argument("--private-key", type=Path, required=True)
    p.add_argument("--public-key", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--max-image-bytes", type=int, default=0x1D0000)
    p.set_defaults(func=prepare)
    p = sub.add_parser("inspect", help="verify prepared artifacts; no device access")
    p.add_argument("artifact", type=Path)
    p.set_defaults(func=lambda a: print(json.dumps(validate_artifact(a.artifact)[3], indent=2)))
    p = sub.add_parser("send", help="send to explicitly selected device; does not reboot")
    p.add_argument("--artifact", type=Path, required=True)
    p.add_argument("--port", required=True)
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--timeout", type=float, default=45)
    p.add_argument("--chunk-bytes", type=int, choices=range(1, MAX_CHUNK+1), default=MAX_CHUNK, metavar="1..256")
    p.add_argument("--negative-image-hash", action="store_true", help="corrupt final image byte; require digest rejection and unchanged detector")
    p.set_defaults(func=send)
    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as exc:
        parser.exit(1, f"error: {type(exc).__name__}: {exc}\n")


if __name__ == "__main__":
    main()
