#!/usr/bin/env python3
"""Run one authenticated whole-firmware A-to-B pilot on an explicit MCU port.

Install the matching whole-A factory image separately. This tool never flashes
through esptool or erases model storage. It transmits one corrupted-image control,
then one valid B image, explicitly reboots once and verifies the running B model.
Only startup STATUS probes may retry; no inference, OTA or reboot command retries.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "host"))
sys.path.insert(0, str(ROOT / "tools"))
import firmware_ota
from ids_update_lab.artifacts import sha256_file, write_json
from ids_update_lab.package import contract_hash, infer, load_public, verify
from ids_update_lab.serial_runner import SerialTransport, synchronize_serial

POLICY = "whole_firmware"
TOLERANCE = 2e-6
REVISION = "0.1.0-whole-firmware-pilot"


def now():
    return datetime.now(timezone.utc).isoformat()


def image_identity(image):
    """Pinned ESP-IDF app_desc in the first image segment; no image mutation."""
    version = firmware_ota.image_version(image)
    if len(image) < 288:
        raise ValueError("application image has a truncated app_desc")
    field = image[144:176]  # app_desc begins at 32; idf_ver offset is 112.
    if b"\0" not in field:
        raise ValueError("application IDF version is not terminated")
    sdk = field.split(b"\0", 1)[0].decode("ascii")
    if not sdk:
        raise ValueError("application IDF version is empty")
    elf = image[176:208].hex()  # app_desc app_elf_sha256 offset is 144.
    if elf == "0" * 64:
        raise ValueError("application ELF identity is missing")
    return {"version": version, "idf_version": sdk, "elf_sha256": elf,
            "image_sha256": hashlib.sha256(image).hexdigest(), "image_size": len(image)}


def preflight(args):
    """Validate every input before creating evidence or opening the device."""
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise ValueError("timeout must be finite and positive")
    if not args.port or not args.board_id:
        raise ValueError("port and board-id must be nonempty")
    experiment = Path(args.experiment)
    contract = json.loads((experiment / "feature_contract.json").read_text(encoding="utf-8"))
    schema = contract_hash(contract)
    public = load_public(experiment / "public.pem")
    provenance = json.loads((experiment / "provenance.json").read_text(encoding="utf-8"))
    if provenance.get("schema_sha256") != schema.hex() or not provenance.get("data_origin"):
        raise ValueError("experiment provenance has inconsistent schema/origin")
    envelopes = [(experiment / f"release-{letter}.sids").read_bytes() for letter in "AB"]
    models = [verify(blob, public, schema, len(contract["feature_names"])) for blob in envelopes]
    if models[0].version != 1 or models[1].version != 2:
        raise ValueError("this pilot requires release A version 1 and release B version 2")
    for letter, blob in zip("AB", envelopes):
        if provenance.get("package_sha256", {}).get(f"release-{letter}.sids") != hashlib.sha256(blob).hexdigest():
            raise ValueError("signed experiment package differs from provenance")
    rows = [json.loads(line) for line in (experiment / "golden.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows or len({row["record_id"] for row in rows}) != len(rows):
        raise ValueError("golden records must be nonempty and have unique record IDs")
    for row in rows:
        if row.get("data_origin") != provenance["data_origin"]:
            raise ValueError("golden record origin differs from provenance")
        for key, model, prep in (("expected_A", models[0], None), ("expected_B", models[1], None),
                                 ("expected_B_model_only", models[1], models[0])):
            probability, label = infer(model, row["raw"], prep)
            expected = row[key]
            if expected["label"] != label or not math.isfinite(expected["probability"]) or abs(expected["probability"] - probability) > 1e-7:
                raise ValueError("golden reference differs from verified signed model")
    image, metadata, signature, artifact_info = firmware_ota.validate_artifact(Path(args.artifact))
    if load_public(Path(args.artifact) / "public.pem").public_numbers() != public.public_numbers():
        raise ValueError("OTA artifact public key differs from experiment key")
    if (Path(args.artifact) / "factory.sids").read_bytes() != envelopes[1]:
        raise ValueError("OTA artifact does not embed the exact experiment release B")
    factory = Path(args.factory_bin).read_bytes()
    identities = [image_identity(factory), image_identity(image)]
    if factory.count(envelopes[0]) != 1 or identities[0]["version"] != models[0].version:
        raise ValueError("factory image does not embed the exact release A once with matching version")
    if identities[0]["idf_version"] != identities[1]["idf_version"]:
        raise ValueError("factory and OTA images use different SDK versions")
    if artifact_info["feature_contract_sha256"] != schema.hex():
        raise ValueError("OTA artifact schema differs from experiment")
    if Path(args.output).exists():
        raise FileExistsError("output already exists; choose a new evidence directory")
    return {"schema": schema.hex(), "origin": provenance["data_origin"], "models": models,
            "envelopes": envelopes, "identities": identities, "records": rows,
            "image": image, "metadata": metadata, "signature": signature,
            "artifact_info": artifact_info}


def check_status(response, context, release, event="status"):
    model = context["models"][release]
    identity = context["identities"][release]
    expected = {"event": event, "ready": True, "reason": "ok", "version": model.version,
                "release": model.release, "policy": POLICY, "schema": context["schema"],
                "feature_count": len(model.means), "chip": "esp32s3", "data_origin": context["origin"],
                "bundle_sha256": hashlib.sha256(context["envelopes"][release][16:-256]).hexdigest()}
    if any(response.get(key) != value for key, value in expected.items()):
        raise RuntimeError(f"unexpected release {'AB'[release]} {event} identity: {response}")
    build = response.get("build", "")
    prefix = f"esp-idf-{identity['idf_version']};app={model.version};elf="
    reported_elf = build[len(prefix):] if isinstance(build, str) and build.startswith(prefix) else ""
    # ESP-IDF prints a configured prefix (9 hexadecimal characters in these
    # builds). Full artifact hashes remain recorded separately in the manifest.
    if not re.fullmatch(r"[0-9a-f]{9,64}", reported_elf) or not identity["elf_sha256"].startswith(reported_elf):
        raise RuntimeError(f"release {'AB'[release]} runtime build differs from supplied image")


def run(args):
    context = preflight(args)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter_ns()
    parameters = {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}
    manifest = {"measurement_origin": "actual_mcu", "hardware_measured": True,
        "data_origin": context["origin"], "policy": POLICY, "board_id": args.board_id,
        "campaign_stage": "synthetic_pilot" if context["origin"] == "synthetic_plumbing" else "whole_firmware_pilot",
        "host_runner_revision": REVISION, "host_runner_sha256": sha256_file(__file__),
        "serial_runner_sha256": sha256_file(ROOT / "host/ids_update_lab/serial_runner.py"),
        "ota_validator_sha256": sha256_file(ROOT / "tools/firmware_ota.py"),
        "started_utc": now(), "parameters": parameters, "checkpoint": "none", "fault_kind": "none",
        "activation_kind": "explicit_software_restart", "physical_power_loss_tested": False,
        "update_trials": 1, "negative_control_trials": 1, "inference_repetitions": 1,
        "golden_total_records": len(context["records"]), "selected_records": len(context["records"]),
        "truncated_correctness_smoke": False, "schema_sha256": context["schema"],
        "numerical_tolerance": {"absolute": TOLERANCE, "relative": 0.0}, "threshold_neighborhood": 2e-5,
        "transport": "USB Serial/JTAG", "baud": 115200, "chunk_bytes": firmware_ota.MAX_CHUNK,
        "firmware_application_sha256": context["identities"][0]["image_sha256"],
        "factory_image_identity": context["identities"][0], "candidate_image_identity": context["identities"][1],
        "artifacts_sha256": {name: sha256_file(Path(args.experiment) / name) for name in
            ("feature_contract.json", "provenance.json", "public.pem", "release-A.sids", "release-B.sids", "golden.jsonl")},
        "ota_artifacts_sha256": {name: sha256_file(Path(args.artifact) / name) for name in
            ("image.bin", "metadata.bin", "signature.bin", "factory.sids", "public.pem")}}
    summary = {"status": "failed", "measurement_origin": "actual_mcu", "data_origin": context["origin"],
        "policy": POLICY, "inferred_records": 0, "label_mismatches": 0, "max_probability_abs_error": 0.0,
        "negative_control_passed": False, "transfer_completed": False, "reboot_issued": False,
        "boot_verified": False, "replay_rejected": False}
    write_json(output / "manifest.json", manifest)
    transport = None
    transcript = (output / "transcript.jsonl").open("x", encoding="utf-8")
    observations = (output / "observations.jsonl").open("x", encoding="utf-8")
    events = (output / "events.jsonl").open("x", encoding="utf-8")

    def append(stream, item):
        stream.write(json.dumps(item, allow_nan=False) + "\n")
        stream.flush()

    def receive(expected):
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            line = transport.readline(min(.5, max(.001, deadline - time.monotonic())))
            if line is None:
                continue
            append(transcript, {"utc_ns": time.time_ns(), "direction": "rx", "line": line})
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(response, dict):
                if response.get("event") in expected or response.get("event") in {"error", "fw_error"}:
                    return response
                # A spontaneous boot during a transfer/inference cannot be
                # silently ignored and confused with the requested activation.
                if response.get("event") in {"boot", "reboot"}:
                    raise RuntimeError(f"unexpected restart while waiting for {sorted(expected)}")
        raise RuntimeError(f"timeout waiting for {sorted(expected)}; command is not retried")

    def command(line, expected, action, phase):
        append(transcript, {"utc_ns": time.time_ns(), "direction": "tx", "line": line, "phase": phase})
        begin = time.perf_counter_ns()
        transport.write(line)
        reply = receive(set(expected))
        elapsed = time.perf_counter_ns() - begin
        append(events, {"action": action, "phase": phase, "command_kind": line.split(" ", 1)[0],
            "wire_bytes": len((line + "\n").encode("ascii")), "response": reply, "host_roundtrip_ns": elapsed})
        return reply, elapsed

    def measure_one(row, release, phase, primary):
        model = context["models"][release]
        expected = row["expected_" + "AB"[release]]
        reply, elapsed = command("INFER " + ",".join(format(float(value), ".9g") for value in row["raw"]),
                                 {"inference"}, "inference" if primary else "negative_control_inference", phase)
        digest = hashlib.sha256(context["envelopes"][release][16:-256]).hexdigest()
        if (reply.get("event") != "inference" or reply.get("version") != model.version or
            reply.get("policy") != POLICY or reply.get("data_origin") != context["origin"] or
            reply.get("bundle_sha256") != digest):
            raise RuntimeError("inference identity differs from expected signed release")
        probability = reply.get("probability")
        if isinstance(probability, bool) or not isinstance(probability, (int, float)) or not math.isfinite(probability) or not 0 <= probability <= 1:
            raise RuntimeError("device returned invalid probability")
        error = abs(probability - expected["probability"])
        matched = type(reply.get("label")) is int and reply["label"] == expected["label"]
        row_out = {"phase": phase, "record_id": row["record_id"], "repetition": 0,
            "expected": expected, "expected_A": row["expected_A"], "expected_B": row["expected_B"],
            "expected_B_model_only": row["expected_B_model_only"], "true_label": row.get("label"),
            "tolerance_pass": error <= TOLERANCE, "near_threshold": abs(expected["probability"] - model.threshold) <= 2e-5,
            "response": reply, "host_roundtrip_ns": elapsed, "probability_abs_error": error, "label_match": matched}
        if primary:
            append(observations, row_out)
            summary["inferred_records"] += 1
            summary["label_mismatches"] += int(not matched)
            summary["max_probability_abs_error"] = max(summary["max_probability_abs_error"], error)
        else:
            append(events, {"action": "negative_control_known_vector", **row_out})
        if not matched or error > TOLERANCE:
            raise RuntimeError("inference differs from verified float32 reference (tolerance 2e-6)")

    begin_line = "FW_BEGIN " + context["metadata"].hex() + " " + context["signature"].hex()

    def transfer(negative):
        phase = "negative_image_hash" if negative else "valid_update"
        action = "negative_image_hash" if negative else "candidate_B"
        image = context["image"]
        if negative:
            image = image[:-1] + bytes([image[-1] ^ 1])
        begun = time.perf_counter_ns()
        wire_bytes = 0
        print(f"{phase}: 0% ({len(image)} image bytes)", flush=True)
        reply, _ = command(begin_line, {"fw_begin"}, action, phase)
        wire_bytes += len(begin_line) + 1
        if reply.get("event") != "fw_begin" or reply.get("ok") is not True or reply.get("version") != 2 or reply.get("size") != len(image):
            raise RuntimeError(f"unexpected FW_BEGIN acknowledgment: {reply}")
        next_progress = 25
        for offset in range(0, len(image), firmware_ota.MAX_CHUNK):
            chunk = image[offset:offset + firmware_ota.MAX_CHUNK]
            line = f"FW_CHUNK {offset} {chunk.hex()}"
            reply, _ = command(line, {"fw_chunk"}, action, phase)
            wire_bytes += len(line) + 1
            if reply.get("event") != "fw_chunk" or reply.get("ok") is not True or reply.get("offset") != offset + len(chunk):
                raise RuntimeError(f"unexpected FW_CHUNK acknowledged offset: {reply}")
            progress = (offset + len(chunk)) * 100 // len(image)
            while next_progress <= progress:
                print(f"{phase}: {next_progress}%", flush=True)
                next_progress += 25
        reply, _ = command("FW_END", {"fw_ready", "fw_error"}, action, phase)
        wire_bytes += len("FW_END\n")
        elapsed = time.perf_counter_ns() - begun
        append(events, {"action": action + "_transfer", "phase": phase, "transfer_elapsed_ns": elapsed,
            "transfer_tx_wire_bytes": wire_bytes, "image_bytes": len(image),
            "transmitted_image_sha256": hashlib.sha256(image).hexdigest(),
            "terminal_event": reply.get("event"), "terminal_version": reply.get("version")})
        summary[phase + "_transfer_elapsed_ns"] = elapsed
        summary[phase + "_tx_wire_bytes"] = wire_bytes
        if negative:
            if reply.get("event") != "fw_error" or reply.get("ok") is not False or reply.get("error") != "image_sha256":
                raise RuntimeError(f"corrupted image was not rejected by final digest: {reply}")
        else:
            if (reply.get("event") != "fw_ready" or reply.get("ok") is not True or reply.get("version") != 2 or
                reply.get("bytes") != len(image) or reply.get("reboot_required") is not True):
                raise RuntimeError(f"unexpected FW_END acknowledgment: {reply}")
            summary["transfer_completed"] = True

    try:
        transport = SerialTransport(args.port, on_read=lambda chunk: append(transcript,
            {"utc_ns": time.time_ns(), "direction": "rx_bytes", "bytes_hex": chunk.hex()}))
        status, elapsed = synchronize_serial(transport, lambda item: append(transcript, item), args.timeout)
        append(events, {"action": "initial_status", "phase": "before", "command_kind": "STATUS", "wire_bytes": 7,
            "response": status, "host_roundtrip_ns": elapsed, "startup_status_probe": True})
        check_status(status, context, 0)
        manifest["initial_status"] = status
        write_json(output / "manifest.json", manifest)
        for row in context["records"]:
            measure_one(row, 0, "before", True)
        transfer(True)
        status, _ = command("STATUS", {"status"}, "after_negative_status", "negative_image_hash")
        check_status(status, context, 0)
        # Separate control observation, excluded from the primary 2*N records.
        measure_one(context["records"][0], 0, "negative_image_hash", False)
        summary["negative_control_passed"] = True
        transfer(False)
        # fw_ready selects an image but is NOT evidence it booted or ran inference.
        status, _ = command("STATUS", {"status"}, "selected_B_running_A_status", "valid_update")
        check_status(status, context, 0)
        activation_start = time.perf_counter_ns()
        summary["reboot_issued"] = True
        reply, _ = command("REBOOT", {"reboot"}, "activate_B", "activation")
        if reply.get("event") != "reboot" or reply.get("fault_kind") != "software_restart":
            raise RuntimeError(f"explicit reboot was not acknowledged: {reply}")
        boot = receive({"boot"})
        append(events, {"action": "boot_after_activation", "phase": "activation", "response": boot,
            "activation_to_boot_ns": time.perf_counter_ns() - activation_start})
        check_status(boot, context, 1, "boot")
        after, _ = command("STATUS", {"status"}, "after_status", "after")
        check_status(after, context, 1)
        summary["boot_verified"] = True
        manifest["after_status"] = after
        write_json(output / "manifest.json", manifest)
        for row in context["records"]:
            measure_one(row, 1, "after", True)
        replay, _ = command(begin_line, {"fw_error"}, "replay_current_version", "replay")
        if replay.get("event") != "fw_error" or replay.get("ok") is not False or replay.get("error") != "non_monotonic_version":
            raise RuntimeError(f"running-version replay was not rejected as non-monotonic: {replay}")
        final, _ = command("STATUS", {"status"}, "final_status", "replay")
        check_status(final, context, 1)
        summary["replay_rejected"] = True
        summary["status"] = "complete"
    except Exception as exc:
        summary["error"] = f"{type(exc).__name__}: {exc}"
        # Do not retry commands or send FW_ABORT as recovery: a lost FW_END ACK
        # can already have selected B, and FW_ABORT cannot undo that selection.
        summary["recovery_note"] = "Preserve logs; inspect board state and explicitly restore whole-A before a new trial."
        raise
    finally:
        summary["trial_elapsed_ns"] = time.perf_counter_ns() - started
        summary["finished_utc"] = now()
        if transport:
            fragment = transport.take_pending_fragment()
            if fragment:
                append(transcript, {"utc_ns": time.time_ns(), "direction": "rx", "complete_line": False,
                    "bytes_hex": fragment.hex(), "line": fragment.decode("utf-8", errors="replace"), "phase": "session_end_fragment"})
            transport.close()
        transcript.close()
        observations.close()
        events.close()
        write_json(output / "summary.json", summary)
    print(json.dumps({"run": str(output), **summary}), flush=True)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True)
    parser.add_argument("--experiment", required=True, type=Path)
    parser.add_argument("--factory-bin", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--board-id", required=True)
    parser.add_argument("--timeout", type=float, default=20, help="seconds per response; not the full-image transfer duration")
    args = parser.parse_args(argv)
    try:
        run(args)
    except Exception as exc:
        parser.exit(1, f"error: {type(exc).__name__}: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
