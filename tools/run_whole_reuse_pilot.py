#!/usr/bin/env python3
"""Instrumented whole-image A->B->C pilot; no negative controls in timed trials.

Explicitly install matching whole-firmware A before this campaign. After a live
policy/build gate, each trial restores partition table, initial OTA selection
and A in ota_0, erases ota_1, then measures B and C with separate reboot checks.
Results concern one board, serial transport, and software activation only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "host"))
import firmware_ota
import run_stage_timing_pilot as component
from ids_update_lab.artifacts import sha256_file, write_json
from ids_update_lab.package import load_public
from run_whole_firmware_pilot import image_identity
from stage_timing_support import validate_status_timing, validate_fw_begin, validate_fw_chunk, validate_fw_ready

REVISION = "0.2.0-whole-reuse-stage-timing-pilot"
append, now, Session = component.append, component.now, component.Session


def validate_partitions(path):
    data = Path(path).read_bytes()
    found = {}
    for offset in range(0, len(data), 32):
        record = data[offset:offset + 32]
        if len(record) != 32:
            raise ValueError("partition table has a truncated entry")
        if record[:2] == b"\xeb\xeb":
            if record[16:] != hashlib.md5(data[:offset]).digest():
                raise ValueError("partition table MD5 does not match entries")
            if any(byte != 255 for byte in data[offset + 32:]):
                raise ValueError("unexpected partition data after MD5")
            break
        magic, kind, subtype, address, size, label, flags = struct.unpack("<HBBII16sI", record)
        if magic != 0x50AA:
            raise ValueError("partition table entry has unexpected magic")
        name = label.split(b"\0", 1)[0].decode("ascii")
        if name in found or flags:
            raise ValueError("duplicate or flagged partition entry")
        found[name] = (kind, subtype, address, size)
    else:
        raise ValueError("partition table must contain its MD5 record")
    required = {"otadata": (1, 0, 0xd000, 0x2000), "ota_0": (0, 16, 0x10000, 0x1d0000),
        "ota_1": (0, 17, 0x1e0000, 0x1d0000), "ids_a": (1, 64, 0x3b0000, 0x10000),
        "ids_b": (1, 65, 0x3c0000, 0x10000)}
    if any(found.get(name) != value for name, value in required.items()) or len(data) > 0x1000:
        raise ValueError("partition table does not match the controlled 4MB dual-OTA layout")
    intervals = sorted((entry[2], entry[2] + entry[3]) for entry in found.values())
    if any(start < 0x9000 or end > 0x400000 or start >= end for start, end in intervals) or any(a[1] > b[0] for a, b in zip(intervals, intervals[1:])):
        raise ValueError("partition ranges overlap or exceed the 4MB flash")
    return found


def preflight(args):
    # Reuse all signed ABC/golden/static preflight gates; no component run or
    # device access occurs here. The whole firmware uses complete model bundles.
    base_args = argparse.Namespace(**vars(args))
    base_args.firmware_bin = args.factory_bin
    base_args.policy = "bundle"
    context = component.preflight(base_args)
    public = load_public(Path(args.experiment) / "public.pem")
    artifacts = []
    for index, path in ((1, args.artifact_b), (2, args.artifact_c)):
        image, metadata, signature, info = firmware_ota.validate_artifact(Path(path))
        if load_public(Path(path) / "public.pem").public_numbers() != public.public_numbers():
            raise ValueError("whole-image signing key differs from experiment key")
        if (Path(path) / "factory.sids").read_bytes() != context["envelopes"][index]:
            raise ValueError("whole image does not embed the exact expected signed release")
        identity = image_identity(image)
        if identity["version"] != index + 1 or identity["idf_version"] != context["identity"]["idf_version"] or len(image) > 0x1d0000:
            raise ValueError("whole image has incompatible version, SDK, or partition size")
        artifacts.append({"image": image, "metadata": metadata, "signature": signature, "identity": identity,
            "file_sha256": {name: sha256_file(Path(path) / name) for name in
                ("image.bin", "metadata.bin", "signature.bin", "factory.sids", "public.pem")}})
    if context["identity"]["image_size"] > 0x1d0000:
        raise ValueError("factory image exceeds OTA partition")
    context["partitions"] = validate_partitions(args.partition_table)
    ota = Path(args.ota_data).read_bytes()
    if ota != b"\xff" * 0x2000:
        raise ValueError("initial OTA data must be the 8192-byte erased image selecting ota_0")
    context["whole_artifacts"] = artifacts
    context["identities"] = [context["identity"], *(artifact["identity"] for artifact in artifacts)]
    context["restore_hashes"] = {"partition_table_sha256": sha256_file(args.partition_table), "ota_data_sha256": sha256_file(args.ota_data)}
    context["policy"] = "whole_firmware"
    return context


def check_status(response, context, release=None, event="status"):
    expected = {"event": event, "ready": True, "reason": "ok", "policy": "whole_firmware", "chip": "esp32s3",
        "schema": context["schema"], "feature_count": 2, "data_origin": "synthetic_plumbing", "active_slot": -1}
    if any(response.get(key) != value for key, value in expected.items()):
        raise RuntimeError("ready instrumented whole-firmware application is required; install the matching whole-A pack first")
    validate_status_timing(response)
    version = response.get("version")
    if type(version) is not int or version not in (1, 2, 3):
        raise RuntimeError("runtime version must identify verified A, B, or C")
    index = version - 1 if release is None else release
    model, identity = context["models"][index], context["identities"][index]
    if version != model.version or response.get("release") != model.release or response.get("bundle_sha256") != context["payload_hashes"][index]:
        raise RuntimeError("runtime model differs from the expected signed release")
    prefix = f"esp-idf-{identity['idf_version']};app={version};elf="
    build = response.get("build", "")
    suffix = build[len(prefix):] if isinstance(build, str) and build.startswith(prefix) else ""
    if not re.fullmatch(r"[0-9a-f]{9,64}", suffix) or not identity["elf_sha256"].startswith(suffix):
        raise RuntimeError("runtime whole-image build differs from its supplied artifact")


def restore(args, output):
    prefix = [sys.executable, "-m", "esptool", "--chip", "esp32s3", "--port", args.port]
    commands = [prefix + ["-b", "460800", "--after", "no_reset", "write_flash", "--flash_mode", "dio",
        "--flash_freq", "80m", "--flash_size", "4MB", "0x8000", str(Path(args.partition_table).resolve()),
        "0xd000", str(Path(args.ota_data).resolve()), "0x10000", str(Path(args.factory_bin).resolve())],
        prefix + ["--after", "hard_reset", "erase_region", "0x1e0000", "0x1d0000"]]
    write_json(output / "restore_commands.json", {"started_utc": now(), "commands": commands,
        "scope": "restore known partition table, ota_0 A and erased OTA selection; erase inactive ota_1 before boot"})
    results = []
    for index, command in enumerate(commands, 1):
        logfile = output / f"restore-{index}.log"
        with logfile.open("x", encoding="utf-8") as stream:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, text=True, timeout=60, check=False)
        content = logfile.read_text(encoding="utf-8", errors="replace")
        marker = "Hash of data verified" if index == 1 else "Erase completed successfully"
        if result.returncode != 0 or marker not in content:
            raise RuntimeError(f"whole-A restore step {index} failed; inspect {logfile.name}")
        results.append({"returncode": result.returncode, "log_sha256": sha256_file(logfile),
            "reported_macs": sorted(set(value.lower() for value in re.findall(r"MAC:\s*([0-9a-fA-F:]{17})", content)))})
    return {"steps": results, "identity_attested": False}


def run_trial(args, context, output, index, plan_hash):
    output.mkdir(exist_ok=False)
    summary = {"status": "failed", "measurement_origin": "actual_mcu", "data_origin": "synthetic_plumbing",
        "policy": "whole_firmware", "inferred_records": 0, "label_mismatches": 0, "max_probability_abs_error": 0.0,
        "accepted_updates": 0, "timing_validated_updates": 0, "boot_verified_updates": 0,
        "restore_attempted": False, "restore_completed": False}
    manifest = {"measurement_origin": "actual_mcu", "hardware_measured": True, "data_origin": "synthetic_plumbing",
        "policy": "whole_firmware", "board_id": args.board_id, "board_id_kind": "user_supplied_label", "started_utc": now(),
        "campaign_stage": "synthetic_whole_reuse_stage_timing_v2_pilot", "trial_index": index,
        "campaign_manifest_sha256": plan_hash, "planned_trials": args.trials, "host_runner_revision": REVISION,
        "host_runner_sha256": sha256_file(__file__), "session_helper_sha256": sha256_file(ROOT / "tools/run_stage_timing_pilot.py"),
        "serial_runner_sha256": sha256_file(ROOT / "host/ids_update_lab/serial_runner.py"),
        "timing_support_sha256": sha256_file(ROOT / "tools/stage_timing_support.py"), "timing_schema": 2,
        "crypto_context": "shared_warm", "firmware_application_sha256": context["identity"]["image_sha256"],
        "firmware_identities": context["identities"], "artifacts_sha256": context["artifacts_sha256"],
        "release_C_envelope_sha256": context["release_C_envelope_sha256"], "restore_artifacts": context["restore_hashes"],
        "ota_artifacts": [artifact["file_sha256"] for artifact in context["whole_artifacts"]],
        "schema_sha256": context["schema"], "numerical_tolerance": {"absolute": component.TOLERANCE, "relative": 0.0},
        "checkpoint": "none", "fault_kind": "none", "activation_kind": "explicit_software_restart",
        "physical_power_loss_tested": False, "update_trials": 2, "inference_repetitions": 1,
        "golden_total_records": 63, "selected_records": 63, "truncated_correctness_smoke": False, "negative_control_trials": 0,
        "transport": "USB Serial/JTAG", "baud": 115200, "chunk_bytes": 256,
        "transitions": [{"source": "A", "target": "B", "destination_partition": "ota_1", "destination_state": "explicitly_erased"},
            {"source": "B", "target": "C", "destination_partition": "ota_0", "destination_state": "previously_accepted_release_A"}],
        "parameters": {name: str(value) if isinstance(value, Path) else value for name, value in vars(args).items()}}
    write_json(output / "manifest.json", manifest)
    started = time.perf_counter_ns()
    with (output / "transcript.jsonl").open("x", encoding="utf-8") as transcript, \
         (output / "events.jsonl").open("x", encoding="utf-8") as events, \
         (output / "observations.jsonl").open("x", encoding="utf-8") as observations:
        session = Session(transcript, args.timeout, events)

        def measure(release, phase):
            for row in context["rows"]:
                response, elapsed = session.command("INFER " + ",".join(format(float(value), ".9g") for value in row["raw"]),
                    {"inference"}, "inference", phase)
                if (response.get("event") != "inference" or response.get("version") != release + 1 or
                    response.get("policy") != "whole_firmware" or response.get("data_origin") != "synthetic_plumbing" or
                    response.get("bundle_sha256") != context["payload_hashes"][release]):
                    raise RuntimeError("whole-image inference identity differs from expected release")
                probability = response.get("probability")
                if isinstance(probability, bool) or not isinstance(probability, (int, float)) or not component.math.isfinite(probability) or not 0 <= probability <= 1:
                    raise RuntimeError("invalid inference probability")
                expected = row["expected_" + "ABC"[release]]
                error = abs(probability - expected["probability"])
                matched = type(response.get("label")) is int and response["label"] == expected["label"]
                append(observations, {"phase": phase, "record_id": row["record_id"], "repetition": 0,
                    "expected": expected, "expected_A": row["expected_A"], "expected_B": row["expected_B"], "expected_C": row["expected_C"],
                    "response": response, "host_roundtrip_ns": elapsed, "probability_abs_error": error,
                    "label_match": matched, "tolerance_pass": error <= component.TOLERANCE})
                summary["inferred_records"] += 1
                summary["label_mismatches"] += int(not matched)
                summary["max_probability_abs_error"] = max(summary["max_probability_abs_error"], error)
                if not matched or error > component.TOLERANCE:
                    raise RuntimeError("inference differs from signed float32 reference")

        def transfer(release, phase):
            artifact = context["whole_artifacts"][release - 1]
            image = artifact["image"]
            action = "candidate_" + "ABC"[release]
            destination = "explicitly_erased" if release == 1 else "previously_accepted_release_A"
            transfer_start = time.perf_counter_ns()
            wire = 0
            print(f"Trial {index}/{args.trials}: {'ABC'[release-1]} -> {'ABC'[release]} 0%", flush=True)
            begin_line = "FW_BEGIN " + artifact["metadata"].hex() + " " + artifact["signature"].hex()
            response, _ = session.command(begin_line, {"fw_begin"}, action, phase, destination_state=destination)
            wire += len(begin_line) + 1
            if response.get("event") != "fw_begin" or response.get("ok") is not True or response.get("version") != release + 1 or response.get("size") != len(image):
                raise RuntimeError("whole-image begin acknowledgment differs from requested candidate")
            timing = validate_fw_begin(response)
            next_progress = 25
            for offset in range(0, len(image), 256):
                chunk = image[offset:offset + 256]
                line = f"FW_CHUNK {offset} {chunk.hex()}"
                response, _ = session.command(line, {"fw_chunk"}, action, phase)
                wire += len(line) + 1
                if response.get("event") != "fw_chunk" or response.get("ok") is not True or response.get("offset") != offset + len(chunk):
                    raise RuntimeError("whole-image chunk acknowledgment has wrong offset or result")
                timing = validate_fw_chunk(response, timing)
                progress = (offset + len(chunk)) * 100 // len(image)
                while next_progress <= progress:
                    print(f"Trial {index}/{args.trials}: {'ABC'[release]} {next_progress}%", flush=True)
                    next_progress += 25
            response, _ = session.command("FW_END", {"fw_ready"}, action, phase)
            wire += len("FW_END\n")
            if (response.get("event") != "fw_ready" or response.get("ok") is not True or response.get("version") != release + 1 or
                response.get("bytes") != len(image) or response.get("reboot_required") is not True):
                raise RuntimeError("whole-image finalize acknowledgment differs from requested candidate")
            summary["accepted_updates"] += 1
            timing = validate_fw_ready(response, timing)
            append(events, {"action": action + "_transfer", "phase": phase, "destination_state": destination,
                "transfer_elapsed_ns": time.perf_counter_ns() - transfer_start, "transfer_tx_wire_bytes": wire,
                "image_bytes": len(image), "terminal_event": "fw_ready", "terminal_version": release + 1,
                "timing_schema": 2, **timing})
            summary["timing_validated_updates"] += 1
            current, _ = session.command("STATUS", {"status"}, "selected_candidate_running_previous", phase)
            check_status(current, context, release - 1)
            activation_start = time.perf_counter_ns()
            reboot, _ = session.command("REBOOT", {"reboot"}, "activate_" + "ABC"[release], phase)
            if reboot.get("event") != "reboot" or reboot.get("fault_kind") != "software_restart":
                raise RuntimeError("whole-image activation reboot was not acknowledged")
            boot = session.receive({"boot"})
            append(events, {"action": "boot_" + "ABC"[release], "phase": phase, "response": boot,
                "activation_to_boot_ns": time.perf_counter_ns() - activation_start})
            check_status(boot, context, release, event="boot")
            status, _ = session.command("STATUS", {"status"}, "status_" + "ABC"[release], phase)
            check_status(status, context, release)
            summary["boot_verified_updates"] += 1
            return status

        try:
            print(f"Trial {index}/{args.trials}: restore whole A and erase ota_1", flush=True)
            summary["restore_attempted"] = True
            restoration = restore(args, output)
            summary["restore_completed"] = True
            # Log hashes are evidence integrity, not a grouping fingerprint.
            append(events, {"action": "restore_evidence", "phase": "preparation", **restoration})
            initial = session.open(args.port)
            check_status(initial, context, 0)
            manifest["initial_status"] = initial
            write_json(output / "manifest.json", manifest)
            measure(0, "before")
            for release, phase in ((1, "after_first"), (2, "after_reuse")):
                status = transfer(release, phase)
                measure(release, phase)
            manifest["final_status"] = status
            write_json(output / "manifest.json", manifest)
            summary["status"] = "complete"
        except BaseException as exc:
            summary["error"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            summary["trial_elapsed_ns"] = time.perf_counter_ns() - started
            summary["finished_utc"] = now()
            try:
                session.close()
            finally:
                write_json(output / "summary.json", summary)
    return summary


def run(args):
    context = preflight(args)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    plan = {"format": "ids-update-lab-whole-reuse-stage-timing-v2", "started_utc": now(), "planned_trials": args.trials,
        "sequence": "restore A -> A:63 -> transfer B -> reboot B -> B:63 -> transfer C -> reboot C -> C:63",
        "policy": "whole_firmware", "campaign_stage": "synthetic_whole_reuse_stage_timing_v2_pilot",
        "measurement_origin": "actual_mcu", "data_origin": "synthetic_plumbing", "board_id": args.board_id,
        "board_id_kind": "user_supplied_label", "independent_boards": 1, "negative_controls": "not_run",
        "physical_power_loss_tested": False, "timing_schema": 2, "crypto_context": "shared_warm",
        "failure_policy": "stop first failure; preserve partial results; no mutation retry or automatic resume",
        "firmware_identities": context["identities"], "restore_artifacts": context["restore_hashes"],
        "artifacts_sha256": context["artifacts_sha256"], "release_C_envelope_sha256": context["release_C_envelope_sha256"],
        "host_runner_sha256": sha256_file(__file__), "timing_support_sha256": sha256_file(ROOT / "tools/stage_timing_support.py"),
        "parameters": {name: str(value) if isinstance(value, Path) else value for name, value in vars(args).items()}}
    write_json(output / "campaign_manifest.json", plan)
    plan_hash = sha256_file(output / "campaign_manifest.json")
    summary = {"status": "incomplete", "planned_trials": args.trials, "completed_trials": 0, "attempted_trials": 0,
        "accepted_updates": 0, "timing_validated_updates": 0, "boot_verified_updates": 0,
        "inferred_records": 0, "restore_attempts": 0, "completed_restores": 0,
        "policy": "whole_firmware", "measurement_origin": "actual_mcu", "data_origin": "synthetic_plumbing",
        "negative_controls": "not_run", "physical_power_loss_tested": False, "count_scope": "all attempted trials, including partial failures"}

    def accumulate(result):
        for key in ("accepted_updates", "timing_validated_updates", "boot_verified_updates", "inferred_records"):
            summary[key] += result[key]
        summary["restore_attempts"] += int(result["restore_attempted"])
        summary["completed_restores"] += int(result["restore_completed"])

    try:
        with (output / "preflight_transcript.jsonl").open("x", encoding="utf-8") as stream:
            session = Session(stream, args.timeout)
            try:
                status = session.open(args.port)
                check_status(status, context)
                write_json(output / "preflight_status.json", status)
            finally:
                session.close()
        for index in range(1, args.trials + 1):
            summary["attempted_trials"] += 1
            summary["active_trial"] = f"trial-{index:03d}"
            trial = output / summary["active_trial"]
            try:
                result = run_trial(args, context, trial, index, plan_hash)
            except BaseException:
                failed = trial / "summary.json"
                if failed.is_file():
                    accumulate(json.loads(failed.read_text(encoding="utf-8")))
                raise
            accumulate(result)
            summary["completed_trials"] += 1
            write_json(output / "campaign_summary.json", summary)
        summary.pop("active_trial", None)
        summary["status"] = "complete"
    except BaseException as exc:
        summary["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        summary["finished_utc"] = now()
        write_json(output / "campaign_summary.json", summary)
    print(json.dumps({"campaign": str(output), **summary}), flush=True)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("port", "board-id"):
        parser.add_argument("--" + name, required=True)
    for name in ("experiment", "release-c", "factory-bin", "ota-data", "partition-table", "artifact-b", "artifact-c", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--trials", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=20)
    args = parser.parse_args(argv)
    try:
        run(args)
    except Exception as exc:
        parser.exit(1, f"error: {type(exc).__name__}: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
