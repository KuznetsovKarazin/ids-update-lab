#!/usr/bin/env python3
"""Predeclared instrumented bundle A->B->C stage-timing pilot on one ESP32-S3.

Install the buffered BUNDLE factory-A application and initial OTA selection
separately before running. This helper checks the live policy/build first, then
erases only the two model partitions before each trial. It never flashes an app
or changes OTA-selection data. No mutation retries or automatic resume.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "host"))
sys.path.insert(0, str(ROOT / "tools"))
from run_whole_firmware_pilot import image_identity
from stage_timing_support import validate_status_timing, validate_bundle_timing
from ids_update_lab.artifacts import sha256_file, write_json
from ids_update_lab.package import contract_hash, infer, load_public, verify
from ids_update_lab.serial_runner import SerialTransport, synchronize_serial

REVISION = "0.2.0-bundle-stage-timing-pilot"
TOLERANCE = 2e-6


def now():
    return datetime.now(timezone.utc).isoformat()


def append(stream, value):
    stream.write(json.dumps(value, allow_nan=False) + "\n")
    stream.flush()


def preflight(args):
    if type(args.trials) is not int or not 1 <= args.trials <= 100:
        raise ValueError("trials must be an explicit integer from 1 to 100")
    if not args.port or not args.board_id or not math.isfinite(args.timeout) or args.timeout <= 0:
        raise ValueError("port, board-id and a finite positive timeout are required")
    experiment = Path(args.experiment)
    contract = json.loads((experiment / "feature_contract.json").read_text(encoding="utf-8"))
    schema = contract_hash(contract)
    public = load_public(experiment / "public.pem")
    provenance = json.loads((experiment / "provenance.json").read_text(encoding="utf-8"))
    if provenance.get("data_origin") != "synthetic_plumbing" or provenance.get("schema_sha256") != schema.hex():
        raise ValueError("this pilot requires the synthetic experiment and matching schema")
    if len(contract["feature_names"]) != 2:
        raise ValueError("this pilot requires the two-feature synthetic fixture")
    envelopes = [(experiment / f"release-{name}.sids").read_bytes() for name in "AB"]
    envelopes.append(Path(args.release_c).read_bytes())
    models = [verify(blob, public, schema, 2) for blob in envelopes]
    policy = getattr(args, "policy", "bundle")
    if policy not in ("bundle", "model_only_factory_preprocess"):
        raise ValueError("unsupported component update policy")
    if policy == "model_only_factory_preprocess":
        if (provenance.get("update_semantics") != "factory_preprocessing_compatible" or
            provenance.get("fixed_factory_A_payload_sha256") != hashlib.sha256(envelopes[0][16:-256]).hexdigest() or
            not re.fullmatch(r"[0-9a-f]{64}", provenance.get("compatibility_source_B_payload_sha256", "")) or
            provenance.get("probabilities_preserved") is not True or
            provenance.get("threshold_adjustment_logit") != 0):
            raise ValueError("model-only requires explicit factory-compatible provenance bound to signed A")
        for candidate in models[1:]:
            # Compare packed float32 bytes so signed zero and all serialized
            # parameters must match, rather than relying on Python float equality.
            candidate_prep = replace(models[0], means=candidate.means, scales=candidate.scales, threshold=candidate.threshold)
            if candidate_prep.payload() != models[0].payload():
                raise ValueError("model-only fixture uses preprocessing incompatible with immutable factory A")
    if [model.version for model in models] != [1, 2, 3]:
        raise ValueError("pilot requires signed versions A=1, B=2, C=3")
    if replace(models[2], version=models[1].version, release=models[1].release).payload() != models[1].payload():
        raise ValueError("C must copy B numerical parameters exactly; only version/release may differ")
    for index, letter in enumerate("AB"):
        if provenance.get("package_sha256", {}).get(f"release-{letter}.sids") != hashlib.sha256(envelopes[index]).hexdigest():
            raise ValueError("signed A/B packages differ from experiment provenance")
    rows = [json.loads(line) for line in (experiment / "golden.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) != 63 or len({row["record_id"] for row in rows}) != 63:
        raise ValueError("pilot requires all 63 uniquely identified synthetic records")
    for row in rows:
        if row.get("data_origin") != "synthetic_plumbing":
            raise ValueError("golden origin differs from synthetic fixture")
        for index, letter in enumerate("AB"):
            probability, label = infer(models[index], row["raw"])
            expected = row["expected_" + letter]
            if not math.isfinite(expected["probability"]) or expected["label"] != label or abs(probability - expected["probability"]) > 1e-7:
                raise ValueError("golden reference differs from signed model")
        probability, label = infer(models[2], row["raw"])
        row["expected_C"] = {"probability": probability, "label": label}
    firmware = Path(args.firmware_bin).read_bytes()
    identity = image_identity(firmware)
    if identity["version"] != 1 or firmware.count(envelopes[0]) != 1:
        raise ValueError("supplied firmware must embed the exact factory A once with app version 1")
    if Path(args.output).exists():
        raise FileExistsError("campaign output already exists; choose a new directory")
    return {"models": models, "envelopes": envelopes, "schema": schema.hex(), "rows": rows, "policy": policy,
        "identity": identity, "payload_hashes": [hashlib.sha256(blob[16:-256]).hexdigest() for blob in envelopes],
        "artifacts_sha256": {name: sha256_file(experiment / name) for name in
            ("release-A.sids", "release-B.sids", "public.pem", "feature_contract.json", "golden.jsonl", "provenance.json")},
        "release_C_envelope_sha256": hashlib.sha256(envelopes[2]).hexdigest()}


def check_status(response, context, release=None, event="status", slot=None):
    expected = {"event": event, "ready": True, "reason": "ok", "policy": context["policy"], "chip": "esp32s3",
        "schema": context["schema"], "feature_count": 2, "data_origin": "synthetic_plumbing"}
    if any(response.get(key) != value for key, value in expected.items()):
        raise RuntimeError("device must be ready buffered BUNDLE firmware with the expected schema; install bundle factory image first")
    validate_status_timing(response)
    version = response.get("version")
    if type(version) is not int or version not in (1, 2, 3):
        raise RuntimeError("device is not running one of the verified A/B/C releases")
    index = version - 1 if release is None else release
    model = context["models"][index]
    if version != model.version or response.get("release") != model.release or response.get("bundle_sha256") != context["payload_hashes"][index]:
        raise RuntimeError("device signed release identity differs from expected A/B/C")
    if slot is not None and response.get("active_slot") != slot:
        raise RuntimeError(f"unexpected active model slot: expected {slot}, received {response.get('active_slot')}")
    identity = context["identity"]
    prefix = f"esp-idf-{identity['idf_version']};app=1;elf="
    build = response.get("build", "")
    suffix = build[len(prefix):] if isinstance(build, str) and build.startswith(prefix) else ""
    if not re.fullmatch(r"[0-9a-f]{9,64}", suffix) or not identity["elf_sha256"].startswith(suffix):
        raise RuntimeError("live BUNDLE application build differs from the supplied firmware binary")


class Session:
    def __init__(self, transcript, timeout, events=None):
        self.transcript, self.timeout, self.events = transcript, timeout, events
        self.transport = None

    def open(self, port):
        self.transport = SerialTransport(port, on_read=lambda chunk: append(self.transcript,
            {"utc_ns": time.time_ns(), "direction": "rx_bytes", "bytes_hex": chunk.hex()}))
        status, elapsed = synchronize_serial(self.transport, lambda row: append(self.transcript, row), self.timeout)
        if self.events:
            append(self.events, {"action": "initial_status", "phase": "before", "command_kind": "STATUS",
                "response": status, "host_roundtrip_ns": elapsed, "wire_bytes": 7, "startup_status_probe": True})
        return status

    def receive(self, expected):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            line = self.transport.readline(min(.5, max(.001, deadline - time.monotonic())))
            if line is None:
                continue
            append(self.transcript, {"utc_ns": time.time_ns(), "direction": "rx", "line": line})
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(response, dict):
                if response.get("event") in expected or response.get("event") in {"error", "fw_error"}:
                    return response
                if response.get("event") in {"boot", "reboot"}:
                    raise RuntimeError("unexpected restart during bundle reuse trial")
        raise RuntimeError(f"timeout waiting for {sorted(expected)}; command is not retried")

    def command(self, line, expected, action, phase, **details):
        append(self.transcript, {"utc_ns": time.time_ns(), "direction": "tx", "line": line, "phase": phase})
        started = time.perf_counter_ns()
        event = {"action": action, "phase": phase, "command_kind": line.split(" ", 1)[0],
            "wire_bytes": len((line + "\n").encode("ascii")), **details}
        try:
            self.transport.write(line)
            response = self.receive(set(expected))
            event["response"] = response
        except BaseException as exc:
            event["error"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            event["host_roundtrip_ns"] = time.perf_counter_ns() - started
            if self.events:
                append(self.events, event)
        return response, event["host_roundtrip_ns"]

    def close(self):
        if self.transport:
            fragment = self.transport.take_pending_fragment()
            if fragment:
                append(self.transcript, {"utc_ns": time.time_ns(), "direction": "rx", "complete_line": False,
                    "bytes_hex": fragment.hex(), "line": fragment.decode("utf-8", errors="replace"), "phase": "session_end_fragment"})
            self.transport.close()
            self.transport = None


def restore(args, trial_dir):
    command = [sys.executable, "-m", "esptool", "--chip", "esp32s3", "--port", args.port,
        "--after", "hard_reset", "erase_region", "0x3b0000", "0x20000"]
    write_json(trial_dir / "restore_command.json", {"argv": command, "started_utc": now(),
        "scope": "two model partitions only; application and OTA selection untouched"})
    with (trial_dir / "restore.log").open("x", encoding="utf-8") as stream:
        completed = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, text=True, timeout=60, check=False)
    output = (trial_dir / "restore.log").read_text(encoding="utf-8", errors="replace")
    if completed.returncode != 0 or "Erase completed successfully" not in output:
        raise RuntimeError(f"model-slot restore failed (esptool exit {completed.returncode}); inspect restore.log")
    # This records esptool's report after the authorized erase. It is NOT a
    # pre-erase identity guard or secure attestation of the user-supplied label.
    macs = re.findall(r"MAC:\s*([0-9a-fA-F:]{17})", output)
    return {"command": command, "returncode": completed.returncode, "log_sha256": sha256_file(trial_dir / "restore.log"),
        "reported_macs": sorted(set(value.lower() for value in macs)), "identity_attested": False}


def run_trial(args, context, output, index, campaign_manifest_sha256):
    output.mkdir(exist_ok=False)
    summary = {"status": "failed", "measurement_origin": "actual_mcu", "data_origin": "synthetic_plumbing",
        "policy": context["policy"], "inferred_records": 0, "label_mismatches": 0, "max_probability_abs_error": 0.0,
        "accepted_updates": 0, "timing_validated_updates": 0, "reboot_verified": False, "post_reboot_probe_passed": False,
        "restore_attempted": False, "restore_completed": False}
    manifest = {"measurement_origin": "actual_mcu", "hardware_measured": True, "data_origin": "synthetic_plumbing",
        "policy": context["policy"], "board_id": args.board_id, "board_id_kind": "user_supplied_label", "started_utc": now(),
        "campaign_stage": "synthetic_bundle_stage_timing_v2_pilot", "trial_index": index,
        "campaign_manifest_sha256": campaign_manifest_sha256, "planned_trials": args.trials,
        "host_runner_revision": REVISION, "host_runner_sha256": sha256_file(__file__),
        "timing_schema": 2, "crypto_context": "shared_warm",
        "timing_support_sha256": sha256_file(ROOT / "tools/stage_timing_support.py"),
        "serial_runner_sha256": sha256_file(ROOT / "host/ids_update_lab/serial_runner.py"),
        "firmware_application_sha256": context["identity"]["image_sha256"], "firmware_identity": context["identity"],
        "artifacts_sha256": context["artifacts_sha256"], "release_C_envelope_sha256": context["release_C_envelope_sha256"],
        "schema_sha256": context["schema"], "numerical_tolerance": {"absolute": TOLERANCE, "relative": 0.0},
        "threshold_neighborhood": 2e-5, "checkpoint": "none", "fault_kind": "none", "physical_power_loss_tested": False,
        "update_trials": 2, "inference_repetitions": 1, "golden_total_records": 63, "selected_records": 63,
        "truncated_correctness_smoke": False, "negative_control_trials": 0,
        "transitions": [{"source": "A", "target": "B", "destination_slot": 1, "destination_state": "explicitly_erased"},
            {"source": "B", "target": "C", "destination_slot": 0, "destination_state": "previously_committed_release_A"}],
        "parameters": {name: str(value) if isinstance(value, Path) else value for name, value in vars(args).items()}}
    write_json(output / "manifest.json", manifest)
    started = time.perf_counter_ns()
    with (output / "transcript.jsonl").open("x", encoding="utf-8") as transcript, \
         (output / "events.jsonl").open("x", encoding="utf-8") as events, \
         (output / "observations.jsonl").open("x", encoding="utf-8") as observations:
        session = Session(transcript, args.timeout, events)

        def measure(row, release, phase, primary=True):
            response, elapsed = session.command("INFER " + ",".join(format(float(value), ".9g") for value in row["raw"]),
                {"inference"}, "inference" if primary else "post_reboot_probe", phase)
            if (response.get("event") != "inference" or response.get("version") != release + 1 or
                response.get("policy") != context["policy"] or response.get("data_origin") != "synthetic_plumbing" or
                response.get("bundle_sha256") != context["payload_hashes"][release]):
                raise RuntimeError("inference identity differs from expected signed release")
            probability = response.get("probability")
            if isinstance(probability, bool) or not isinstance(probability, (int, float)) or not math.isfinite(probability) or not 0 <= probability <= 1:
                raise RuntimeError("invalid inference probability")
            expected = row["expected_" + "ABC"[release]]
            error = abs(probability - expected["probability"])
            matched = type(response.get("label")) is int and response["label"] == expected["label"]
            record = {"phase": phase, "record_id": row["record_id"], "repetition": 0,
                "expected": expected, "expected_A": row["expected_A"], "expected_B": row["expected_B"], "expected_C": row["expected_C"],
                "true_label": row.get("label"), "response": response, "host_roundtrip_ns": elapsed,
                "probability_abs_error": error, "label_match": matched, "tolerance_pass": error <= TOLERANCE,
                "near_threshold": abs(expected["probability"] - context["models"][release].threshold) <= 2e-5}
            if primary:
                append(observations, record)
                summary["inferred_records"] += 1
                summary["label_mismatches"] += int(not matched)
                summary["max_probability_abs_error"] = max(summary["max_probability_abs_error"], error)
            else:
                append(events, {"action": "post_reboot_known_vector", **record})
            if not matched or error > TOLERANCE:
                raise RuntimeError("inference differs from float32 reference (tolerance 2e-6)")

        try:
            print(f"Trial {index}/{args.trials}: restore model slots", flush=True)
            summary["restore_attempted"] = True
            restoration = restore(args, output)
            append(events, {"action": "restore_evidence", "phase": "preparation", **restoration})
            summary["restore_completed"] = True
            initial = session.open(args.port)
            check_status(initial, context, 0, slot=0)
            manifest["initial_status"] = initial
            write_json(output / "manifest.json", manifest)
            for row in context["rows"]:
                measure(row, 0, "before")
            for release, phase, slot, destination in ((1, "after_first", 1, "explicitly_erased"), (2, "after_reuse", 0, "previously_committed_release_A")):
                print(f"Trial {index}/{args.trials}: {'ABC'[release-1]} -> {'ABC'[release]} ({destination})", flush=True)
                response, _ = session.command("UPDATE " + context["envelopes"][release].hex(), {"update"},
                    "candidate_" + "ABC"[release], phase, destination_slot=slot, destination_state=destination)
                if (response.get("event") != "update" or response.get("accepted") is not True or
                    response.get("ready") is not True or response.get("version") != release + 1 or response.get("policy") != context["policy"]):
                    raise RuntimeError(f"candidate {'ABC'[release]} was not correctly accepted: {response}")
                summary["accepted_updates"] += 1
                timing = validate_bundle_timing(response)
                append(events, {"action": "candidate_" + "ABC"[release] + "_stages", "phase": phase,
                    "timing_schema": 2, "timing_executed_mask": 63, "destination_state": destination,
                    **{name + "_us": value for name, value in timing.items()}})
                summary["timing_validated_updates"] += 1
                status, _ = session.command("STATUS", {"status"}, "status_" + "ABC"[release], phase)
                check_status(status, context, release, slot=slot)
                for row in context["rows"]:
                    measure(row, release, phase)
            reply, _ = session.command("REBOOT", {"reboot"}, "persistence_reboot", "persistence")
            if reply.get("event") != "reboot" or reply.get("fault_kind") != "software_restart":
                raise RuntimeError("persistence reboot was not acknowledged")
            boot = session.receive({"boot"})
            append(events, {"action": "boot_after_reuse", "phase": "persistence", "response": boot})
            check_status(boot, context, 2, event="boot", slot=0)
            final, _ = session.command("STATUS", {"status"}, "final_status", "persistence")
            check_status(final, context, 2, slot=0)
            summary["reboot_verified"] = True
            measure(context["rows"][0], 2, "persistence", primary=False)
            summary["post_reboot_probe_passed"] = True
            manifest["final_status"] = final
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
    plan = {"format": "ids-update-lab-bundle-stage-timing-pilot-v2", "started_utc": now(), "planned_trials": args.trials,
        "sequence": "restore -> A:63 -> B:63 -> C:63 -> reboot C -> known-vector probe", "policy": context["policy"],
        "campaign_stage": "synthetic_bundle_stage_timing_v2_pilot", "measurement_origin": "actual_mcu",
        "data_origin": "synthetic_plumbing", "board_id": args.board_id, "board_id_kind": "user_supplied_label",
        "independent_boards": 1, "negative_controls": "not_run", "physical_power_loss_tested": False,
        "failure_policy": "stop first failure; preserve every attempt; no mutation retry or automatic resume",
        "firmware_identity": context["identity"], "artifacts_sha256": context["artifacts_sha256"],
        "release_C_envelope_sha256": context["release_C_envelope_sha256"], "host_runner_sha256": sha256_file(__file__),
        "timing_schema": 2, "crypto_context": "shared_warm",
        "timing_support_sha256": sha256_file(ROOT / "tools/stage_timing_support.py"),
        "parameters": {name: str(value) if isinstance(value, Path) else value for name, value in vars(args).items()}}
    write_json(output / "campaign_manifest.json", plan)
    plan_hash = sha256_file(output / "campaign_manifest.json")
    summary = {"status": "incomplete", "planned_trials": args.trials, "completed_trials": 0, "attempted_trials": 0,
        "accepted_updates": 0, "timing_validated_updates": 0, "inferred_records": 0, "data_origin": "synthetic_plumbing", "measurement_origin": "actual_mcu",
        "policy": context["policy"], "negative_controls": "not_run", "physical_power_loss_tested": False,
        "restore_attempts": 0, "completed_restores": 0, "count_scope": "all attempted trials, including partial failed trial"}

    def accumulate(result):
        summary["accepted_updates"] += result["accepted_updates"]
        summary["timing_validated_updates"] += result["timing_validated_updates"]
        summary["inferred_records"] += result["inferred_records"]
        summary["restore_attempts"] += int(result["restore_attempted"])
        summary["completed_restores"] += int(result["restore_completed"])

    try:
        # Gate the currently running application BEFORE the first erasure.
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
            trial_dir = output / summary["active_trial"]
            try:
                result = run_trial(args, context, trial_dir, index, plan_hash)
            except BaseException:
                failed_summary = trial_dir / "summary.json"
                if failed_summary.is_file():
                    accumulate(json.loads(failed_summary.read_text(encoding="utf-8")))
                raise
            summary["completed_trials"] += 1
            accumulate(result)
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
    parser.add_argument("--port", required=True)
    parser.add_argument("--policy", choices=("bundle", "model_only_factory_preprocess"), default="bundle")
    parser.add_argument("--experiment", required=True, type=Path)
    parser.add_argument("--release-c", required=True, type=Path)
    parser.add_argument("--firmware-bin", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--board-id", required=True)
    parser.add_argument("--trials", required=True, type=int, help="predeclared pilot trials on the same board; no automatic resume")
    parser.add_argument("--timeout", type=float, default=20)
    args = parser.parse_args(argv)
    try:
        run(args)
    except Exception as exc:
        parser.exit(1, f"error: {type(exc).__name__}: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
