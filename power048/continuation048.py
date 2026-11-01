"""Incident-specific continuation after power045 trials61 and113.

Original software: Oleksandr Kuznetsov. MIT license.
This does not reclassify the original timeout or permit a generic unsafe resume.
All admission checks precede flash writes; the old evidence is append-only.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import time

CHECKPOINT_MANIFEST_SHA256 = "d46bd06fbea35d975c775b6bb4c2a7ffb1630101eb9f7d0d7711086967dc12e5"
ORIGINAL_RUNNER_SHA256 = "521e3cf51b74f0f9c89abafec78af4584037e59ab84f24956a821ca511264319"
LATE_SUMMARY_SHA256 = "ae01b24d92bb3a2bf9cce383c5bb72c8cce82c52e8de239a3da0801f6d281a41"
LATE_SERIAL_SHA256 = "88559d2261931d66a17ca09a6b045a7a78c318fc71125ee5d86f9d1ff3b3c7c0"
BOARD_ID = "esp32s3-a0f262ebb558"
ADMISSION_NAME = "continuation048_admission.json"
ATTEMPT_NAME = "continuation048_attempt.json"
TOLERANCE = 2e-6
IDENTITY_FIELDS = (
    "version", "release", "bundle_sha256", "active_slot", "selector_sequence", "build",
    "chip", "policy", "erase_policy", "storage_layout", "storage_scheme", "runtime_abi",
    "schema", "feature_count", "pretransform",
)


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def append(path, data):
    with Path(path).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"utc_ns": time.time_ns(), **data}, allow_nan=False) + "\n")
        stream.flush()


def same_identity(status, expected):
    return status.get("event") == "status" and status.get("ready") is True and all(
        status.get(key) == expected[key] for key in IDENTITY_FIELDS
    )


def expected_commands(controls):
    return ["STATUS"] + [
        "INFER " + ",".join(format(float(value), ".9g") for value in raw)
        for raw in controls["raw"]
    ] + ["STATUS"]


def verify_checks(checks, controls, expected):
    raw_rows = controls.get("raw", [])
    wants = controls.get("expected", {}).get("B", [])
    if len(raw_rows) != 12 or len(wants) != 12 or len(checks) != 12:
        raise ValueError("Exactly twelve frozen B-model controls are required")
    for index, (check, raw, want) in enumerate(zip(checks, raw_rows, wants)):
        response = check.get("response", {})
        probability = response.get("probability")
        if (check.get("raw") != raw or check.get("expected") != want
                or response.get("event") != "inference"
                or response.get("version") != expected["version"]
                or response.get("bundle_sha256") != expected["bundle_sha256"]
                or response.get("runtime_abi") != expected["runtime_abi"]
                or response.get("policy") != expected["policy"]
                or response.get("pretransform") != expected["pretransform"]
                or response.get("label") != want["label"]
                or type(probability) not in (int, float) or not math.isfinite(probability)
                or abs(probability - want["probability"]) > TOLERANCE):
            raise ValueError("Late/live control mismatch at index " + str(index))


def verify_serial(path, diagnostic, controls):
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]
    commands = [x.get("line") for x in rows if x.get("direction") == "tx"]
    if commands != expected_commands(controls) or any(x.get("link") != "mcu" for x in rows):
        raise ValueError("Late serial command sequence is not STATUS + 12 INFER + STATUS")
    replies = [json.loads(x["line"]) for x in rows if x.get("direction") == "rx"]
    expected = [diagnostic["before"]] + [x["response"] for x in diagnostic["checks"]] + [diagnostic["after"]]
    if replies != expected:
        raise ValueError("Late serial replies differ from diagnostic summary")
    # Hashes bind the exact raw bytes as well as the decoded transcript.
    decoded = b"".join(bytes.fromhex(x["bytes_hex"]) for x in rows if x.get("direction") == "rx_bytes")
    raw_replies = [json.loads(line) for line in decoded.decode("utf-8").splitlines() if line.strip()]
    if raw_replies != expected:
        raise ValueError("Late raw USB bytes differ from decoded replies")


def verify_control(directory, controls, old, cfg):
    """Recompute the frozen power-only control, independently of its pass flags."""
    summary = read(directory / "summary.json")
    if (summary.get("status") != "complete" or summary.get("completed_cycles") != 100
            or summary.get("attempted_cycles") != 100 or summary.get("flash_mutation_attempted") is not False
            or summary.get("automatic_cleanup_power_commands") is not False
            or summary.get("recovery_window_seconds") != 20 or summary.get("off_ms") != 2000):
        raise ValueError("The separate100-cycle control is incomplete or changed protocol")
    initial = summary["initial_model"]
    if not same_identity(initial["before"], old) or not same_identity(initial["after"], old):
        raise ValueError("Control initial identity mismatch")
    verify_checks(initial["checks"], controls, old)
    cycles = [json.loads(line) for line in (directory / "cycle_results.jsonl").read_text().splitlines()]
    if [x.get("cycle") for x in cycles] != list(range(1, 101)):
        raise ValueError("Expected exactly100 separate control cycles")
    for cycle in cycles:
        if {k: v for k, v in cycle.items() if k != "utc_ns"} != read(directory / ("cycle_%03d.json" % cycle["cycle"])):
            raise ValueError("Control cycle JSON/JSONL mismatch")
        if cycle.get("status") != "passed" or not 0 <= cycle.get("recovery_seconds", -1) <= 20:
            raise ValueError("Control recovery outcome mismatch")
        for key in ("before", "after", "recovery_status"):
            if not same_identity(cycle[key], old):
                raise ValueError("Control changed old1136 identity")
        verify_checks(cycle["checks"], controls, old)
        probe = cycle["probe"]
        points = probe.get("rail_samples", [])
        if (probe.get("off_ms") != 2000 or probe.get("power_restored") is not True or not points
                or any(not isinstance(p, list) or len(p) != 2 or type(p[0]) is not int
                       or type(p[1]) is not int or p[0] < 0 or not 0 <= p[1] <= 65535 for p in points)
                or any(points[i][0] <= points[i - 1][0] for i in range(1, len(points)))):
            raise ValueError("Malformed control OFF trace")
        tail = [cfg["adc_zero_volts"] + cfg["adc_volts_per_count"] * p[1] for p in points if p[0] >= 100000]
        if not tail or max(tail) > cfg["rail_off_max_volts"] or points[-1][0] < 900000:
            raise ValueError("Control OFF trace does not establish supply loss")
        recovered_adc = [x for x in cycle["adc"] if x.get("label") == "at_status_recovery"]
        if len(recovered_adc) != 1:
            raise ValueError("Missing control recovery rail measurement")
        raw = recovered_adc[0]["response"].get("raw")
        if type(raw) is not int or not 0 <= raw <= 65535:
            raise ValueError("Malformed control recovery ADC")
        volts = cfg["adc_zero_volts"] + cfg["adc_volts_per_count"] * raw
        if not cfg["rail_on_min_volts"] <= volts <= 3.6 or abs(volts - recovered_adc[0]["volts"]) > 1e-12:
            raise ValueError("Control recovery rail measurement mismatch")
    rows = [json.loads(line) for line in (directory / "serial.jsonl").read_text().splitlines()]
    tx = lambda name: [x["line"] for x in rows if x.get("link") == name and x.get("direction") == "tx"]
    if tx("mcu") != expected_commands(controls) * 101:
        raise ValueError("Control MCU transcript includes unexpected commands")
    if tx("pico") != ["ID", "ADC"] + ["PROBE 2000", "ADC", "ADC"] * 100 + ["ADC"]:
        raise ValueError("Control Pico transcript includes unexpected commands")
    expected_mcu = [initial["before"]] + [x["response"] for x in initial["checks"]] + [initial["after"]]
    expected_pico = [summary["controller"], summary["adc"][0]["response"]]
    for cycle in cycles:
        expected_mcu.extend([cycle["before"]] + [x["response"] for x in cycle["checks"]] + [cycle["after"]])
        expected_pico.extend([cycle["probe"]] + [x["response"] for x in cycle["adc"]])
    expected_pico.append(summary["adc"][-1]["response"])
    for name in ("mcu", "pico"):
        decoded = b"".join(bytes.fromhex(x["bytes_hex"]) for x in rows
                           if x.get("link") == name and x.get("direction") == "rx_bytes")
        parsed = [json.loads(x["line"]) for x in rows if x.get("link") == name and x.get("direction") == "rx"]
        if [json.loads(line) for line in decoded.decode("utf-8").splitlines() if line.strip()] != parsed:
            raise ValueError("Control raw USB bytes differ from decoded transcript")
        if parsed != (expected_mcu if name == "mcu" else expected_pico):
            raise ValueError("Control serial responses differ from saved model/ADC evidence")
    return {"completed_cycles": 100, "numeric_checks_recomputed": 1212,
            "control_is_separate_from_main_trials": True, "main_trials_reclassified": False}


def validate_evidence(args, prior, controls, plan_path):
    """Pure offline admission for this exact113-trial checkpoint only."""
    if not (getattr(args, "resume", False) and getattr(args, "late_recovery", None)
            and getattr(args, "control_run", None)):
        raise ValueError("Requires --resume --late-recovery --control-run for the reviewed incident")
    if (args.board_id != BOARD_ID or args.allow_unconfirmed_phase_timing is not True
            or args.mcu_port.upper() != "COM13" or args.controller_port.upper() != "COM5"):
        raise ValueError("Continuation is bound to the original board, ports and timing protocol")
    run_root = Path(args.output).resolve().parent
    if Path(args.output).resolve() != run_root / "results":
        raise ValueError("Expected original run/results directory")
    expected_paths = {Path(plan_path).resolve(): run_root / "plan/plan.json",
                      Path(args.config).resolve(): run_root / "setup/powercut_config.json",
                      Path(args.preflight).resolve(): run_root / "preflight"}
    if any(got != want for got, want in expected_paths.items()):
        raise ValueError("Plan/config/preflight must be the original run files")
    if any((Path(args.output) / name).exists() for name in (ADMISSION_NAME, ATTEMPT_NAME)):
        raise ValueError("Continuation048 has already been attempted; automatic repetition is blocked")
    manifest = Path(__file__).with_name("incident113_hashes.json")
    if digest(manifest) != CHECKPOINT_MANIFEST_SHA256:
        raise ValueError("Bundled incident checkpoint manifest changed")
    frozen = read(manifest)
    late_directory = Path(args.late_recovery)
    if late_directory.is_file():
        late_directory = late_directory.parent
    control_directory = Path(args.control_run)
    for group, directory in (("run", run_root), ("late113", late_directory), ("control047", control_directory)):
        for relative, expected_hash in frozen[group].items():
            candidate = directory / relative
            if not candidate.is_file() or digest(candidate) != expected_hash:
                raise ValueError("Reviewed evidence changed/missing: " + group + "/" + relative)
    source = Path(args.root) / "revision039/powercut/run_powercut039.py"
    if digest(source) != ORIGINAL_RUNNER_SHA256:
        raise ValueError("Installed revision039 runner differs from the reviewed USB-fix version")
    if len(prior) != 113 or [x.get("trial") for x in prior] != list(range(1, 114)):
        raise ValueError("Only the exact113-trial checkpoint can be admitted")
    unsafe = [x for x in prior if x.get("state") not in ("old_valid", "new_valid") or x.get("update_rejected")]
    if ([x["trial"] for x in unsafe] != [61, 113]
            or any(x["state"] != "no_response" or x.get("update_rejected")
                   or x.get("rail_off_confirmed") is not True for x in unsafe)):
        raise ValueError("Only the investigated trial61 and113 timeouts are covered")
    if any(int(x.stem.split("_")[1]) > 113 for x in Path(args.output).glob("trial_*_intent.json")):
        raise ValueError("Later trial intents already exist; additional investigation required")
    old = prior[-1]["old"]
    if old["version"] != 1136 or old["release"] != "p39B-1136" or prior[-1]["candidate"]["version"] != 1140:
        raise ValueError("Unexpected incident113 model versions")
    late = read(late_directory / "summary.json")
    if (late.get("status") != "passed" or late.get("flash_mutation_attempted") is not False
            or late.get("late_recovery") != "old_valid" or late.get("checks_passed") != 12
            or not same_identity(late.get("before", {}), old)
            or not same_identity(late.get("after", {}), old)):
        raise ValueError("Late113 diagnostic does not establish unchanged old1136")
    verify_checks(late.get("checks", []), controls, old)
    verify_serial(late_directory / "serial.jsonl", late, controls)
    control_review = verify_control(control_directory, controls, old, read(args.config))
    return {"schema": "power048_incident113_review_v1", "incident_trials": [61, 113],
            "original_states": {"61": "no_response", "113": "no_response"},
            "late_states": {"61": "old_valid", "113": "old_valid"},
            "late_state_is_not_original_endpoint": True, "first_continued_trial": 114,
            "remaining_trials": 87, "checkpoint_manifest_sha256": CHECKPOINT_MANIFEST_SHA256,
            "original_file_sha256": frozen, "original_runner_sha256": ORIGINAL_RUNNER_SHA256,
            "late_summary_sha256": LATE_SUMMARY_SHA256, "late_serial_sha256": LATE_SERIAL_SHA256,
            "expected_identity": old, "reviewed_late_checks": 12, "control047_review": control_review,
            "protocol_epoch": {"revision": "048", "recovery_window_seconds": 20,
                "timing_grid_changed": False, "trial61_replayed": False, "trial113_replayed": False,
                "changes": ["explicit incident113 admission after separate100-cycle control",
                            "read-only ADC at recovery endpoints outside primary recovery decision",
                            "original retry loop unchanged; ADC never reclassifies the endpoint",
                            "no extra ON command at cleanup"],
                "sleep_cause_proven": False, "failure_cause_proven": False}}


def verify_live(mcu, status, review, controls):
    """Only INFER and STATUS. Never ARM, UPDATE, reset, or power control."""
    expected = review["expected_identity"]
    if not same_identity(status, expected):
        raise ValueError("Live model differs from reviewed old1136; no flash update permitted")
    if len(controls.get("raw", [])) != 12 or len(controls.get("expected", {}).get("B", [])) != 12:
        raise ValueError("Expected exactly twelve live controls")
    checks = []
    for raw, want in zip(controls["raw"], controls["expected"]["B"]):
        response = mcu.request("INFER " + ",".join(format(float(x), ".9g") for x in raw), {"inference"})
        check = {"raw": raw, "expected": want, "response": response}
        checks.append(check)
    verify_checks(checks, controls, expected)
    after = mcu.request("STATUS", {"status"})
    if not same_identity(after, expected):
        raise ValueError("Live model identity changed during controls")
    return {"before": status, "after": after, "checks": checks, "checks_passed": 12,
            "flash_mutation_attempted": False, "power_control_attempted": False}


def port_snapshot():
    try:
        from serial.tools import list_ports
        return [{"device": p.device, "description": p.description, "hwid": p.hwid,
                 "vid": p.vid, "pid": p.pid, "serial_number": p.serial_number}
                for p in list_ports.comports()]
    except Exception as exc:
        return {"enumeration_error": repr(exc)}


class SleepGuard:
    """Temporary per-thread Windows system-awake request, restored on exit.

    Does not prevent manual sleep, lid closure, shutdown, or USB power policies.
    """
    def __init__(self, log_path):
        self.log_path = Path(log_path)
        self.previous = None
        self.setter = None

    def __enter__(self):
        if os.name != "nt":
            append(self.log_path, {"event": "system_awake_not_applicable", "platform": os.name})
            return self
        self.setter = ctypes.windll.kernel32.SetThreadExecutionState
        self.setter.argtypes = [ctypes.c_uint32]
        self.setter.restype = ctypes.c_uint32
        previous = self.setter(0x80000001)  # ES_CONTINUOUS | ES_SYSTEM_REQUIRED
        if not previous:
            raise OSError("SetThreadExecutionState failed; no hardware operation was started")
        self.previous = previous
        try:
            append(self.log_path, {"event": "system_awake_requested", "previous": previous,
                                   "flags": 0x80000001, "persistent_settings_changed": False})
        except BaseException:
            self.setter(previous | 0x80000000)
            self.previous = None
            raise
        return self

    def __exit__(self, exc_type, exc, traceback):
        if self.previous is not None:
            restored = self.setter(self.previous | 0x80000000)
            append(self.log_path, {"event": "system_awake_restored", "success": bool(restored),
                                   "previous": self.previous})
            if not restored and exc_type is None:
                raise OSError("Failed to restore the previous Windows execution state")
        return False
