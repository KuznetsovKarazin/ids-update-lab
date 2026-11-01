"""Incident-specific continuation after power045 trial 61.

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

CHECKPOINT_MANIFEST_SHA256 = "4b4927802a867c2ddca13299bcd3e2f43a7a18563de944e4cd87c854a3ed545d"
ORIGINAL_RUNNER_SHA256 = "521e3cf51b74f0f9c89abafec78af4584037e59ab84f24956a821ca511264319"
LATE_SUMMARY_SHA256 = "8508ebaa7103dcbf27ce918cef373b39ce3a6ddec5856898e5f2ffc50f09ee75"
LATE_SERIAL_SHA256 = "00b36b4087c3d216cb0e8231312ef0da37d6c4f584dd15a2bb881cc7fd2330e1"
BOARD_ID = "esp32s3-a0f262ebb558"
ADMISSION_NAME = "continuation046_admission.json"
ATTEMPT_NAME = "continuation046_attempt.json"
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


def validate_evidence(args, prior, controls, plan_path):
    """Pure offline check. No file writes, imports of serial, or device access."""
    if not getattr(args, "resume", False) or not getattr(args, "late_recovery", None):
        raise ValueError("Incident admission requires run --resume --late-recovery")
    if args.board_id != BOARD_ID or args.allow_unconfirmed_phase_timing is not True:
        raise ValueError("Incident admission is bound to the original board and timing protocol")
    run_root = Path(args.output).resolve().parent
    if Path(args.output).resolve() != run_root / "results":
        raise ValueError("Expected original run/results directory")
    expected_paths = {
        Path(plan_path).resolve(): run_root / "plan/plan.json",
        Path(args.config).resolve(): run_root / "setup/powercut_config.json",
        Path(args.preflight).resolve(): run_root / "preflight",
    }
    if any(got != want for got, want in expected_paths.items()):
        raise ValueError("Plan/config/preflight must be the original run files")
    if any((Path(args.output) / name).exists() for name in (ADMISSION_NAME, ATTEMPT_NAME)):
        raise ValueError("This continuation has already been attempted; do not repeat it automatically")
    manifest = Path(__file__).with_name("incident061_hashes.json")
    if digest(manifest) != CHECKPOINT_MANIFEST_SHA256:
        raise ValueError("Bundled incident checkpoint manifest changed")
    frozen = read(manifest)
    for relative, expected_hash in frozen.items():
        candidate = run_root / relative
        if not candidate.is_file() or digest(candidate) != expected_hash:
            raise ValueError("Original incident evidence changed/missing: " + relative)
    source = Path(args.root) / "revision039/powercut/run_powercut039.py"
    if digest(source) != ORIGINAL_RUNNER_SHA256:
        raise ValueError("Installed revision039 runner differs from the reviewed USB-fix version")
    if len(prior) != 61 or [x.get("trial") for x in prior] != list(range(1, 62)):
        raise ValueError("Only the exact original 61-trial checkpoint can be admitted")
    unsafe = [x for x in prior if x.get("state") not in ("old_valid", "new_valid") or x.get("update_rejected")]
    if (len(unsafe) != 1 or unsafe[0]["trial"] != 61 or unsafe[0]["state"] != "no_response"
            or unsafe[0].get("update_rejected") or unsafe[0].get("rail_off_confirmed") is not True):
        raise ValueError("Only the investigated terminal trial61 no_response is covered")
    if any(int(x.stem.split("_")[1]) > 61 for x in Path(args.output).glob("trial_*_intent.json")):
        raise ValueError("Later trial intents already exist; additional investigation required")
    old = prior[-1]["old"]
    if old["version"] != 749 or old["release"] != "p39B-749" or prior[-1]["candidate"]["version"] != 750:
        raise ValueError("Unexpected incident model versions")
    diagnostic_path = Path(args.late_recovery)
    if diagnostic_path.is_dir():
        diagnostic_path = diagnostic_path / "summary.json"
    serial_path = diagnostic_path.with_name("serial.jsonl")
    if digest(diagnostic_path) != LATE_SUMMARY_SHA256 or digest(serial_path) != LATE_SERIAL_SHA256:
        raise ValueError("Late diagnostic files differ from the reviewed twelve-control capture")
    late = read(diagnostic_path)
    if (late.get("status") != "passed" or late.get("flash_mutation_attempted") is not False
            or late.get("late_recovery") != "old_valid" or late.get("checks_passed") != 12
            or not same_identity(late.get("before", {}), old)
            or not same_identity(late.get("after", {}), old)):
        raise ValueError("Late diagnostic does not establish the unchanged old model")
    verify_checks(late.get("checks", []), controls, old)
    verify_serial(serial_path, late, controls)
    return {
        "schema": "power046_incident061_review_v1", "incident_trial": 61,
        "original_state": "no_response", "late_state": "old_valid",
        "late_state_is_not_original_endpoint": True,
        "first_continued_trial": 62, "remaining_trials": 139,
        "checkpoint_manifest_sha256": CHECKPOINT_MANIFEST_SHA256,
        "original_file_sha256": frozen, "original_runner_sha256": ORIGINAL_RUNNER_SHA256,
        "late_summary_sha256": LATE_SUMMARY_SHA256, "late_serial_sha256": LATE_SERIAL_SHA256,
        "expected_identity": old, "reviewed_late_checks": 12,
        "protocol_epoch": {
            "revision": "046", "recovery_window_seconds": 20,
            "timing_grid_changed": False, "trial61_replayed": False,
            "changes": ["explicit incident61 late-recovery admission", "log serial open/recovery errors",
                        "temporary Windows system-awake request"],
            "sleep_cause_proven": False,
        },
    }


def verify_live(mcu, status, review, controls):
    """Only INFER and STATUS. Never ARM, UPDATE, reset, or power control."""
    expected = review["expected_identity"]
    if not same_identity(status, expected):
        raise ValueError("Live model differs from reviewed old749; no flash update permitted")
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
