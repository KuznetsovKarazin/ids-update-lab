"""Incident-specific continuation after preserved power045 trial186.

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

CHECKPOINT_MANIFEST_SHA256 = "2db00c8f6e3c3f89b57a9647cf529f5e075aa37e407777d542ade096006a3c1b"
ORIGINAL_RUNNER_SHA256 = "521e3cf51b74f0f9c89abafec78af4584037e59ab84f24956a821ca511264319"
BOARD_ID = "esp32s3-a0f262ebb558"
ADMISSION_NAME = "continuation049_admission.json"
ATTEMPT_NAME = "continuation049_attempt.json"
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
    wants = controls.get("expected", {}).get("A", [])
    if len(raw_rows) != 12 or len(wants) != 12 or len(checks) != 12:
        raise ValueError("Exactly twelve frozen A-model controls are required")
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
    """Offline checkpoint check only: current trial186 recovery is still unknown."""
    if not (getattr(args, "resume", False) and getattr(args, "verify_incident186", False)):
        raise ValueError("Requires --resume --verify-incident186 for this exact checkpoint")
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
    if any((Path(args.output) / name).exists() for name in (ADMISSION_NAME, ATTEMPT_NAME, "incident186_late049")):
        raise ValueError("Continuation049 has already been attempted; automatic repetition is blocked")
    manifest = Path(__file__).with_name("incident186_hashes.json")
    if digest(manifest) != CHECKPOINT_MANIFEST_SHA256:
        raise ValueError("Bundled incident186 checkpoint manifest changed")
    frozen = read(manifest)
    for relative, expected_hash in frozen.items():
        candidate = run_root / relative
        if not candidate.is_file() or digest(candidate) != expected_hash:
            raise ValueError("Reviewed evidence changed/missing: " + relative)
    source = Path(args.root) / "revision039/powercut/run_powercut039.py"
    if digest(source) != ORIGINAL_RUNNER_SHA256:
        raise ValueError("Installed revision039 runner differs from the reviewed USB-fix version")
    if len(prior) != 186 or [x.get("trial") for x in prior] != list(range(1, 187)):
        raise ValueError("Only the exact186-trial checkpoint can be conditionally admitted")
    unsafe = [x for x in prior if x.get("state") not in ("old_valid", "new_valid") or x.get("update_rejected")]
    if ([x["trial"] for x in unsafe] != [61, 113, 186]
            or any(x["state"] != "no_response" or x.get("update_rejected")
                   or x.get("rail_off_confirmed") is not True for x in unsafe)):
        raise ValueError("Only preserved trial61,113 and186 timeouts are covered")
    if any(int(x.stem.split("_")[1]) > 186 for x in Path(args.output).glob("trial_*_intent.json")):
        raise ValueError("Later trial intents already exist; additional investigation required")
    old = prior[-1]["old"]
    if (old["version"] != 1696 or old["release"] != "p39A-1696" or old["active_slot"] != 0
            or old["selector_sequence"] != 1543 or prior[-1]["candidate"]["version"] != 1698
            or old["bundle_sha256"] != "f26ac55e93547d414997a60866e4bad7418eaecd07cd95d2d21cbef2016f7eb3"):
        raise ValueError("Unexpected incident186 model identity")
    if len(controls.get("raw", [])) != 12 or len(controls.get("expected", {}).get("A", [])) != 12:
        raise ValueError("Exactly twelve frozen A-model controls are required")
    return {"schema": "power049_incident186_conditional_review_v1", "incident_trials": [61, 113, 186],
            "original_states": {"61": "no_response", "113": "no_response", "186": "no_response"},
            "previous_late_states": {"61": "old_valid", "113": "old_valid"},
            "incident186_live_check_pending": True, "first_continued_trial": 187,
            "remaining_trials": 14, "checkpoint_manifest_sha256": CHECKPOINT_MANIFEST_SHA256,
            "original_file_sha256": frozen, "original_runner_sha256": ORIGINAL_RUNNER_SHA256,
            "expected_identity": old, "expected_control_role": "A",
            "protocol_epoch": {"revision": "049", "recovery_window_seconds": 20,
                "timing_grid_changed": False, "historical_trials_replayed": False,
                "changes": ["conditional old1696-only trial186 late observation saved before mutation",
                            "read-only ADC at recovery endpoints outside primary recovery decision",
                            "failed-endpoint QueryDosDevice after ADC outside original retry window",
                            "original retry loop unchanged; no extra ON command at cleanup"],
                "failure_cause_proven": False}}


def verify_live(mcu, status, review, controls, evidence=None):
    """Only STATUS/INFER, exact oldA1696. Partial checks survive every failure."""
    evidence = {} if evidence is None else evidence
    evidence.update(before=status, checks=[], flash_mutation_attempted=False, power_control_attempted=False)
    expected = review["expected_identity"]
    if not same_identity(status, expected):
        raise ValueError("Live model differs from exact old1696; no power or flash command is permitted")
    for index, (raw, want) in enumerate(zip(controls["raw"], controls["expected"]["A"])):
        check = {"index": index, "raw": raw, "expected": want}
        evidence["checks"].append(check)
        check["response"] = mcu.request("INFER " + ",".join(format(float(x), ".9g") for x in raw), {"inference"}, 5)
        probability = check["response"].get("probability")
        if (type(probability) not in (int, float) or not math.isfinite(probability)
                or abs(probability - want["probability"]) > TOLERANCE
                or check["response"].get("label") != want["label"]):
            raise ValueError("Live numeric control mismatch at index " + str(index))
    verify_checks(evidence["checks"], controls, expected)
    evidence["after"] = mcu.request("STATUS", {"status"}, 5)
    if not same_identity(evidence["after"], expected):
        raise ValueError("Live model identity changed during controls")
    evidence["checks_passed"] = 12
    return evidence


def json_safe(value):
    if isinstance(value, float) and not math.isfinite(value):
        return {"nonfinite_float": repr(value)}
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    return value


def query_dos_device(port):
    if os.name != "nt":
        return {"status": "not_applicable", "platform": os.name}
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        function = kernel.QueryDosDeviceW
        function.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        function.restype = ctypes.c_uint32
        buffer = ctypes.create_unicode_buffer(32768)
        count = function(port, buffer, len(buffer))
        if not count:
            code = ctypes.get_last_error()
            return {"status": "error", "winerror": code, "message": ctypes.FormatError(code)}
        return {"status": "ok", "targets": [x for x in buffer[:count].split("\0") if x]}
    except Exception as exc:
        return {"status": "error", "error": repr(exc)}


def host_snapshot(port):
    return {"utc_ns": time.time_ns(), "query_dos_device": query_dos_device(port), "ports": port_snapshot()}


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
