#!/usr/bin/env python3
"""Read-only diagnostic for the preserved power045 trial113 incident.

Original software: Oleksandr Kuznetsov. No continuation or device reset is offered.
Only one serial open is attempted; the only application commands are STATUS/INFER.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace
import zipfile

CASE_HASHES = {
    "results/trial_results.jsonl": "6984bd8c08c1279f78b52b7fffc23c46e3d47882c59b587283e4bd67e675220a",
    "results/run_binding.json": "f2fd73e76e0ed105d59459f797f40a1e4f9c282f20db35f3b637049132a59060",
    "plan/plan.json": "cea659fad777b410ab055462c08a8b32c5754ac7dc807378dbc12f26f89507ec",
    "plan/model.json": "aae3547306fd278c543c0a601864883116039019386a401efa99d992bb070311",
    "plan/controls.json": "1839e9c7371fcc502fd38786dd7053a02649c82f31f4e0e0ced98e3a9aacaa53",
}
RUNTIME_HASHES = {
    "run_powercut046.py": "23d461700d99438b8d91113656643a6f153cfe60d7f0cefad353f42b8e783532",
    "continuation046.py": "c106f36404ce328a5b5606f40b3e3d4f5f7b893c3fdb0997234e70eb58f63b5f",
}
IDENTITY_KEYS = (
    "version", "release", "bundle_sha256", "active_slot", "selector_sequence", "build",
    "chip", "policy", "erase_policy", "storage_layout", "storage_scheme", "runtime_abi",
    "schema", "feature_count", "pretransform",
)
MODEL_KEYS = ("version", "release", "bundle_sha256")
TOLERANCE = 2e-6


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    def safe(item):
        if isinstance(item, float) and not math.isfinite(item):
            return {"nonfinite_float": repr(item)}
        if isinstance(item, dict):
            return {key: safe(child) for key, child in item.items()}
        if isinstance(item, list):
            return [safe(child) for child in item]
        return item
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(safe(value), stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def error_info(exc):
    return {"type": type(exc).__name__, "repr": repr(exc), "message": str(exc),
            "errno": getattr(exc, "errno", None), "winerror": getattr(exc, "winerror", None)}


def load_runner(directory):
    sys.path.insert(0, str(directory))
    spec = importlib.util.spec_from_file_location("diagnostic113_runtime", directory / "run_powercut046.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def validate_inputs(run, runner_dir):
    for relative, expected in CASE_HASHES.items():
        if digest(run / relative) != expected:
            raise ValueError("Incident input changed: " + relative)
    for name, expected in RUNTIME_HASHES.items():
        if digest(runner_dir / name) != expected:
            raise ValueError("Runner source differs from the captured revision046: " + name)
    trials = [json.loads(line) for line in (run / "results/trial_results.jsonl").read_text().splitlines()]
    if len(trials) != 113 or [x.get("trial") for x in trials] != list(range(1, 114)):
        raise ValueError("Expected the exact checkpoint ending at trial113")
    incident = trials[-1]
    if incident.get("state") != "no_response" or incident.get("rail_off_confirmed") is not True:
        raise ValueError("Expected preserved trial113 no_response with rail-OFF evidence")
    binding = read(run / "results/run_binding.json")
    if binding["plan_sha256"] != CASE_HASHES["plan/plan.json"]:
        raise ValueError("Run binding does not match the frozen plan")
    runner = load_runner(runner_dir)
    _, _, _, controls = runner.load_plan(SimpleNamespace(plan=run / "plan"))
    if len(controls.get("raw", [])) != 12 or any(
        len(controls.get("expected", {}).get(role, [])) != 12 for role in ("A", "B")
    ):
        raise ValueError("Both frozen models require exactly twelve controls")
    return runner, incident, controls


def choose_identity(status, incident):
    old, candidate = incident["old"], incident["candidate"]
    if (status.get("event") != "status" or status.get("ready") is not True
            or any(key not in status for key in IDENTITY_KEYS)):
        raise ValueError("Unsupported or unavailable model STATUS")
    for key in IDENTITY_KEYS:
        if key not in MODEL_KEYS + ("active_slot", "selector_sequence") and status[key] != old[key]:
            raise ValueError("Unexpected live firmware/model contract: " + key)
    if all(status[key] == old[key] for key in MODEL_KEYS):
        if any(status[key] != old[key] for key in IDENTITY_KEYS):
            raise ValueError("Old identity has changed slot/selector metadata")
        return "B", "old_valid"
    if all(status[key] == candidate[key] for key in MODEL_KEYS):
        if (type(status["active_slot"]) is not int or status["active_slot"] not in (0, 1)
                or type(status["selector_sequence"]) is not int or status["selector_sequence"] < 0):
            raise ValueError("Invalid candidate storage identity")
        return "A", "new_valid"
    raise ValueError("Live model is neither the exact old1136 nor the exact candidate1140")


def verify_inference(response, status, expected):
    probability = response.get("probability")
    return (response.get("event") == "inference"
            and all(response.get(key) == status[key] for key in
                    ("version", "bundle_sha256", "runtime_abi", "policy", "pretransform"))
            and type(response.get("label")) is int and response["label"] == expected["label"]
            and type(probability) in (int, float) and math.isfinite(probability)
            and abs(probability - expected["probability"]) <= TOLERANCE)


def serial_metadata():
    import serial
    origin = Path(serial.__file__)
    paths = [origin, origin.with_name("serialwin32.py")]
    return {"version": getattr(serial, "__version__", getattr(serial, "VERSION", None)),
            "sources": [{"path": str(path), "sha256": digest(path)} for path in paths if path.is_file()]}


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
        return {"status": "error", "error": error_info(exc)}


def windows_snapshot(include_events=False):
    if os.name != "nt":
        return {"status": "not_applicable", "platform": os.name}
    script = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$result = @{}
try {
    $result.pnp = @(Get-CimInstance -ClassName Win32_PnPEntity | Where-Object {
        $_.PNPDeviceID -like '*VID_303A&PID_1001*'
    } | Select-Object Name, PNPDeviceID, DeviceID, Present, Status, ConfigManagerErrorCode, Service, ClassGuid, Manufacturer)
    $result.pnp_status = 'ok'
} catch { $result.pnp_status = 'error'; $result.pnp_error = $_.ToString() }
'''
    if include_events:
        script += r'''
try {
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        StartTime = ([DateTimeOffset]'2026-10-27T10:05:00Z').LocalDateTime
        EndTime = ([DateTimeOffset]'2026-10-27T10:10:00Z').LocalDateTime
    } -ErrorAction Stop | Where-Object {
        $_.ProviderName -match 'Kernel-PnP|UserPnp|DriverFrameworks|Kernel-Power|Power-Troubleshooter'
    } | Select-Object @{Name='utc';Expression={$_.TimeCreated.ToUniversalTime().ToString('o')}}, Id, ProviderName, RecordId, LevelDisplayName, Message)
    $result.events = $events
    $result.events_status = if ($events.Count) { 'ok' } else { 'no_matching_events' }
} catch {
    $result.events_status = if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { 'no_matching_events' } else { 'error' }
    $result.events_error = $_.ToString()
}
'''
    script += "\n$result | ConvertTo-Json -Depth 6 -Compress\n"
    try:
        response = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                  capture_output=True, timeout=25, check=False)
        stdout = response.stdout.decode("utf-8-sig", errors="replace").strip()
        result = {"status": "ok" if response.returncode == 0 else "error", "returncode": response.returncode,
                  "stderr": response.stderr.decode("utf-8-sig", errors="replace"),
                  "include_events": include_events}
        try:
            result["data"] = json.loads(stdout)
        except ValueError:
            result["stdout_unparsed"] = stdout
        return result
    except Exception as exc:
        return {"status": "error", "error": error_info(exc), "include_events": include_events}


def host_snapshot(port, include_events=False):
    result = {"utc_ns": time.time_ns(), "port": port}
    try:
        from serial.tools import list_ports
        result["ports"] = [{"device": p.device, "description": p.description, "hwid": p.hwid,
                            "vid": p.vid, "pid": p.pid, "serial_number": p.serial_number,
                            "location": p.location} for p in list_ports.comports()]
    except Exception as exc:
        result["ports_error"] = error_info(exc)
    result["query_dos_device"] = query_dos_device(port)
    result["windows"] = windows_snapshot(include_events)
    result["finished_utc_ns"] = time.time_ns()
    return result


def diagnose(args):
    run = Path(args.run).resolve(strict=True)
    runner_dir = Path(args.runner_dir).resolve(strict=True)
    port = args.mcu_port.upper()
    if port != "COM13":
        raise ValueError("This incident diagnostic is pinned to ESP32 COM13; no other port may be opened")
    out = run / ("diagnostic-incident113-" + str(time.time_ns()))
    out.mkdir()
    report = {"schema": "power045_incident113_diagnostic_v1", "original_author": "Oleksandr Kuznetsov",
              "status": "failed", "incident_trial": 113, "original_state": "no_response",
              "original_trial_reclassified": False, "flash_mutation_attempted": False,
              "power_control_attempted": False, "reset_command_sent": False, "port": port,
              "serial_open_attempts": 0, "commands": [], "checks": [],
              "started_utc_ns": time.time_ns(), "status_reply_freshness_independently_verified": False,
              "status_scope": "Replies received through the existing Link STATUS protocol; no boot-age or reboot provenance is inferred."}
    link = None
    stage = "validate_inputs"
    capture_host_after = False
    try:
        runner, incident, controls = validate_inputs(run, runner_dir)
        report["source_sha256"] = {"case": CASE_HASHES, "runtime": RUNTIME_HASHES, "diagnostic": digest(__file__)}
        report["pyserial"] = serial_metadata()
        shutil.copyfile(__file__, out / "diagnose113.py")
        before_host = host_snapshot(port)
        save(out / "host_before.json", before_host)
        capture_host_after = True
        selected = [p for p in before_host.get("ports", []) if p.get("device", "").upper() == port]
        if any(p.get("vid") != 0x303A or p.get("pid") != 0x1001 for p in selected):
            raise ValueError("COM13 is listed as a different USB device; no serial open attempted")
        (out / "serial.jsonl").touch(exist_ok=False)
        stage = "serial_open"
        report["serial_open_attempts"] = 1
        link = runner.Link(port, out / "serial.jsonl", "mcu")
        stage = "status_before"
        report["commands"].append("STATUS")
        before = link.request("STATUS", {"status"}, timeout=5)
        report["before"] = before
        role, late_state = choose_identity(before, incident)
        report["matched_role"] = role
        for index, (raw, expected) in enumerate(zip(controls["raw"], controls["expected"][role])):
            stage = "control_" + str(index)
            command = "INFER " + ",".join(format(float(value), ".9g") for value in raw)
            report["commands"].append(command)
            item = {"index": index, "raw": raw, "expected": expected, "ok": False}
            report["checks"].append(item)
            item["response"] = link.request(command, {"inference"}, timeout=5)
            item["ok"] = verify_inference(item["response"], before, expected)
            if not item["ok"]:
                raise ValueError("Control inference mismatch at index " + str(index))
        stage = "status_after"
        report["commands"].append("STATUS")
        after = link.request("STATUS", {"status"}, timeout=5)
        report["after"] = after
        if (choose_identity(after, incident) != (role, late_state)
                or any(after[key] != before[key] for key in IDENTITY_KEYS)):
            raise ValueError("Model/storage identity changed during the diagnostic")
        report.update(status="passed", late_recovery=late_state, checks_passed=12)
    except Exception as exc:
        report["failed_stage"] = stage
        report["error"] = error_info(exc)
    finally:
        if link is not None:
            try:
                link.close()
            except Exception as exc:
                report["close_error"] = error_info(exc)
                report["status"] = "failed"
        if capture_host_after:
            try:
                save(out / "host_after.json", host_snapshot(port, include_events=True))
            except Exception as exc:
                report["host_after_error"] = error_info(exc)
        report["finished_utc_ns"] = time.time_ns()
        save(out / "summary.json", report)
    archive = out.with_suffix(".zip")
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as target:
        for source in sorted(out.iterdir()):
            if source.is_file():
                target.write(source, arcname=out.name + "/" + source.name)
    with archive.with_name(archive.name + ".sha256").open("x", encoding="ascii") as stream:
        stream.write(digest(archive) + "  " + archive.name + "\n")
    return report, out, archive


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--runner-dir", type=Path, default=Path(__file__).resolve().parent.parent / "power046")
    parser.add_argument("--mcu-port", default="COM13")
    args = parser.parse_args(argv)
    try:
        report, out, archive = diagnose(args)
        print(json.dumps({key: report[key] for key in
                         ("status", "incident_trial", "late_recovery", "checks_passed", "failed_stage", "error", "close_error")
                         if key in report}, ensure_ascii=False))
        print("Saved:", out)
        print("Archive:", archive)
        return 0 if report["status"] == "passed" else 2
    except Exception as exc:
        print("error:", repr(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
