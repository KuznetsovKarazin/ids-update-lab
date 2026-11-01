#!/usr/bin/env python3
"""Separate 100-cycle power-only control; no model UPDATE or main-trial resume.

Original software: Oleksandr Kuznetsov. MIT license.
Pico must already be armed and target must already be on. Ctrl+C requests a stop
at a complete-cycle boundary, never an additional power transition.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import signal
import sys
import time
import zipfile

sys.dont_write_bytecode = True

CYCLES = 100
RECOVERY_SECONDS = 20
OFF_MS = 2000
CONFIG_SHA256 = "0090dc963b1f59575010d9efb482860ec94458ec5df2c041e42a7c6d9c0c5fdd"
HELPER_SHA256 = "b24a2ebdbba0df2ca2d8640d5c133d907b056fc445400aad1ce8f9eff1a41f1a"
LATE_SUMMARY_SHA256 = "ae01b24d92bb3a2bf9cce383c5bb72c8cce82c52e8de239a3da0801f6d281a41"
LATE_SERIAL_SHA256 = "88559d2261931d66a17ca09a6b045a7a78c318fc71125ee5d86f9d1ff3b3c7c0"
LOCK_NAME = "control047_active.lock"


class StopRequested(Exception):
    pass


def helper_module():
    path = Path(__file__).with_name("diagnose113_helpers.py")
    import hashlib
    if hashlib.sha256(path.read_bytes()).hexdigest() != HELPER_SHA256:
        raise ValueError("Bundled diagnostic helper differs from the reviewed source")
    spec = importlib.util.spec_from_file_location("power047_diagnostic_helper", path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def validate(args):
    d = helper_module()
    run = Path(args.run).resolve(strict=True)
    directory = Path(args.runner_dir).resolve(strict=True)
    if args.mcu_port.upper() != "COM13" or args.controller_port.upper() != "COM5":
        raise ValueError("This control is pinned to ESP32 COM13 and Pico COM5")
    r, incident, controls = d.validate_inputs(run, directory)
    config_path = run / "setup/powercut_config.json"
    if d.digest(config_path) != CONFIG_SHA256:
        raise ValueError("Original calibrated wiring config changed")
    cfg = d.read(config_path)
    r.validate_wiring(cfg, config_path, require_phase_timing=False)
    if cfg.get("off_ms") != OFF_MS:
        raise ValueError("Control requires the original two-second OFF interval")
    late_dir = Path(args.late_recovery).resolve(strict=True)
    if d.digest(late_dir / "summary.json") != LATE_SUMMARY_SHA256 or d.digest(late_dir / "serial.jsonl") != LATE_SERIAL_SHA256:
        raise ValueError("Late113 evidence differs from the reviewed archive")
    late = d.read(late_dir / "summary.json")
    if late.get("status") != "passed" or late.get("late_recovery") != "old_valid" or len(late.get("checks", [])) != 12:
        raise ValueError("Late113 diagnostic has not passed twelve old-model controls")
    for key in ("before", "after"):
        if d.choose_identity(late[key], incident) != ("B", "old_valid"):
            raise ValueError("Late113 old model mismatch")
    for check, raw, expected in zip(late["checks"], controls["raw"], controls["expected"]["B"]):
        if check["raw"] != raw or check["expected"] != expected or not d.verify_inference(check["response"], late["before"], expected):
            raise ValueError("Late113 numeric evidence mismatch")
    serial = [json.loads(x) for x in (late_dir / "serial.jsonl").read_text().splitlines()]
    commands = [x["line"] for x in serial if x.get("direction") == "tx"]
    expected_commands = ["STATUS"] + ["INFER " + ",".join(format(float(v), ".9g") for v in raw) for raw in controls["raw"]] + ["STATUS"]
    replies = [json.loads(x["line"]) for x in serial if x.get("direction") == "rx"]
    if commands != expected_commands or replies != [late["before"]] + [x["response"] for x in late["checks"]] + [late["after"]]:
        raise ValueError("Late113 raw commands/replies mismatch")
    return {"d": d, "r": r, "run": run, "directory": directory, "incident": incident,
            "controls": controls, "cfg": cfg, "config_path": config_path,
            "hashes": {"case": d.CASE_HASHES, "runtime": d.RUNTIME_HASHES, "config": CONFIG_SHA256,
                       "late_summary": LATE_SUMMARY_SHA256, "late_serial": LATE_SERIAL_SHA256}}


def append(path, row):
    def safe(value):
        if isinstance(value, float) and not math.isfinite(value):
            return {"nonfinite_float": repr(value)}
        if isinstance(value, dict):
            return {k: safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [safe(v) for v in value]
        return value
    with Path(path).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(safe({"utc_ns": time.time_ns(), **row}), allow_nan=False) + "\n")
        stream.flush()


def identity_checks(mcu, ctx, evidence, before=None):
    d, incident, controls = ctx["d"], ctx["incident"], ctx["controls"]
    before = mcu.request("STATUS", {"status"}, timeout=5) if before is None else before
    evidence["before"] = before
    if d.choose_identity(before, incident) != ("B", "old_valid"):
        raise ValueError("Power-only control requires unchanged old1136, not candidate or another model")
    evidence["checks"] = []
    for index, (raw, expected) in enumerate(zip(controls["raw"], controls["expected"]["B"])):
        item = {"index": index, "raw": raw, "expected": expected, "ok": False}
        evidence["checks"].append(item)
        command = "INFER " + ",".join(format(float(v), ".9g") for v in raw)
        item["response"] = mcu.request(command, {"inference"}, timeout=5)
        item["ok"] = d.verify_inference(item["response"], before, expected)
        if not item["ok"]:
            raise ValueError("Control inference mismatch at index " + str(index))
    after = mcu.request("STATUS", {"status"}, timeout=5)
    evidence["after"] = after
    if d.choose_identity(after, incident) != ("B", "old_valid") or any(after[k] != before[k] for k in d.IDENTITY_KEYS):
        raise ValueError("Model/storage identity changed during the numeric check")
    evidence["checks_passed"] = 12
    return after


def adc_sample(ctrl, cfg, evidence, label, t0=None, timeout=.5):
    started = time.monotonic()
    item = {"label": label, "request_monotonic": started, "utc_ns": time.time_ns()}
    evidence.setdefault("adc", []).append(item)
    try:
        response = ctrl.request("ADC", {"adc"}, timeout=timeout)
        item["response"] = response
        raw = response.get("raw")
        if type(raw) is not int or not 0 <= raw <= 65535:
            raise ValueError("Malformed Pico ADC reading")
        item["volts"] = cfg["adc_zero_volts"] + cfg["adc_volts_per_count"] * raw
        item["received_monotonic"] = time.monotonic()
        if t0 is not None:
            item["seconds_after_probe_reply"] = item["received_monotonic"] - t0
        if item["volts"] > 3.6:
            raise ValueError("Measured rail exceeds the 3.6 V control limit")
        return item
    except Exception as exc:
        item["error"] = repr(exc)
        raise


def recover(ctx, ctrl, transcript, evidence, t0):
    """Twenty seconds from probe reply receipt, including all ADC work."""
    deadline = t0 + RECOVERY_SECONDS
    immediate = adc_sample(ctrl, ctx["cfg"], evidence, "immediate_after_probe_reply", t0,
                           timeout=max(.001, min(.5, deadline - time.monotonic())))
    last_adc = immediate["received_monotonic"]
    first_error = True
    attempt = 0
    while time.monotonic() < deadline:
        if time.monotonic() - last_adc >= 1:
            sample = adc_sample(ctrl, ctx["cfg"], evidence, "during_recovery", t0,
                                timeout=max(.001, min(.25, deadline - time.monotonic())))
            last_adc = sample["received_monotonic"]
        if time.monotonic() >= deadline:
            break
        attempt += 1
        mcu = None
        stage = "open"
        try:
            mcu = ctx["r"].Link("COM13", transcript, "mcu")
            stage = "status"
            time.sleep(min(.3, max(0, deadline - time.monotonic())))
            if time.monotonic() >= deadline:
                raise TimeoutError("Twenty-second recovery deadline reached before STATUS")
            status = mcu.request("STATUS", {"status"}, timeout=min(2, deadline - time.monotonic()))
            receipt = time.monotonic()
            if receipt > deadline:
                raise TimeoutError("STATUS arrived after the fixed recovery deadline")
            evidence.update(recovery_status=status, recovery_seconds=receipt - t0, recovery_attempts=attempt)
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("No time remains to confirm the rail at STATUS recovery")
                at_status = adc_sample(ctrl, ctx["cfg"], evidence, "at_status_recovery", t0,
                                       timeout=min(.5, remaining))
                if time.monotonic() > deadline:
                    raise TimeoutError("Rail confirmation arrived after the recovery deadline")
                if at_status["volts"] < ctx["cfg"]["rail_on_min_volts"]:
                    raise ValueError("STATUS received but the measured rail is below the ON threshold")
            except BaseException:
                try:
                    mcu.close()
                except Exception as exc:
                    evidence["recovery_close_error"] = repr(exc)
                raise
            return mcu, status
        except Exception as exc:
            # A parsed status with bad/unknown rail is a terminal diagnostic failure.
            if "recovery_status" in evidence:
                raise
            row = {"event": "recovery_attempt_failed", "attempt": attempt, "stage": stage,
                   "seconds_after_probe_reply": time.monotonic() - t0, "error": ctx["d"].error_info(exc)}
            if first_error:
                row["query_dos_device"] = ctx["d"].query_dos_device("COM13")
                first_error = False
            evidence.setdefault("recovery_errors", []).append(row)
            append(transcript, {"link": "host", **row})
            if mcu is not None:
                try:
                    mcu.close()
                except Exception as close_exc:
                    row["close_error"] = repr(close_exc)
            time.sleep(min(.3, max(0, deadline - time.monotonic())))
    evidence["recovery_attempts"] = attempt
    evidence["deadline_seconds"] = RECOVERY_SECONDS
    evidence["query_dos_device_at_deadline"] = ctx["d"].query_dos_device("COM13")
    try:
        endpoint = adc_sample(ctrl, ctx["cfg"], evidence, "failed_endpoint_after_deadline", t0)
        evidence["rail_on_at_failed_endpoint"] = endpoint["volts"] >= ctx["cfg"]["rail_on_min_volts"]
    except Exception as exc:
        evidence["rail_on_at_failed_endpoint"] = None
        evidence["endpoint_adc_error"] = repr(exc)
    raise TimeoutError("No STATUS within the fixed twenty-second recovery window")


def run_control(args):
    ctx = validate(args)
    if args.prepare_only:
        return {"status": "prepared_not_run", "planned_cycles": CYCLES, "off_ms": OFF_MS,
                "recovery_window_seconds": RECOVERY_SECONDS, "hardware_access_attempted": False}, None, None
    d, r, cfg, run = ctx["d"], ctx["r"], ctx["cfg"], ctx["run"]
    out = run / ("control-power047-" + str(time.time_ns()))
    out.mkdir()
    transcript = out / "serial.jsonl"
    lock = run / LOCK_NAME
    report = {"schema": "power047_control_v1", "original_author": "Oleksandr Kuznetsov", "status": "failed",
              "planned_cycles": CYCLES, "completed_cycles": 0, "attempted_cycles": 0,
              "main_trial_count_unchanged": 113, "flash_mutation_attempted": False,
              "recovery_window_seconds": RECOVERY_SECONDS, "off_ms": OFF_MS,
              "source_sha256": ctx["hashes"], "started_utc_ns": time.time_ns(),
              "power_after_exit": "unknown_until_recorded_adc", "automatic_cleanup_power_commands": False}
    state = {"stop": False, "probe_in_flight": False}
    ctrl = mcu = awake = None
    owns_lock = False
    old_handler = None
    active_cycle = None
    def stop_requested(signum, frame):
        state["stop"] = True
        print("Stop requested: completing the current probe/recovery; no extra power command will be sent.", flush=True)
    try:
        with lock.open("x", encoding="utf-8") as stream:
            json.dump({"pid": os.getpid(), "output": str(out), "started_utc_ns": time.time_ns()}, stream)
        owns_lock = True
        old_handler = signal.signal(signal.SIGINT, stop_requested)
        sources = out / "sources"
        sources.mkdir()
        for source in (Path(__file__), Path(__file__).with_name("diagnose113_helpers.py"),
                       ctx["directory"] / "run_powercut046.py", ctx["directory"] / "continuation046.py",
                       ctx["directory"] / "incident061_hashes.json"):
            shutil.copyfile(source, sources / source.name)
        d.save(sources / "SHA256.json", {p.name: d.digest(p) for p in sources.iterdir() if p.is_file()})
        report["pyserial"] = d.serial_metadata()
        awake = r.continuation.SleepGuard(out / "host_power.jsonl")
        awake.__enter__()
        mcu = r.Link("COM13", transcript, "mcu")
        report["initial_model"] = {}
        identity_checks(mcu, ctx, report["initial_model"])
        if state["stop"]:
            raise StopRequested("Stop requested before the first power cycle")
        ctrl = r.Link("COM5", transcript, "pico")
        info = ctrl.request("ID", {"controller_id"}, timeout=5)
        report["controller"] = info
        if (info.get("protocol") != "ids-power039-v1" or info.get("config_sha256") != CONFIG_SHA256
                or info.get("enabled") is not True or info.get("armed") is not True
                or any(info.get(k) != cfg[k] for k in ("enable_pin", "phase_pin", "adc_pin", "active_high_enable"))):
            raise ValueError("Pico must already be armed with the exact reviewed config; no ARM is sent")
        baseline = adc_sample(ctrl, cfg, report, "baseline_before_cycles")
        if baseline["volts"] < cfg["rail_on_min_volts"]:
            raise ValueError("Baseline target rail is below the ON threshold")
        for cycle in range(1, CYCLES + 1):
            if state["stop"]:
                report["status"] = "stopped_by_user"
                break
            active_cycle = {"cycle": cycle, "status": "failed", "started_utc_ns": time.time_ns()}
            report["attempted_cycles"] = cycle
            append(out / "cycle_intents.jsonl", {"cycle": cycle, "command": "PROBE 2000"})
            state["probe_in_flight"] = True
            ctrl.send("PROBE 2000")
            active_cycle["probe_send_return_monotonic"] = time.monotonic()
            # Match the main experiment's open-at-cut, close-during-outage lifecycle.
            passive_deadline = time.monotonic() + .5
            active_cycle["passive_mcu_messages"] = []
            try:
                while time.monotonic() < passive_deadline:
                    message = mcu.receive(max(.001, passive_deadline - time.monotonic()))
                    if message is not None:
                        active_cycle["passive_mcu_messages"].append(message)
            except Exception as exc:
                active_cycle["passive_usb_error"] = d.error_info(exc)
            try:
                mcu.close()
            except Exception as exc:
                active_cycle["outage_close_error"] = d.error_info(exc)
            finally:
                mcu = None
            probe = ctrl.expect({"probe_result"}, timeout=10)
            t0 = time.monotonic()
            state["probe_in_flight"] = False
            active_cycle.update(probe=probe, probe_reply_monotonic=t0, recovery_deadline_monotonic=t0 + RECOVERY_SECONDS)
            if "outage_close_error" in active_cycle:
                adc_sample(ctrl, cfg, active_cycle, "after_probe_with_close_error", t0)
                raise RuntimeError("MCU handle close failed during outage; PROBE completed, stopping without another transition")
            if probe.get("off_ms") != OFF_MS or probe.get("power_restored") is not True:
                raise ValueError("Unexpected PROBE reply")
            active_cycle["rail_off"] = r.rail_evidence(probe, cfg)
            if active_cycle["rail_off"].get("rail_off_confirmed") is not True:
                raise ValueError("PROBE did not establish the required physical rail-OFF evidence")
            mcu, status = recover(ctx, ctrl, transcript, active_cycle, t0)
            identity_checks(mcu, ctx, active_cycle, before=status)
            active_cycle.update(status="passed", finished_utc_ns=time.time_ns())
            d.save(out / ("cycle_%03d.json" % cycle), active_cycle)
            append(out / "cycle_results.jsonl", active_cycle)
            report["completed_cycles"] = cycle
            progress = {"cycle": cycle, "status": "passed", "recovery_seconds": active_cycle["recovery_seconds"]}
            active_cycle = None
            print(json.dumps(progress), flush=True)
        else:
            report["status"] = "complete"
    except StopRequested as exc:
        report.update(status="stopped_before_cycles", stop_reason=str(exc))
    except BaseException as exc:
        report["error"] = d.error_info(exc)
        report["probe_in_flight_at_stop"] = state["probe_in_flight"]
        if active_cycle is not None:
            active_cycle.update(error=d.error_info(exc), finished_utc_ns=time.time_ns())
            try:
                cycle_path = out / ("cycle_%03d.json" % active_cycle["cycle"])
                if not cycle_path.exists():
                    d.save(cycle_path, active_cycle)
                d.save(out / "failed_cycle.json", active_cycle)
                append(out / "cycle_results.jsonl", active_cycle)
            except Exception as save_exc:
                report["failed_cycle_save_error"] = repr(save_exc)
                report["failed_cycle"] = active_cycle
    finally:
        # Never issue ON, OFF, ARM, DISARM, RESET, or another PROBE during cleanup.
        if ctrl is not None and not state["probe_in_flight"]:
            try:
                final = adc_sample(ctrl, cfg, report, "final_readonly")
                report["power_after_exit"] = "last_adc_on" if final["volts"] >= cfg["rail_on_min_volts"] else "last_adc_below_on"
                if final["volts"] < cfg["rail_on_min_volts"]:
                    report["status"] = "failed"
                    report["final_rail_error"] = "Final measured rail is below the ON threshold"
            except Exception as exc:
                report["final_adc_error"] = repr(exc)
                report["status"] = "failed"
        for name, link in (("mcu", mcu), ("pico", ctrl)):
            if link is not None:
                try:
                    link.close()
                except Exception as exc:
                    report.setdefault("cleanup_errors", []).append({"link": name, "error": repr(exc)})
                    report["status"] = "failed"
        if awake is not None:
            try:
                awake.__exit__(*sys.exc_info())
            except Exception as exc:
                report.setdefault("cleanup_errors", []).append({"operation": "restore_awake", "error": repr(exc)})
                report["status"] = "failed"
        if old_handler is not None:
            try:
                signal.signal(signal.SIGINT, old_handler)
            except Exception as exc:
                report.setdefault("cleanup_errors", []).append({"operation": "restore_signal", "error": repr(exc)})
                report["status"] = "failed"
        if owns_lock:
            try:
                lock.unlink()
            except Exception as exc:
                report.setdefault("cleanup_errors", []).append({"operation": "remove_lock", "error": repr(exc)})
                report["status"] = "failed"
        if report["status"] == "failed":
            try:
                d.save(out / "host_after_failure.json", d.host_snapshot("COM13", include_events=False))
            except Exception as exc:
                report["host_snapshot_error"] = repr(exc)
        report["finished_utc_ns"] = time.time_ns()
        d.save(out / "summary.json", report)
    archive = out.with_suffix(".zip")
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as target:
        for source in sorted(out.rglob("*")):
            if source.is_file():
                target.write(source, arcname=out.name + "/" + source.relative_to(out).as_posix())
    with archive.with_name(archive.name + ".sha256").open("x", encoding="ascii") as stream:
        stream.write(d.digest(archive) + "  " + archive.name + "\n")
    return report, out, archive


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--late-recovery", type=Path, required=True)
    parser.add_argument("--runner-dir", type=Path, default=Path(__file__).resolve().parent.parent / "power046")
    parser.add_argument("--mcu-port", default="COM13")
    parser.add_argument("--controller-port", default="COM5")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        report, out, archive = run_control(args)
        print(json.dumps({k: report[k] for k in ("status", "planned_cycles", "attempted_cycles", "completed_cycles", "error", "power_after_exit") if k in report}, ensure_ascii=False))
        if out is not None:
            print("Saved:", out)
            print("Archive:", archive)
        return 0 if report["status"] in ("complete", "prepared_not_run", "stopped_by_user", "stopped_before_cycles") else 2
    except Exception as exc:
        print("error:", repr(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
