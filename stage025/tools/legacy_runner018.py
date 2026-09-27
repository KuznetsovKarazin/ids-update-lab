#!/usr/bin/env python3
"""Stage 018: a pinned, functional A -> B log1p pipeline check on ESP32-S3.

No training, energy measurement, fault injection, automatic retry of mutations,
full-chip erase, or implicit restoration is performed by ``run``.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
TOLERANCE = 2e-6
DEFAULT_BOARD = "esp32s3-a0f262ebb558"
REQUIRED = {
    "run_018.py", "host/ids_update_lab/__init__.py",
    "host/ids_update_lab/package.py", "host/ids_update_lab/serial_runner.py",
    "host/ids_update_lab/artifacts.py", "artifacts/feature_contract.json",
    "artifacts/release-A.sids", "artifacts/release-B.sids", "artifacts/public.pem",
    "artifacts/golden.jsonl", "artifacts/experiment.json",
    "prebuilt/bundle/bootloader/bootloader.bin", "prebuilt/bundle/partition_table/partition-table.bin",
    "prebuilt/bundle/ota_data_initial.bin", "prebuilt/bundle/ids_update_lab.bin", "prebuilt/bundle/flash_args",
}
FLASH_ARGS = ["--flash_mode", "dio", "--flash_freq", "80m", "--flash_size", "4MB",
              "0x0", "bootloader/bootloader.bin", "0x10000", "ids_update_lab.bin",
              "0x8000", "partition_table/partition-table.bin", "0xd000", "ota_data_initial.bin"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def now():
    return {"utc_ns": time.time_ns(), "monotonic_ns": time.monotonic_ns()}


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"),
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite JSON: " + value)))


def verify_pins(root):
    manifest = root / "KIT_MANIFEST.json"
    data = read_json(manifest)
    pins = data.get("sha256", data.get("files", data))
    if not isinstance(pins, dict) or not REQUIRED.issubset(pins):
        raise ValueError("KIT_MANIFEST.json is missing required pinned inputs")
    for name, expected in pins.items():
        p = PurePosixPath(name)
        if p.is_absolute() or ".." in p.parts or "\\" in name or not re.fullmatch(r"[0-9a-f]{64}", str(expected)):
            raise ValueError("Invalid manifest path or digest: " + name)
        path = root / name
        if not path.resolve().is_relative_to(root.resolve()) or not path.is_file() or sha(path) != expected:
            raise ValueError("Kit integrity check failed: " + name)
    # An extra Python import must not silently come from an unreviewed package file.
    for path in (root / "host").rglob("*.py"):
        if path.relative_to(root).as_posix() not in pins:
            raise ValueError("Unpinned host Python file: " + str(path))
    actual_args = shlex.split((root / "prebuilt/bundle/flash_args").read_text(encoding="utf-8"))
    if actual_args != FLASH_ARGS:
        raise ValueError("flash_args differs from the reviewed ESP32-S3 4 MB layout")
    return pins, sha(manifest)


def load_context(root=ROOT):
    root = Path(root).resolve()
    pins, manifest_sha = verify_pins(root)
    sys.path.insert(0, str(root / "host"))
    package = importlib.import_module("ids_update_lab.package")
    serial = importlib.import_module("ids_update_lab.serial_runner")
    for name in ("ids_update_lab", "ids_update_lab.package", "ids_update_lab.serial_runner", "ids_update_lab.artifacts"):
        module = sys.modules[name]
        if not Path(module.__file__).resolve().is_relative_to(root / "host"):
            raise ValueError("Imported module outside the pinned kit: " + name)
    artifacts = root / "artifacts"
    experiment = read_json(artifacts / "experiment.json")
    required_meta = {"runtime_abi": 2, "preprocessing": "log1p", "feature_count": 8,
                     "expected_chip": "esp32s3", "data_origin": "TON_IoT_development"}
    for key, value in required_meta.items():
        if experiment.get(key) != value:
            raise ValueError("Unexpected experiment metadata: " + key)
    if not re.fullmatch(r"esp-idf-v5\.3\.2;app=1;elf=[0-9a-f]{9}", experiment.get("expected_build", "")):
        raise ValueError("A compiled firmware expected_build must be pinned before use")
    contract = read_json(artifacts / "feature_contract.json")
    schema = package.contract_hash(contract)
    if len(contract["feature_names"]) != 8:
        raise ValueError("Stage 018 requires exactly eight input features")
    public = package.load_public(artifacts / "public.pem")
    envelopes = {name: (artifacts / ("release-" + name + ".sids")).read_bytes() for name in ("A", "B")}
    models = {name: package.verify(blob, public, schema, 8, expected_abi=2) for name, blob in envelopes.items()}
    if (models["A"].version, models["B"].version) != (1, 2):
        raise ValueError("Unexpected A/B versions")
    if any(model.runtime_abi != 2 for model in models.values()):
        raise ValueError("Stage 018 requires ABI 2 packages")
    golden = [json.loads(line) for line in (artifacts / "golden.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    if not golden or len({row["id"] for row in golden}) != len(golden):
        raise ValueError("Golden records must be nonempty with unique IDs")
    golden_max_error = 0.0
    for row in golden:
        if not isinstance(row.get("origin"), str) or not row["origin"]:
            raise ValueError("Golden record is missing input provenance")
        raw = row["raw"]
        if len(raw) != 8 or any(type(x) not in (int, float) or not math.isfinite(x) or x < 0 for x in raw):
            raise ValueError("Golden input must have eight finite nonnegative values")
        for name, model in models.items():
            p, label = package.infer(model, raw)
            expected = row["expected_" + name]
            if (type(expected.get("probability")) not in (float, int) or not math.isfinite(expected["probability"])
                    or abs(p - expected["probability"]) > TOLERANCE or type(expected.get("label")) is not int
                    or expected["label"] != label):
                raise ValueError("Golden output differs from signed model: " + str(row["id"]) + " / " + name)
            golden_max_error = max(golden_max_error, abs(p - expected["probability"]))
    return {"root": root, "pins": pins, "kit_manifest_sha256": manifest_sha, "package": package,
            "serial": serial, "experiment": experiment, "schema": schema.hex(), "golden": golden,
            "envelopes": envelopes, "models": models, "golden_host_max_probability_abs_error": golden_max_error,
            "digests": {name: hashlib.sha256(blob[16:-256]).hexdigest() for name, blob in envelopes.items()}}


class Evidence:
    def __init__(self, output):
        self.output = Path(output)
        self.phase = "startup"
        self.streams = {name: (self.output / (name + ".jsonl")).open("x", encoding="utf-8")
                        for name in ("transcript", "events", "observations")}

    def record(self, item, stream="transcript"):
        item = {**now(), "phase": self.phase, **item}
        self.streams[stream].write(json.dumps(item, allow_nan=False) + "\n")
        self.streams[stream].flush()
        return item

    def event(self, event, **fields):
        return self.record({"event": event, **fields}, "events")

    def close(self):
        for stream in self.streams.values():
            stream.close()


class Link:
    def __init__(self, api, evidence, timeout):
        self.api, self.evidence, self.timeout = api, evidence, timeout
        self.transport = None
        self.allow_reconnect = False
        self.opens = 0

    def open(self, port):
        owner = self
        class ObservedTransport(self.api.SerialTransport):
            def _open(inner):
                owner.opens += 1
                owner.evidence.record({"direction": "host", "event": "serial_open_attempt", "attempt": owner.opens})
                if owner.opens > 1 and not owner.allow_reconnect:
                    raise RuntimeError("Unexpected serial disconnect: no reconnect or command retry")
                return super()._open()
        self.transport = ObservedTransport(port, on_read=lambda data: self.evidence.record(
            {"direction": "rx_bytes", "bytes_hex": data.hex()}))
        status, _ = self.api.synchronize_serial(self.transport, self.evidence.record, self.timeout)
        return status

    def receive(self, expected):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            line = self.transport.readline(min(.1, max(.001, deadline - time.monotonic())))
            if line is None:
                continue
            self.evidence.record({"direction": "rx", "line": line})
            try:
                result = json.loads(line, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
            except ValueError as exc:
                if self.allow_reconnect and expected == {"boot"} and not line.lstrip().startswith(("{", "[")):
                    continue  # Plain ESP-IDF boot text is preserved in the transcript.
                raise RuntimeError("Malformed protocol response; command will not be retried") from exc
            if not isinstance(result, dict) or result.get("event") not in expected:
                raise RuntimeError("Unexpected protocol event; command will not be retried: " + line)
            return result
        raise TimeoutError("No expected protocol response; command will not be retried")

    def command(self, line, expected):
        self.evidence.record({"direction": "tx", "line": line})
        start = time.monotonic_ns()
        self.transport.write(line)
        reply = self.receive(set(expected))
        self.evidence.event("command_response", command_kind=line.split(" ", 1)[0], response=reply,
                            tx_wire_bytes=len((line + "\n").encode("ascii")), host_roundtrip_ns=time.monotonic_ns() - start)
        return reply

    def close(self):
        if self.transport:
            fragment = self.transport.take_pending_fragment()
            if fragment:
                self.evidence.record({"direction": "rx", "bytes_hex": fragment.hex(), "complete_line": False,
                                      "line": fragment.decode("utf-8", errors="replace"), "phase": "session_end_fragment"})
            self.transport.close()
            self.transport = None


def check_status(reply, context, release, event="status"):
    model = context["models"][release]
    expected = {"event": event, "ready": True, "reason": "ok", "version": model.version,
                "release": model.release, "policy": "bundle", "schema": context["schema"], "feature_count": 8,
                "bundle_sha256": context["digests"][release], "chip": "esp32s3",
                "build": context["experiment"]["expected_build"], "data_origin": "TON_IoT_development",
                "runtime_abi": 2, "pretransform": "log1p"}
    for key, value in expected.items():
        if reply.get(key) != value or (key in ("ready", "version", "feature_count", "runtime_abi") and type(reply.get(key)) is not type(value)):
            raise RuntimeError("Unexpected " + event + " identity " + key + ": " + repr(reply.get(key)) + "; expected " + repr(value))


def check_inference(reply, expected, context, release):
    model = context["models"][release]
    identity = {"event": "inference", "version": model.version, "policy": "bundle",
                "bundle_sha256": context["digests"][release], "data_origin": "TON_IoT_development",
                "runtime_abi": 2, "pretransform": "log1p"}
    for key, value in identity.items():
        if reply.get(key) != value or (type(value) is int and type(reply.get(key)) is not int):
            raise RuntimeError("Inference identity mismatch: " + key)
    p = reply.get("probability")
    if type(p) not in (float, int) or not math.isfinite(p) or not 0 <= p <= 1:
        raise RuntimeError("Invalid/nonfinite inference probability")
    if type(reply.get("label")) is not int or reply["label"] not in (0, 1):
        raise RuntimeError("Invalid inference label")
    return abs(p - expected["probability"]), reply["label"] == expected["label"]


def check_replay(reply, context):
    """Validate the bundle core's replay rejection and no-flash-work timing trace.

    ``replay_or_downgrade`` belongs to Engine::update. The separate firmware-OTA
    dispatcher uses ``non_monotonic_version``; it is not a bundle response.
    Instrumented stage 018 must reject after candidate verification, before
    executing any erase, write, readback, or commit stage.
    """
    expected = {"event": "update", "accepted": False, "reason": "replay_or_downgrade",
                "ready": True, "version": context["models"]["B"].version, "policy": "bundle",
                "timing_schema": 2, "timing_measured": True, "timing_executed_mask": 1}
    for key, value in expected.items():
        if reply.get(key) != value or type(reply.get(key)) is not type(value):
            raise RuntimeError("Invalid bundle replay rejection " + key + ": " + repr(reply.get(key)))
    timings = reply.get("timing_us")
    if not isinstance(timings, dict):
        raise RuntimeError("Bundle replay rejection has no timing_us object")
    for stage in ("candidate_verify", "erase", "body_write", "readback", "readback_verify", "commit", "total"):
        if type(timings.get(stage)) is not int or timings[stage] < 0:
            raise RuntimeError("Invalid bundle replay timing: " + stage)
    for stage in ("erase", "body_write", "readback", "readback_verify", "commit"):
        if timings[stage] != 0:
            raise RuntimeError("Bundle replay unexpectedly executed flash stage: " + stage)
    if timings["total"] < timings["candidate_verify"]:
        raise RuntimeError("Bundle replay total timing is smaller than candidate verification")


def run_session(args, context, evidence, summary, manifest, link_factory=Link):
    link = link_factory(context["serial"], evidence, args.timeout)
    try:
        initial = link.open(args.port)
        check_status(initial, context, "A")
        summary["measurement_origin"] = "actual_mcu"
        save(args.output / "status_before.json", initial)
        manifest["initial_status"] = initial
        save(args.output / "manifest.json", manifest)

        def measure(phase, release):
            evidence.phase = phase
            rows = context["golden"]
            for index, row in enumerate(rows):
                expected = row["expected_" + release]
                command = "INFER " + ",".join(format(float(x), ".9g") for x in row["raw"])
                reply = link.command(command, {"inference", "error"})
                error, matched = check_inference(reply, expected, context, release)
                evidence.record({"record_id": row["id"], "origin": row["origin"], "expected": expected,
                                 "response": reply, "probability_abs_error": error, "label_match": matched,
                                 "tolerance_pass": error <= TOLERANCE}, "observations")
                summary["inferred_records"] += 1
                summary["label_mismatches"] += int(not matched)
                summary["max_probability_abs_error"] = max(summary["max_probability_abs_error"], error)
                if not matched or error > TOLERANCE:
                    raise RuntimeError("MCU differs from frozen float32 reference: " + str(row["id"]) + " / " + phase)
                if (index + 1) % 64 == 0 or index + 1 == len(rows):
                    print(f"{phase}: {index + 1}/{len(rows)}", flush=True)
            summary[phase + "_verified"] = True
            save(args.output / "summary.json", summary)

        measure("A", "A")
        evidence.phase = "update_B"
        # Persist the intent BEFORE sending the sole potentially accepted update.
        manifest["update_attempted"] = True
        manifest["update_attempt_time"] = now()
        save(args.output / "manifest.json", manifest)
        reply = link.command("UPDATE " + context["envelopes"]["B"].hex(), {"update", "error"})
        if (reply.get("event") != "update" or reply.get("accepted") is not True or reply.get("reason") != "ok"
                or type(reply.get("version")) is not int or reply["version"] != context["models"]["B"].version
                or reply.get("ready") is not True or reply.get("policy") != "bundle"):
            raise RuntimeError("Valid B update not confirmed: " + repr(reply))
        summary["update_accepted"] = True
        check_status(link.command("STATUS", {"status"}), context, "B")
        measure("B", "B")
        evidence.phase = "reboot_B"
        link.allow_reconnect = True
        response = link.command("REBOOT", {"reboot"})
        if response.get("fault_kind") != "software_restart":
            raise RuntimeError("Unexpected REBOOT acknowledgment")
        boot = link.receive({"boot"})
        evidence.event("boot_after_explicit_reboot", response=boot)
        check_status(boot, context, "B", event="boot")
        link.allow_reconnect = False
        check_status(link.command("STATUS", {"status"}), context, "B")
        summary["boot_verified"] = True
        measure("B_after_reboot", "B")
        evidence.phase = "negative_raw_input"
        invalid = link.command("INFER -1,0,0,0,0,0,0,0", {"error", "inference"})
        if invalid.get("event") != "error" or invalid.get("reason") != "negative_raw_input":
            raise RuntimeError("Negative raw input was not explicitly rejected")
        summary["negative_input_rejected"] = True
        check_status(link.command("STATUS", {"status"}), context, "B")
        evidence.phase = "replay_B"
        replay = link.command("UPDATE " + context["envelopes"]["B"].hex(), {"update", "error"})
        check_replay(replay, context)
        summary["replay_rejected"] = True
        final = link.command("STATUS", {"status"})
        check_status(final, context, "B")
        save(args.output / "status_after.json", final)
        summary["final_release"] = "B"
        summary["status"] = "complete"
    finally:
        link.close()


def expected_mac(board_id):
    match = re.fullmatch(r"esp32s3-([0-9a-fA-F]{12})", board_id)
    if not match:
        raise ValueError("--board-id must be esp32s3- followed by the 12 hexadecimal MAC digits")
    value = match.group(1).lower()
    return ":".join(value[index:index + 2] for index in range(0, 12, 2))


def esptool_step(args, context, evidence, name, command, invoke=subprocess.run):
    full = [sys.executable, "-m", "esptool", "--chip", "esp32s3", "--port", args.port] + command
    evidence.event("esptool_start", step=name, command=full)
    try:
        result = invoke(full, cwd=context["root"] / "prebuilt/bundle", capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=120, check=False)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        text = (stdout.decode("utf-8", errors="replace") if isinstance(stdout, bytes) else stdout)
        text += (stderr.decode("utf-8", errors="replace") if isinstance(stderr, bytes) else stderr)
        (args.output / (name + ".log")).write_text(text, encoding="utf-8")
        raise RuntimeError("esptool timed out; do not repeat automatically: " + name) from exc
    output = result.stdout + result.stderr
    (args.output / (name + ".log")).write_text(output, encoding="utf-8")
    macs = sorted(set(value.lower() for value in re.findall(r"\bMAC:\s*([0-9a-fA-F:]{17})", output)))
    record = {"step": name, "returncode": result.returncode, "reported_macs": macs,
              "log_sha256": sha(args.output / (name + ".log"))}
    evidence.event("esptool_end", **record)
    if result.returncode != 0:
        raise RuntimeError("esptool failed: " + name + "; inspect its log")
    if macs != [expected_mac(args.board_id)] or not re.search(r"Chip is ESP32-S3\b", output):
        raise RuntimeError("Unexpected chip or MAC reported by esptool: " + name)
    return record


def flash_session(args, context, evidence, summary, manifest, invoke=subprocess.run, link_factory=Link):
    evidence.phase = "chip_identity_before_flash"
    preflight = esptool_step(args, context, evidence, "00-identify", ["--after", "no_reset", "flash_id"], invoke)
    identity_log = (args.output / "00-identify.log").read_text(encoding="utf-8")
    if "Detected flash size: 4MB" not in identity_log:
        raise RuntimeError("Unexpected flash size; stage 018 image requires the verified 4 MB board")
    manifest["board_identity_source"] = "esptool chip and MAC before flash"
    manifest["verified_mac"] = expected_mac(args.board_id)
    manifest["flash_steps"] = [preflight]
    manifest["flash_mutation_attempted"] = True
    save(args.output / "manifest.json", manifest)
    evidence.phase = "flash_factory_A"
    written = esptool_step(args, context, evidence, "01-write-factory-A",
                           ["-b", "460800", "--after", "no_reset", "write_flash", *FLASH_ARGS], invoke)
    manifest["flash_steps"].append(written)
    save(args.output / "manifest.json", manifest)
    evidence.phase = "erase_model_slots_only"
    cleared = esptool_step(args, context, evidence, "02-erase-model-slots",
                           ["--after", "hard_reset", "erase_region", "0x3b0000", "0x20000"], invoke)
    manifest["flash_steps"].append(cleared)
    save(args.output / "manifest.json", manifest)
    evidence.phase = "verify_factory_A"
    link = link_factory(context["serial"], evidence, args.timeout)
    try:
        ready = link.open(args.port)
        check_status(ready, context, "A")
        summary["measurement_origin"] = "actual_mcu"
        save(args.output / "status_after.json", ready)
    finally:
        link.close()
    summary.update(status="complete", factory_A_verified=True, final_release="A",
                   model_erase_offset="0x3b0000", model_erase_bytes=131072,
                   board_identity_source=manifest["board_identity_source"])


def execute(args, context_loader=load_context, link_factory=Link, invoke=subprocess.run):
    if args.timeout <= 0:
        raise ValueError("--timeout must be positive")
    if args.command == "inspect":
        context = context_loader(ROOT)
        report = {"status": "complete", "command": "inspect", "hardware_accessed": False,
                  "pinned_files": len(context["pins"]), "kit_manifest_sha256": context["kit_manifest_sha256"],
                  "golden_records": len(context["golden"]), "golden_evaluations_verified": 2 * len(context["golden"]),
                  "golden_host_max_probability_abs_error": context["golden_host_max_probability_abs_error"],
                  "golden_tolerance_absolute": TOLERANCE, "golden_labels_exact": True,
                  "expected_build": context["experiment"]["expected_build"], "runtime_abi": 2,
                  "dependencies": {"host": "numpy, cryptography", "run": "pyserial", "flash": "esptool 4.x, pyserial"},
                  "note": "Manifest detects changes; authenticate the delivered ZIP hash separately. Inspect never opens a serial port."}
        print(json.dumps(report, indent=2))
        return report
    expected_mac(args.board_id)
    args.output = Path(args.output).resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = Evidence(args.output)
    summary = {"status": "failed", "stage": "018", "command": args.command,
               "measurement_origin": "not_measured", "data_origin": "TON_IoT_development", "policy": "bundle",
               "inferred_records": 0, "label_mismatches": 0, "max_probability_abs_error": 0.0,
               "update_accepted": False, "boot_verified": False, "negative_input_rejected": False,
               "replay_rejected": False, "energy_measured": False, "physical_power_loss_tested": False,
               "heldout_detection_quality_measured": False, "hardware_access_attempted": False}
    manifest = {"stage": "018", "command": args.command, "started": now(), "runner_sha256": sha(__file__),
                "port": args.port, "board_id": args.board_id, "board_identity_source": "user-supplied label",
                "numerical_tolerance_absolute": TOLERANCE, "numerical_tolerance_relative": 0.0,
                "update_attempted": False, "automatic_mutation_retry": False}
    save(args.output / "manifest.json", manifest)
    try:
        context = context_loader(ROOT)
        manifest.update(kit_manifest_sha256=context["kit_manifest_sha256"], input_sha256=context["pins"],
                        experiment=context["experiment"], golden_records=len(context["golden"]),
                        golden_passes=["A", "B", "B_after_reboot"] if args.command == "run" else [])
        save(args.output / "manifest.json", manifest)
        summary["hardware_access_attempted"] = True
        if args.command == "flash":
            flash_session(args, context, evidence, summary, manifest, invoke, link_factory)
        else:
            run_session(args, context, evidence, summary, manifest, link_factory)
    except Exception as exc:
        summary["error"] = str(exc)
        evidence.event("failed", error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        summary["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        save(args.output / "summary.json", summary)
        evidence.close()
    print(json.dumps({"run": str(args.output), **summary}))
    return summary


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest="command", required=True)
    for command in ("inspect", "flash", "run"):
        sub = commands.add_parser(command)
        sub.add_argument("--timeout", type=float, default=20.0)
        if command != "inspect":
            sub.add_argument("--port", required=True)
            sub.add_argument("--board-id", default=DEFAULT_BOARD)
            sub.add_argument("--output", type=Path, required=True, help="Fresh evidence directory; never overwritten")
    return p


if __name__ == "__main__":
    try:
        execute(parser().parse_args())
    except Exception as exc:
        print("error: " + str(exc), file=sys.stderr)
        sys.exit(1)
