"""Append-only experiment evidence for serial boards or the native simulator.

Native timings are never board measurements. ARM_FAIL only injects software
restart checkpoints; none of its results establishes physical power-loss safety.
"""
import datetime
import hashlib
import json
import math
import queue
from pathlib import Path
import subprocess
import threading
import time

from .artifacts import sha256_file, write_json
from .package import PackageError, contract_hash, infer, load_public, verify


class NativeTransport:
    def __init__(self, executable, store, model_only):
        self.command = [str(Path(executable).resolve()), "--store", str(Path(store).resolve())]
        if model_only:
            self.command.append("--model-only")
        self.process = None
        self._start()

    def _start(self):
        self.lines = queue.Queue()
        self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        process, lines = self.process, self.lines
        def reader():
            for line in process.stdout:
                lines.put(line.rstrip("\r\n"))
            lines.put(None)
        threading.Thread(target=reader, daemon=True).start()

    def write(self, line):
        self.process.stdin.write(line + "\n")
        self.process.stdin.flush()

    def readline(self, timeout):
        try:
            line = self.lines.get(timeout=timeout)
        except queue.Empty:
            return None
        if line is None:
            code = self.process.wait(timeout=2)
            if code == 75:
                self._start()
                return self.readline(timeout)
            raise RuntimeError(f"native process terminated with exit code {code}")
        return line

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()


class SerialTransport:
    def __init__(self, port, on_read=None):
        try:
            import serial
        except ImportError as exc:
            raise RuntimeError("pyserial is required for physical MCU transport: python -m pip install pyserial") from exc
        self.serial_module, self.port = serial, port
        self.on_read = on_read
        self.pending = bytearray()
        self.received_bytes = 0
        self.connection = self._open()

    def _open(self):
        # Opening with default asserted modem lines can reset an ESP32-S3.
        # Set both levels while the object is CLOSED, including on reconnect.
        connection = self.serial_module.Serial(port=None, baudrate=115200, timeout=0.05, write_timeout=3)
        connection.dtr = False
        connection.rts = False
        connection.port = self.port
        connection.open()
        return connection

    def write(self, line):
        self.connection.write((line + "\n").encode("ascii"))
        self.connection.flush()

    def readline(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            if b"\n" in self.pending:
                frame, _, remainder = self.pending.partition(b"\n")
                self.pending = bytearray(remainder)
                return frame.rstrip(b"\r").decode("utf-8", errors="replace")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                self.connection.timeout = min(0.05, remaining)
                chunk = self.connection.read(max(1, min(self.connection.in_waiting, 4096)))
                if chunk:
                    self.received_bytes += len(chunk)
                    self.pending.extend(chunk)
                    if self.on_read:
                        self.on_read(chunk)
            except (self.serial_module.SerialException, OSError):
                self.connection.close()
                # USB Serial/JTAG may temporarily disconnect during software reset.
                while time.monotonic() < deadline:
                    try:
                        self.connection = self._open()
                        break
                    except (self.serial_module.SerialException, OSError):
                        time.sleep(0.1)

    def take_pending_fragment(self):
        """Explicit framing boundary ONLY; caller must record returned bytes."""
        fragment = bytes(self.pending)
        self.pending.clear()
        return fragment

    def close(self):
        self.connection.close()


def synchronize_serial(transport, record, timeout, attempts=3, startup_wait=2.0, quiet_period=0.2):
    """Read-only startup handshake; malformed frames are logged, never salvaged.

    Startup is drained for at least startup_wait, with at most one extra quiet
    period. STATUS probes share a separate total `timeout` budget. Only this safe
    query is retried. No UPDATE/INFER/reboot/erase is issued by this function.
    """
    if attempts < 1 or timeout <= 0 or startup_wait < 0 or quiet_period <= 0:
        raise ValueError("invalid serial synchronization limits")

    def log_line(line, **extra):
        record({"utc_ns": time.time_ns(), "direction": "rx", "line": line, **extra})

    def drain(settle):
        began = time.monotonic()
        last_activity = began
        seen = transport.received_bytes
        deadline = began + settle + quiet_period
        while time.monotonic() < deadline:
            line = transport.readline(min(0.05, max(0.001, deadline - time.monotonic())))
            now = time.monotonic()
            if transport.received_bytes != seen or line is not None:
                seen = transport.received_bytes
                last_activity = now
            if line is not None:
                log_line(line, phase="startup_drain")
            if now - began >= settle and now - last_activity >= quiet_period:
                break
        # A missing newline cannot become a protocol frame merely by timing out.
        # Startup synchronization explicitly closes that fragment and preserves it.
        fragment = transport.take_pending_fragment()
        if fragment:
            log_line(fragment.decode("utf-8", errors="replace"), complete_line=False,
                bytes_hex=fragment.hex(), phase="startup_fragment", reason="explicit_startup_framing_boundary")

    drain(startup_wait)
    overall_deadline = time.monotonic() + timeout
    for attempt in range(1, attempts + 1):
        remaining = overall_deadline - time.monotonic()
        if remaining <= 0:
            break
        if attempt > 1:
            # Preserve late/partial bytes from the failed safe probe before
            # establishing the next boundary. Nothing is silently flushed.
            drain(0.0)
            remaining = overall_deadline - time.monotonic()
            if remaining <= 0:
                break
        start = time.perf_counter_ns()
        for line in ("", "STATUS"):
            record({"utc_ns": time.time_ns(), "direction": "tx", "line": line,
                "phase": "startup_sync", "attempt": attempt})
            transport.write(line)
        attempt_deadline = time.monotonic() + remaining / (attempts - attempt + 1)
        while time.monotonic() < attempt_deadline:
            line = transport.readline(min(0.05, max(0.001, attempt_deadline - time.monotonic())))
            if line is None:
                continue
            log_line(line, phase="startup_sync", attempt=attempt)
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(response, dict) and response.get("event") == "status":
                return response, time.perf_counter_ns() - start
        record({"utc_ns": time.time_ns(), "direction": "host", "event": "startup_status_timeout", "attempt": attempt})
    raise RuntimeError("serial startup synchronization failed after bounded STATUS probes; inspect transcript.jsonl")


def run(args):
    if (args.limit is not None and args.limit <= 0) or args.repetitions <= 0 or args.timeout <= 0:
        raise PackageError("limit, repetitions, and timeout must be positive")
    if args.port and args.model_only:
        raise PackageError("--model-only selects native policy only; board policy is compiled and read from STATUS")
    if args.native and not args.native_store:
        raise PackageError("--native requires --native-store pointing to a fresh directory")
    if args.native and Path(args.native_store).exists():
        raise PackageError("native store must be a new path; existing flash state is never erased automatically")
    experiment = Path(args.experiment)
    contract = json.loads((experiment / "feature_contract.json").read_text())
    schema = contract_hash(contract)
    public = load_public(experiment / "public.pem")
    envelope_a, envelope_b = ((experiment / name).read_bytes() for name in ("release-A.sids", "release-B.sids"))
    a = verify(envelope_a, public, schema, len(contract["feature_names"]))
    b = verify(envelope_b, public, schema, len(contract["feature_names"]))
    provenance = json.loads((experiment / "provenance.json").read_text())
    all_records = [json.loads(line) for line in (experiment / "golden.jsonl").read_text().splitlines() if line]
    records = all_records[:args.limit]
    if not records or b.version <= a.version:
        raise PackageError("experiment needs nonempty golden records and a strictly newer release B")
    if any(row.get("data_origin") != provenance.get("data_origin") for row in records):
        raise PackageError("golden record origin differs from experiment provenance")
    for name in ["release-A.sids", "release-B.sids"]:
        if provenance.get("package_sha256", {}).get(name) != sha256_file(experiment / name):
            raise PackageError("signed package differs from experiment provenance hash")
    for row in records:
        for field, model, prep in [("expected_A", a, None), ("expected_B", b, None), ("expected_B_model_only", b, a)]:
            probability, label = infer(model, row["raw"], prep)
            if row[field]["label"] != label or not math.isfinite(row[field]["probability"]) or abs(row[field]["probability"] - probability) > 1e-7:
                raise PackageError("golden reference differs from verified signed model; regenerate experiment artifacts")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    transcript = (output / "transcript.jsonl").open("x")
    observations = (output / "observations.jsonl").open("x")
    events = (output / "events.jsonl").open("x")
    origin = "actual_mcu" if args.port else "native_simulation"
    manifest = {"measurement_origin": origin, "data_origin": provenance["data_origin"], "hardware_measured": bool(args.port),
        "host_runner_revision": "0.1.1-usb-sync", "host_runner_sha256": sha256_file(__file__),
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "parameters": vars(args),
        "checkpoint": args.checkpoint, "fault_kind": "software_restart" if args.checkpoint != "none" else "none",
        "physical_power_loss_tested": False, "policy": None, "schema_sha256": schema.hex(),
        "update_trials": 1, "inference_repetitions": args.repetitions,
        "golden_total_records": len(all_records), "selected_records": len(records), "truncated_correctness_smoke": len(records) < len(all_records),
        "board_id": args.board_id, "numerical_tolerance": {"absolute": 2e-6, "relative": 0.0}, "threshold_neighborhood": 2e-5,
        "artifacts_sha256": {name: sha256_file(experiment / name) for name in ["release-A.sids", "release-B.sids", "public.pem", "feature_contract.json", "golden.jsonl"]}}
    summary = {"status": "failed", "measurement_origin": origin, "data_origin": provenance["data_origin"],
        "inferred_records": 0, "label_mismatches": 0, "max_probability_abs_error": 0.0, "policy": None}
    if args.native:
        manifest["native_executable_sha256"] = sha256_file(args.native)
    if args.firmware_bin:
        manifest["firmware_application_sha256"] = sha256_file(args.firmware_bin)
    write_json(output / "manifest.json", manifest)
    transport = None
    def append(stream, item):
        stream.write(json.dumps(item, allow_nan=False) + "\n")
        stream.flush()
    def receive(expected):
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            line = transport.readline(min(0.5, max(0.01, deadline - time.monotonic())))
            if line is None:
                continue
            append(transcript, {"utc_ns": time.time_ns(), "direction": "rx", "line": line})
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(response, dict) and response.get("event") in expected:
                return response
        raise RuntimeError(f"timeout waiting for {sorted(expected)}; inspect transcript.jsonl")
    def command(line, expected, action=None):
        append(transcript, {"utc_ns": time.time_ns(), "direction": "tx", "line": line})
        start = time.perf_counter_ns()
        transport.write(line)
        response = receive(set(expected))
        elapsed = time.perf_counter_ns() - start
        if action:
            append(events, {"action": action, "command_kind": line.split(" ", 1)[0], "wire_bytes": len((line + "\n").encode("ascii")), "response": response, "host_roundtrip_ns": elapsed})
        return response, elapsed
    try:
        transport = SerialTransport(args.port, on_read=lambda chunk: append(transcript, {
            "utc_ns": time.time_ns(), "direction": "rx_bytes", "bytes_hex": chunk.hex()})) if args.port else NativeTransport(args.native, args.native_store, args.model_only)
        if args.native:
            receive({"boot"})
            status, _ = command("STATUS", {"status"}, "initial_status")
        else:
            status, elapsed = synchronize_serial(transport, lambda item: append(transcript, item), args.timeout)
            append(events, {"action": "initial_status", "command_kind": "STATUS", "wire_bytes": 7,
                "response": status, "host_roundtrip_ns": elapsed, "startup_status_probe": True})
        if not status.get("ready") or status.get("version") != a.version or status.get("schema") != schema.hex():
            raise RuntimeError("device must start with release A and matching trusted schema; flash appropriate factory image / fresh storage explicitly")
        if status.get("bundle_sha256") != hashlib.sha256(envelope_a[16:-256]).hexdigest():
            raise RuntimeError("device release A payload digest differs from expected signed factory")
        if status.get("data_origin") != provenance["data_origin"]:
            raise RuntimeError("device data origin differs from experiment provenance")
        expected_chip = "esp32s3" if args.port else "native_host_NOT_MCU"
        if status.get("chip") != expected_chip or status.get("release") != a.release:
            raise RuntimeError("reported chip/release differs from requested transport and factory package")
        policy = status.get("policy")
        if policy not in {"bundle", "model_only_factory_preprocess"}:
            raise RuntimeError(f"unsupported reported policy {policy!r}")
        manifest["policy"] = summary["policy"] = policy
        manifest["initial_status"] = status
        write_json(output / "manifest.json", manifest)
        def measure(phase, version):
            key = "expected_A" if version == a.version else ("expected_B_model_only" if policy == "model_only_factory_preprocess" else "expected_B")
            for repeat in range(args.repetitions):
                for row in records:
                    line = "INFER " + ",".join(format(float(v), ".9g") for v in row["raw"])
                    response, elapsed = command(line, {"inference", "error"})
                    if response.get("event") != "inference" or response.get("version") != version:
                        raise RuntimeError(f"inference failed or unexpected version: {response}")
                    expected_digest = hashlib.sha256((envelope_a if version == a.version else envelope_b)[16:-256]).hexdigest()
                    if response.get("bundle_sha256") != expected_digest or response.get("data_origin") != provenance["data_origin"] or response.get("policy") != policy:
                        raise RuntimeError("inference identity/provenance differs from experiment")
                    expected = row[key]
                    if not isinstance(response.get("probability"), (float, int)) or not math.isfinite(response["probability"]) or not 0 <= response["probability"] <= 1:
                        raise RuntimeError("invalid/nonfinite probability from device")
                    error = abs(response["probability"] - expected["probability"])
                    matched = response["label"] == expected["label"]
                    append(observations, {"phase": phase, "record_id": row["record_id"], "repetition": repeat, "expected": expected,
                        "expected_A": row["expected_A"], "expected_B": row["expected_B"], "expected_B_model_only": row["expected_B_model_only"], "true_label": row.get("label"),
                        "tolerance_pass": error <= 2e-6, "near_threshold": abs(expected["probability"] - (a.threshold if key in {"expected_A", "expected_B_model_only"} else b.threshold)) <= 2e-5,
                        "response": response, "host_roundtrip_ns": elapsed, "probability_abs_error": error, "label_match": matched})
                    summary["inferred_records"] += 1
                    summary["label_mismatches"] += int(not matched)
                    summary["max_probability_abs_error"] = max(summary["max_probability_abs_error"], error)
        measure("before", a.version)
        damaged = bytearray(envelope_b); damaged[-1] ^= 1
        rejected, _ = command("UPDATE " + damaged.hex(), {"update", "error"}, "tampered_signature")
        if rejected.get("accepted") is not False:
            raise RuntimeError("tampered candidate was not explicitly rejected")
        if args.checkpoint != "none":
            armed, _ = command("ARM_FAIL " + args.checkpoint, {"armed", "error"}, "arm_failure")
            if armed.get("event") != "armed":
                raise RuntimeError(f"cannot arm checkpoint: {armed}")
        result, _ = command("UPDATE " + envelope_b.hex(), {"update", "fault_checkpoint", "error"}, "candidate_B")
        if args.checkpoint != "none":
            if result.get("event") != "fault_checkpoint" or result.get("checkpoint") != args.checkpoint:
                raise RuntimeError(f"expected restart checkpoint was not reached: {result}")
            rebooted = receive({"boot"})
            append(events, {"action": "boot_after_software_restart", "response": rebooted})
        elif result.get("accepted") is not True:
            raise RuntimeError(f"valid update rejected: {result}")
        after, _ = command("STATUS", {"status"}, "after_status")
        expected_version = b.version if args.checkpoint in {"none", "after_commit"} else a.version
        if not after.get("ready") or after.get("version") != expected_version:
            raise RuntimeError(f"unexpected post-update state: {after}")
        expected_envelope = envelope_b if expected_version == b.version else envelope_a
        if after.get("bundle_sha256") != hashlib.sha256(expected_envelope[16:-256]).hexdigest() or after.get("policy") != policy or after.get("data_origin") != provenance["data_origin"]:
            raise RuntimeError("post-update identity/provenance differs from expected release")
        measure("after", expected_version)
        replay_package = envelope_b if expected_version == b.version else envelope_a
        replay, _ = command("UPDATE " + replay_package.hex(), {"update", "error"}, "replay_current_version")
        if replay.get("accepted") is not False:
            raise RuntimeError("current-version replay was not explicitly rejected")
        if summary["label_mismatches"] or summary["max_probability_abs_error"] > 2e-6:
            raise RuntimeError("device inference disagrees with float32 golden reference (tolerance 2e-6)")
        summary["status"] = "complete"
    except Exception as exc:
        summary["error"] = str(exc)
        raise
    finally:
        write_json(output / "summary.json", summary)
        if transport:
            if args.port:
                fragment = transport.take_pending_fragment()
                if fragment:
                    append(transcript, {"utc_ns": time.time_ns(), "direction": "rx", "line": fragment.decode("utf-8", errors="replace"),
                        "bytes_hex": fragment.hex(), "complete_line": False, "phase": "session_end_fragment"})
            transport.close()
        transcript.close(); observations.close(); events.close()
    print(json.dumps({"run": str(output), **summary}))
