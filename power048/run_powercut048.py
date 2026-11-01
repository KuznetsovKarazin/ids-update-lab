#!/usr/bin/env python3
"""Guarded physical power-cut campaign, revision048 continuation of revision039.

Original software: Oleksandr Kuznetsov. MIT license.
All raw serial and mutation intents are append-only. No UPDATE is retried.
Plan/preflight/run are separate; old study outputs are never modified.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import random
import shutil
import sys
import time

sys.dont_write_bytecode = True
import continuation048 as continuation

PHASES = ("model_erase", "model_body", "slot_commit", "selector_body", "selector_commit",
          "rotation_erase", "rotation_body", "rotation_commit")
PROTOCOL = "ids-power039-v1"
REPO = Path(__file__).resolve().parents[2]
TOLERANCE = 2e-6


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save_new(path, data):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("x", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")


def append(path, data):
    with Path(path).open("a", encoding="utf-8") as f:
        f.write(json.dumps({"utc_ns": time.time_ns(), **data}, allow_nan=False) + "\n")
        f.flush()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def dependencies(root):
    return (module("power039_codec", root / "research030/hardware_codec/codec030.py"),
            module("power039_model", root / "research030/training/model030.py"))


def make_trials(repeats=25, seed=23102026):
    if not 1 <= repeats <= 100:
        raise ValueError("repeats_per_phase must be 1..100")
    rng = random.Random(seed)
    phases = [p for p in PHASES for _ in range(repeats)]
    rng.shuffle(phases)
    return [dict(trial=i + 1, phase=phase, phase_width_fraction=rng.uniform(.05, .75))
            for i, phase in enumerate(phases)]


def validate_wiring(cfg, config_path=None, require_phase_timing=False):
    if cfg.get("protocol") != "ids-power039-wiring-v1":
        raise ValueError("Wrong wiring protocol")
    required = ("enabled", "active_high_enable", "external_switch_accepts_3v3_enable",
                "external_enable_pulldown", "common_ground", "no_usb_vbus_bypass",
                "no_other_power_path", "esp_not_powered_by_gpio", "phase_signal_is_3v3",
                "adc_is_target_3v3_rail_via_divider", "adc_input_never_exceeds_3v3",
                "adc_calibration_verified")
    missing = [key for key in required if cfg.get(key) is not True]
    if missing:
        raise ValueError("Wiring is not ready; verify: " + ", ".join(missing))
    pins = [cfg.get(k) for k in ("enable_pin", "phase_pin", "adc_pin")]
    if len(set(pins)) != 3 or not all(type(p) is int and 0 <= p <= 28 for p in pins) or pins[2] not in (26, 27, 28):
        raise ValueError("Invalid/distinct Pico GPIO assignments")
    if type(cfg.get("esp_phase_gpio")) is not int:
        raise ValueError("Specify verified ESP32 phase GPIO")
    if cfg.get("external_switch_model", "FILL").startswith("FILL") or len(cfg.get("verification_notes", "")) < 30 or "FILL_IN" in cfg.get("verification_notes", ""):
        raise ValueError("Record actual load switch and wiring verification notes")
    slope = cfg.get("adc_volts_per_count")
    if type(slope) not in (float, int) or not math.isfinite(slope) or not 0 < slope < .01:
        raise ValueError("Measured ADC volts-per-count calibration required")
    zero = cfg.get("adc_zero_volts")
    if type(zero) not in (float, int) or not math.isfinite(zero) or abs(zero) > .5:
        raise ValueError("Finite calibrated ADC zero offset required")
    if not 0 <= cfg.get("rail_off_max_volts", -1) <= .5 or not 2.8 <= cfg.get("rail_on_min_volts", -1) <= 3.5:
        raise ValueError("Target 3.3 V rail thresholds invalid")
    if not 1000 <= cfg.get("off_ms", 0) <= 10000:
        raise ValueError("off_ms must be 1000..10000")
    if require_phase_timing:
        limit = cfg.get("switch_to_rail_collapse_upper_us")
        if cfg.get("phase_timing_verified") is not True or type(limit) not in (int, float) or not math.isfinite(limit) or limit <= 0:
            raise ValueError("Measure/document switch-to-rail-collapse bound before the phase-confirmed series")
        path = Path(cfg.get("phase_timing_evidence_file") or "")
        if config_path and not path.is_absolute():
            path = Path(config_path).parent / path
        if not path.is_file() or digest(path) != cfg.get("phase_timing_evidence_sha256"):
            raise ValueError("Missing or mismatched external phase/power timing evidence")


def rail_evidence(event, cfg):
    points = event.get("rail_samples", [])
    if not points:
        return dict(rail_off_confirmed=False, reason="no_rail_samples")
    if any(not isinstance(p, list) or len(p) != 2 or type(p[0]) is not int or type(p[1]) is not int or p[0] < 0 or not 0 <= p[1] <= 65535 for p in points):
        raise ValueError("Malformed raw ADC trace")
    if any(points[i][0] <= points[i - 1][0] for i in range(1, len(points))):
        raise ValueError("ADC sample times must increase")
    volts = [cfg["adc_zero_volts"] + p[1] * cfg["adc_volts_per_count"] for p in points]
    tail = [v for p, v in zip(points, volts) if p[0] >= 100000]
    confirmed = bool(tail) and max(tail) <= cfg["rail_off_max_volts"] and points[-1][0] >= 900000
    return dict(rail_off_confirmed=confirmed, minimum_volts=min(volts),
                tail_max_volts=max(tail) if tail else None, samples=len(points),
                trace_last_us=points[-1][0], independent_analog_calibration=False)


def classify_recovery(status, old, candidate, numeric_ok=None):
    if status is None:
        return "no_response"
    if status.get("ready") is not True:
        return "fail_closed"
    pair = (status.get("version"), status.get("bundle_sha256"), status.get("release"))
    oldpair = (old.get("version"), old.get("bundle_sha256"), old.get("release"))
    newpair = (candidate.get("version"), candidate.get("bundle_sha256"), candidate.get("release"))
    if pair not in (oldpair, newpair) or numeric_ok is False:
        return "unexpected_or_mixed"
    return "old_valid" if pair == oldpair else "new_valid"


def trial_delay(trial, widths, cfg, require_bounds):
    values = widths.get(trial["phase"], [])
    if not values or any(type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for v in values):
        raise ValueError("Missing positive uncut strobe widths for " + trial["phase"])
    width = min(values)
    bound = cfg.get("switch_to_rail_collapse_upper_us")
    verified = cfg.get("phase_timing_verified") is True and type(bound) in (int, float) and math.isfinite(bound) and bound > 0
    # 6 us reserved for nominal PIO edge overhead and input synchronization;
    # external verification must cover actual target supply capacitance.
    room = width - (bound if verified else 0) - 6
    if room < 0 and require_bounds:
        raise ValueError("Phase " + trial["phase"] + " is shorter than verified supply-switch latency; improve the apparatus")
    delay = max(0, int(max(0, room) * trial["phase_width_fraction"]))
    return delay, width


def plan(args):
    root = args.root.resolve()
    model_path = args.model
    model_a_path = args.model_a
    if model_path is None:
        if args.prior_run is None:
            raise ValueError("Supply --model or --prior-run with training/models/B_mlp_float.json")
        model_path = args.prior_run / "training/models/B_mlp_float.json"
        model_a_path = args.prior_run / "training/models/A_mlp_float.json"
    if model_a_path is None:
        raise ValueError("Supply --model-a as well, so physical cuts exercise changes in real model parameters")
    model = {"A": read(model_a_path), "B": read(model_path)}
    validation_only = getattr(args, "allow_test_models", False)
    source_paths = {"A": model_a_path, "B": model_path}
    public_hashes = {}
    published = {row["path"]: row["sha256"] for row in read(root / "MANIFEST.sha256.json")["files"]}
    for role in ("A", "B"):
        relative = "paper037/evidence_inputs/training/models/" + role + "_" + model[role]["kind"] + ".json"
        reference = root / relative
        public_hashes[role] = published.get(relative)
        if not validation_only and (not reference.is_file() or digest(reference) != public_hashes[role] or digest(source_paths[role]) != public_hashes[role]):
            raise ValueError("Model differs from published frozen " + role + " reference; do not silently change the physical-cut baseline")
    codec, ref = dependencies(root)
    if model["A"]["kind"] != model["B"]["kind"]:
        raise ValueError("A/B models must use the same runtime ABI")
    blobs = [codec.sign_envelope(model[k], 1, "039-pc-plan") for k in ("A", "B")]
    if blobs[0] == blobs[1]:
        raise ValueError("A/B model parameters must differ for the physical-cut comparison")
    raw = [[0.] * 8, [0., 0., 0., 0., 1., 63., 0., 0.]]
    for j in range(8):
        row = [0.] * 8
        row[j] = 1.
        raw.append(row)
    raw += [[1., 40., 50., 2., 3., 120., 4., 180.], [1000.] * 8]
    args.output.mkdir(parents=True, exist_ok=False)
    save_new(args.output / "model.json", model)
    expected = {}
    for role in ("A", "B"):
        prob, y = ref.predict(model[role], raw)
        expected[role] = [dict(probability=float(a), label=int(b)) for a, b in zip(prob, y)]
    save_new(args.output / "controls.json", {"raw": raw, "purpose": "numerical recovery controls, not IDS-quality data",
             "expected": expected, "role_rule": "candidate alternates from selected A/B; release p39A-<version> or p39B-<version>"})
    result = dict(stage="039", experiment="physical_powercut", status="prepared_not_run",
                  measurement_origin="not_measured", physical_power_loss_tested=False,
                  validation_only_test_models=validation_only,
                  published_model_sha256=public_hashes,
                  published_model_manifest_sha256=digest(root / "MANIFEST.sha256.json"),
                  model_kind=model["B"]["kind"], model_source_sha256={"A": digest(model_a_path), "B": digest(model_path)},
                  model_sha256=digest(args.output / "model.json"), controls_sha256=digest(args.output / "controls.json"),
                  trials=make_trials(args.repeats_per_phase, args.seed), seed=args.seed,
                  rule="PIO rising-phase trigger; delay=floor(fraction*(minimum uncut width - verified collapse upper bound - 6us)); abort if phase already low",
                  phases=list(PHASES), repeats_per_phase=args.repeats_per_phase,
                  max_preparatory_updates_per_trial=34,
                  timing_scope="esp_partition API strobe; exact internal flash instruction phase unobserved",
                  required_extra_hardware=["external active-high 3.3-V-logic load switch with default-off pulldown",
                    "verified target power isolation including USB", "target 3.3-V rail ADC divider and calibration",
                    "independent phase/supply fall-time validation for phase-confirmed claim"],
                  stop_on=["unexpected_or_mixed", "fail_closed", "no_response", "missing_rail_off_evidence"],
                  interrupted_trial_policy="never replay UPDATE; preserve intent, mark interrupted, continue only from verified current state")
    save_new(args.output / "plan.json", result)
    return result


class Link:
    def __init__(self, port, transcript, name):
        import serial
        self.name, self.transcript = name, transcript
        self.s = serial.Serial(port=None, baudrate=115200, timeout=.01, write_timeout=3)
        # Pico CDC requires DTR; preserve inactive reset lines for the ESP32.
        self.s.dtr = name == "pico"
        self.s.rts = False
        self.s.port = port
        self.s.open()
        self.buf = bytearray()

    def log(self, **fields):
        append(self.transcript, {"link": self.name, "monotonic_ns": time.monotonic_ns(), **fields})

    def send(self, line):
        self.log(direction="tx", line=line)
        self.s.write((line + "\n").encode("ascii"))
        self.s.flush()

    def receive(self, timeout=.1):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if b"\n" in self.buf:
                frame, _, tail = self.buf.partition(b"\n")
                self.buf = bytearray(tail)
                line = frame.decode("utf-8", errors="replace").strip()
                self.log(direction="rx", line=line)
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        return obj
                except ValueError:
                    pass
            else:
                data = self.s.read(max(1, min(self.s.in_waiting, 8192)))
                if data:
                    self.buf.extend(data)
                    self.log(direction="rx_bytes", bytes_hex=data.hex())
        return None

    def request(self, line, expected, timeout=5):
        self.send(line)
        return self.expect(expected, timeout)

    def expect(self, expected, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            obj = self.receive(min(.1, deadline - time.monotonic()))
            if obj is None:
                continue
            if obj.get("event") in expected:
                return obj
            if obj.get("event") in ("error", "controller_error"):
                raise RuntimeError(str(obj))
        raise TimeoutError("No " + "/".join(sorted(expected)) + " from " + self.name)

    def close(self):
        if self.buf:
            self.log(direction="rx_fragment", bytes_hex=self.buf.hex())
        self.s.close()


def observe_adc(ctrl, cfg, transcript, label, timeout=.25):
    """Read-only, log-only observation. Never changes recovery classification."""
    observation = dict(event="rail_observation", label=label, request_monotonic_ns=time.monotonic_ns())
    try:
        response = ctrl.request("ADC", {"adc"}, timeout)
        observation["response"] = response
        raw = response.get("raw")
        if type(raw) is not int or not 0 <= raw <= 65535:
            raise ValueError("Malformed Pico ADC reading")
        volts = cfg["adc_zero_volts"] + cfg["adc_volts_per_count"] * raw
        observation.update(volts=volts, rail_on=cfg["rail_on_min_volts"] <= volts <= 3.6,
                           received_monotonic_ns=time.monotonic_ns())
    except Exception as exc:
        observation["error"] = repr(exc)
        observation["rail_on"] = None
    observation["completed_monotonic_ns"] = time.monotonic_ns()
    def safe(value):
        if isinstance(value, float) and not math.isfinite(value):
            return {"nonfinite_float": repr(value)}
        if isinstance(value, dict):
            return {key: safe(item) for key, item in value.items()}
        if isinstance(value, list):
            return [safe(item) for item in value]
        return value
    observation = safe(observation)
    observation["response_wait_timeout_seconds"] = timeout
    try:
        append(transcript, dict(link="host", **observation))
    except Exception as exc:
        observation["log_error"] = repr(exc)
    return observation


def open_mcu(args, transcript, timeout=20, ctrl=None, cfg=None):
    # Same recovery window and retry policy as revision039. No UPDATE is retried.
    deadline = time.monotonic() + timeout
    attempt = 0
    last_error = None
    while time.monotonic() < deadline:
        attempt += 1
        link = None
        stage = "open"
        try:
            link = Link(args.mcu_port, transcript, "mcu")
            stage = "status"
            time.sleep(.3)
            link.send("")
            status = link.request("STATUS", {"status"}, 2)
            append(transcript, dict(link="host", event="mcu_recovery_ready", port=args.mcu_port,
                                   attempt=attempt, recovery_window_seconds=timeout))
        except Exception as exc:
            last_error = repr(exc)
            append(transcript, dict(link="host", event="mcu_recovery_attempt_failed", port=args.mcu_port,
                                   attempt=attempt, stage=stage, error_type=type(exc).__name__,
                                   error=last_error, monotonic_ns=time.monotonic_ns()))
            if link:
                try:
                    link.close()
                except Exception as close_exc:
                    append(transcript, dict(link="host", event="mcu_close_failed", error=repr(close_exc)))
            time.sleep(.3)
            continue
        if ctrl is not None:
            observe_adc(ctrl, cfg, transcript, "after_status_recovery_decision")
        return link, status
    if ctrl is not None:
        observe_adc(ctrl, cfg, transcript, "failed_recovery_endpoint")
    append(transcript, dict(link="host", event="mcu_recovery_deadline", port=args.mcu_port,
                           attempts=attempt, recovery_window_seconds=timeout, last_error=last_error,
                           snapshot_after_deadline=True, ports=continuation.port_snapshot()))
    raise TimeoutError("MCU did not return STATUS after power restoration; see recovery-attempt diagnostics")


def validate_status(s, model, codec):
    expected = {"chip": "esp32s3", "policy": "bundle", "storage_layout": 2,
                "runtime_abi": codec.ABI[model["B"]["kind"]], "schema": codec.SCHEMA.hex(), "feature_count": 8}
    if s.get("ready") is not True or any(s.get(k) != v for k, v in expected.items()):
        raise ValueError("Expected ready revision039 phase-enabled bundle firmware: " + str(s))


def phase_arm(mcu, phase, cfg):
    r = mcu.request("PHASE_ARM " + phase, {"phase_control"})
    if r.get("ok") is not True or r.get("enabled") is not True or r.get("phase") != phase or r.get("gpio") != cfg["esp_phase_gpio"]:
        raise RuntimeError("Phase hook unavailable or GPIO differs: " + str(r))


def confirm_controller(ctrl, config_path, cfg):
    r = ctrl.request("ID", {"controller_id"})
    if r.get("protocol") != PROTOCOL or r.get("config_sha256") != digest(config_path) or r.get("enabled") is not True:
        raise RuntimeError("Controller protocol/config mismatch; copy the exact reviewed config to Pico")
    for key in ("enable_pin", "phase_pin", "adc_pin"):
        if r.get(key) != cfg[key]:
            raise RuntimeError("Controller pin mismatch")
    ctrl.request("ARM PHYSICAL", {"armed"})
    return r


def selected_role(status):
    release = status.get("release", "")
    if release.startswith("p39A-"):
        return "A"
    if release.startswith("p39B-"):
        return "B"
    raise ValueError("Selected release is not bound to this powercut model pair")


def next_role(status):
    return "A" if status.get("release", "").startswith("p39B-") else "B"


def validate_replay_rejection(response):
    # Bundle UPDATE and whole-image FW_BEGIN use different reason vocabularies.
    if response.get("event") != "update" or response.get("accepted") is not False or response.get("reason") != "replay_or_downgrade":
        raise RuntimeError("Current-version bundle replay not explicitly rejected: " + str(response))


def candidate(model, codec, version, role="B"):
    if not 1 <= version < 0xffffffff:
        raise ValueError("Version range exhausted")
    if role not in ("A", "B"):
        raise ValueError("Unknown model role")
    blob = codec.sign_envelope(model[role], version, "p39" + role + "-" + str(version))
    return blob, codec.envelope_metadata(blob)


def install(mcu, model, codec, status, output, label, version=None):
    version = status["version"] + 1 if version is None else version
    blob, identity = candidate(model, codec, version, next_role(status))
    append(output / "mutations.jsonl", dict(kind="intent", label=label, previous=status, candidate=identity))
    reply = mcu.request("UPDATE " + blob.hex(), {"update"}, 10)
    append(output / "mutations.jsonl", dict(kind="receipt", label=label, response=reply))
    if reply.get("accepted") is not True:
        raise RuntimeError("Preparation update rejected: " + str(reply))
    now = mcu.request("STATUS", {"status"})
    if (now.get("version"), now.get("bundle_sha256")) != (identity["version"], identity["bundle_sha256"]):
        raise RuntimeError("Preparation identity mismatch")
    return now, identity


def control_inference(mcu, status, controls):
    rows = []
    role = selected_role(status)
    for raw, want in zip(controls["raw"], controls["expected"][role]):
        got = mcu.request("INFER " + ",".join(format(float(x), ".9g") for x in raw), {"inference"})
        p = got.get("probability")
        ok = (got.get("version") == status["version"] and got.get("bundle_sha256") == status["bundle_sha256"]
              and got.get("label") == want["label"] and type(p) in (int, float)
              and math.isfinite(p) and abs(p - want["probability"]) <= TOLERANCE)
        rows.append(dict(raw=raw, expected=want, response=got, ok=ok))
    return all(r["ok"] for r in rows), rows


def load_plan(args):
    directory = args.plan.parent if args.plan.is_file() else args.plan
    path = directory / "plan.json"
    p = read(path)
    if digest(directory / "model.json") != p["model_sha256"] or digest(directory / "controls.json") != p["controls_sha256"]:
        raise ValueError("Powercut plan artifact hash mismatch")
    return p, path, read(directory / "model.json"), read(directory / "controls.json")


def flash(args):
    p, plan_path, models, controls = load_plan(args)
    if p.get("validation_only_test_models"):
        raise ValueError("Software-only test-model plan cannot provision the physical board")
    codec, _ = dependencies(args.root)
    family = models["B"]["kind"]
    base = args.prebuilt_root / (family + "_bundle")
    meta = read(base / "metadata.json")
    if meta.get("revision") != "039" or meta.get("family") != family or meta.get("policy") != "bundle" or type(meta.get("phase_gpio")) is not int:
        raise ValueError("Use revision039 phase-enabled bundle prebuilt for the planned family")
    required = {"ids_update_lab.bin", "bootloader/bootloader.bin", "partition_table/partition-table.bin",
                "ota_data_initial.bin", "flash_args", "sdkconfig"}
    pins = meta.get("files_sha256", {})
    if not required.issubset(pins):
        raise ValueError("Incomplete phase-build file manifest")
    for name, expected in pins.items():
        path = (base / name).resolve()
        if not path.is_relative_to(base.resolve()) or digest(path) != expected:
            raise ValueError("Phase build file hash mismatch: " + name)
    settings = (base / "sdkconfig").read_text()
    if "CONFIG_IDS_PHASE_GPIO_ENABLED=y" not in settings or ("CONFIG_IDS_PHASE_GPIO=" + str(meta["phase_gpio"]) + "\n") not in settings:
        raise ValueError("Phase build configuration/metadata mismatch")
    image_meta = codec.verify_image((base / "ids_update_lab.bin").read_bytes())
    if image_meta["image_sha256"] != meta.get("image_sha256"):
        raise ValueError("Phase image hash mismatch")
    args.output.mkdir(parents=True, exist_ok=False)
    factory = args.output / "factory"
    factory.mkdir()
    for name in ("bootloader/bootloader.bin", "partition_table/partition-table.bin", "ota_data_initial.bin", "flash_args", "sdkconfig"):
        (factory / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(base / name, factory / name)
    blob, identity = candidate(models, codec, 1, "A")
    patched = codec.patch_image((base / "ids_update_lab.bin").read_bytes(), blob)
    patched_meta = codec.verify_image(patched)
    (factory / "ids_update_lab.bin").write_bytes(patched)
    save_new(factory / "source_build_metadata.json", meta)
    report = dict(stage="039", experiment="powercut_phase_flash", status="prepared_not_flashed",
                  board_id=args.board_id, plan_sha256=digest(plan_path),
                  source_build_metadata_sha256=digest(base / "metadata.json"),
                  template_image_sha256=image_meta["image_sha256"], patched_image=patched_meta,
                  factory_model_identity=identity, phase_gpio=meta["phase_gpio"],
                  model_state_erase={"address": "0x3b0000", "length": "0x22000"},
                  hardware_access_attempted=False, physical_power_loss_tested=False)
    try:
        if args.prepare_only:
            return report
        hardware = module("power039_hardware030", args.root / "research030/tools/hardware030.py")
        artifact = {"root": args.output, "families": {family: {"policies": {"bundle": {
            "factory_dir": "factory", "images": {"1": {"sha256": patched_meta["image_sha256"]}}}}}}}
        report["hardware_access_attempted"] = True
        hardware.provision(args, args.output, artifact, family, "bundle")
        args.mcu_port = args.port
        mcu, status = open_mcu(args, args.output / "transcript.jsonl")
        try:
            validate_status(status, models, codec)
            if (status.get("version"), status.get("release"), status.get("bundle_sha256")) != (1, identity["release"], identity["bundle_sha256"]):
                raise RuntimeError("Flashed factory model identity mismatch")
            if not status.get("build", "").startswith(patched_meta["expected_build"]):
                raise RuntimeError("Flashed SDK/app/ELF identity mismatch")
            hook = mcu.request("PHASE_STATUS", {"phase_status"})
            if hook.get("enabled") is not True or hook.get("gpio") != meta["phase_gpio"] or hook.get("phase") != "none":
                raise RuntimeError("Flashed phase hook disabled/wrong pin/not disarmed")
            ok, observed = control_inference(mcu, status, controls)
            report.update(status="complete", factory_status=status, phase_status=hook, controls=observed,
                          board_identity="ROM MAC matched board_id before flash write")
            if not ok:
                raise RuntimeError("Flashed model control inference mismatch")
        finally:
            mcu.close()
        return report
    except Exception as exc:
        report.update(status="failed", error=str(exc))
        raise
    finally:
        save_new(args.output / "summary.json", report)


def preflight(args):
    cfg = read(args.config)
    validate_wiring(cfg, args.config)
    if args.mcu_port.lower() == args.controller_port.lower():
        raise ValueError("MCU and Pico serial ports must differ")
    p, plan_path, model, controls = load_plan(args)
    if p.get("validation_only_test_models"):
        raise ValueError("Software-only test-model plan cannot start a physical preflight")
    codec, _ = dependencies(args.root)
    args.output.mkdir(parents=True, exist_ok=False)
    transcript = args.output / "transcript.jsonl"
    ctrl = mcu = None
    report = dict(status="failed", stage="039", experiment="powercut_preflight",
                  plan_sha256=digest(plan_path), config_sha256=digest(args.config),
                  board_id=args.board_id, board_id_source="user_declared; use root flash verification",
                  physical_power_loss_tested=False, phase_widths_us={})
    try:
        ctrl = Link(args.controller_port, transcript, "pico")
        report["controller"] = confirm_controller(ctrl, args.config, cfg)
        time.sleep(2)
        mcu, status = open_mcu(args, transcript)
        validate_status(status, model, codec)
        report["initial_status"] = status
        mcu.request("PHASE_DISARM", {"phase_control"})
        # Fill both model slots before all subsequent storage probes.
        for i in range(2):
            status, _ = install(mcu, model, codec, status, args.output, "occupied_slot_setup_" + str(i))
        ok, observed = control_inference(mcu, status, controls)
        report["controls"] = observed
        if not ok:
            raise RuntimeError("Recovery control model fails host/MCU agreement before power cuts")
        on = ctrl.request("ADC", {"adc"})
        report["on_voltage"] = cfg["adc_zero_volts"] + on["raw"] * cfg["adc_volts_per_count"]
        if report["on_voltage"] < cfg["rail_on_min_volts"]:
            raise RuntimeError("Target rail not at verified ON voltage")
        mcu.close()
        mcu = None
        probe = ctrl.request("PROBE " + str(cfg["off_ms"]), {"probe_result"}, cfg["off_ms"] / 1000 + 10)
        report["off_probe"] = probe
        report["off_evidence"] = rail_evidence(probe, cfg)
        if not report["off_evidence"]["rail_off_confirmed"]:
            raise RuntimeError("Rail did not remain below off threshold; inspect backpower/switch/ADC")
        report["physical_power_loss_tested"] = True
        mcu, restored = open_mcu(args, transcript)
        if classify_recovery(restored, status, status) != "old_valid":
            raise RuntimeError("OFF/ON probe changed the selected release")
        status = restored
        # Three independent uncut pulses per named phase, with ordinary
        # successful updates advancing the real journal to rotation naturally.
        for phase in PHASES:
            report["phase_widths_us"][phase] = []
            for rep in range(3):
                phase_arm(mcu, phase, cfg)
                token = phase + "-" + str(rep)
                ctrl.request("MEASURE " + token + " 30000", {"phase_armed"})
                width = None
                for k in range(p["max_preparatory_updates_per_trial"]):
                    status, _ = install(mcu, model, codec, status, args.output, token + "-" + str(k))
                    event = ctrl.receive(.02)
                    if event and event.get("event") in ("phase_width", "phase_timeout"):
                        width = event
                        break
                if width is None:
                    width = ctrl.expect({"phase_width", "phase_timeout"}, 31)
                if width.get("event") != "phase_width" or width.get("trial") != token or width.get("strobe_width_us", 0) < 1:
                    raise RuntimeError("Missing digital phase pulse: " + str(width))
                report["phase_widths_us"][phase].append(width["strobe_width_us"])
                mcu.request("PHASE_DISARM", {"phase_control"})
        report.update(status="complete", final_status=status, measurement_origin="actual_mcu",
                      phase_timing_verified=cfg.get("phase_timing_verified") is True,
                      note="Uncut digital pulse-width and rail-OFF preflight; not the 200-trial recovery series")
        return report
    except Exception as exc:
        report["error"] = str(exc)
        raise
    finally:
        if mcu:
            try:
                mcu.request("PHASE_DISARM", {"phase_control"})
            except Exception:
                pass
            mcu.close()
        if ctrl:
            try:
                ctrl.request("ON", {"power_on"})
            except Exception:
                pass
            ctrl.close()
        save_new(args.output / "summary.json", report)


def run(args):
    if not (args.resume and getattr(args, "late_recovery", None) and getattr(args, "control_run", None)):
        raise ValueError("Revision048 only admits --resume --late-recovery --control-run for incident113")
    if getattr(args, "prepare_only", False) and not getattr(args, "late_recovery", None):
        raise ValueError("run --prepare-only is only defined for the reviewed incident continuation")
    cfg = read(args.config)
    validate_wiring(cfg, args.config, require_phase_timing=not args.allow_unconfirmed_phase_timing)
    p, plan_path, model, controls = load_plan(args)
    if p.get("validation_only_test_models"):
        raise ValueError("Software-only test-model plan cannot start the physical campaign")
    pf = read(args.preflight / "summary.json")
    if pf.get("status") != "complete" or pf.get("plan_sha256") != digest(plan_path) or pf.get("config_sha256") != digest(args.config) or pf.get("board_id") != args.board_id:
        raise ValueError("Successful preflight must match plan, exact config, and board")
    for item in p["trials"]:
        trial_delay(item, pf["phase_widths_us"], cfg, not args.allow_unconfirmed_phase_timing)
    codec, _ = dependencies(args.root)
    if args.mcu_port.lower() == args.controller_port.lower():
        raise ValueError("MCU and Pico serial ports must differ")
    if args.resume:
        bind = read(args.output / "run_binding.json")
        expected = {"plan_sha256": digest(plan_path), "config_sha256": digest(args.config), "preflight_sha256": digest(args.preflight / "summary.json"), "board_id": args.board_id,
                    "allow_unconfirmed_phase_timing": args.allow_unconfirmed_phase_timing}
        if any(bind.get(k) != v for k, v in expected.items()):
            raise ValueError("Cannot resume a different plan/config/board/preflight")
    else:
        args.output.mkdir(parents=True, exist_ok=False)
        save_new(args.output / "run_binding.json", {"plan_sha256": digest(plan_path), "config_sha256": digest(args.config),
                 "preflight_sha256": digest(args.preflight / "summary.json"), "board_id": args.board_id,
                 "allow_unconfirmed_phase_timing": args.allow_unconfirmed_phase_timing})
    prior = []
    log = args.output / "trial_results.jsonl"
    if log.exists():
        prior = [json.loads(line) for line in log.read_text().splitlines()]
    late_review = None
    if getattr(args, "late_recovery", None):
        late_review = continuation.validate_evidence(args, prior, controls, plan_path)
    elif any(row.get("state") in ("unexpected_or_mixed", "fail_closed", "no_response") or row.get("update_rejected") for row in prior):
        raise ValueError("Previous unsafe/unavailable state requires investigation; automatic resume blocked")
    replay_log = args.output / "replay_checks.jsonl"
    if replay_log.exists():
        for line in replay_log.read_text().splitlines():
            validate_replay_rejection(json.loads(line)["response"])
    if getattr(args, "prepare_only", False):
        return dict(status="prepared_not_run", first_continued_trial=114, remaining_trials=87,
                    original_trial61_state="no_response", original_trial113_state="no_response", hardware_access_attempted=False,
                    original_results_changed=False, late_recovery_verified_offline=True)
    done = {row["trial"] for row in prior}
    transcript = args.output / "transcript.jsonl"
    summary = dict(stage="039", status="failed", experiment="physical_powercut", measurement_origin="not_measured",
                   board_id=args.board_id, planned_trials=len(p["trials"]), physical_power_loss_tested=False)
    ctrl = mcu = None
    awake = None
    phase_instrumentation_started = False
    controller_power_armed = False
    if late_review is not None:
        # Atomic marker before device access excludes concurrent/resubmitted attempts.
        save_new(args.output / continuation.ATTEMPT_NAME,
                 dict(schema="power048_attempt_v1", started_utc_ns=time.time_ns(),
                      original_state="no_response", first_continued_trial=114,
                      checkpoint_manifest_sha256=continuation.CHECKPOINT_MANIFEST_SHA256))
        source_directory = args.output / "continuation048_sources"
        source_directory.mkdir(exist_ok=False)
        source_hashes = {}
        for source_path in (Path(__file__), Path(continuation.__file__),
                            Path(continuation.__file__).with_name("incident113_hashes.json")):
            copied_path = source_directory / source_path.name
            shutil.copyfile(source_path, copied_path)
            source_hashes[source_path.name] = digest(source_path)
            if digest(copied_path) != source_hashes[source_path.name]:
                raise RuntimeError("Continuation source snapshot mismatch")
        save_new(source_directory / "SHA256.json", source_hashes)
    try:
        # This is an execution-state request, not a persistent Windows power-plan edit.
        awake = continuation.SleepGuard(args.output / "host_power048.jsonl")
        awake.__enter__()
        if late_review is not None:
            # Deliberately do not ARM or power-cycle before checking the late state.
            mcu, status = open_mcu(args, transcript)
            validate_status(status, model, codec)
            live = continuation.verify_live(mcu, status, late_review, controls)
            # Pico is only observed before admission; an unarmed/off board is not repaired here.
            ctrl = Link(args.controller_port, transcript, "pico")
            controller_id = ctrl.request("ID", {"controller_id"})
            if (controller_id.get("protocol") != PROTOCOL
                    or controller_id.get("config_sha256") != digest(args.config)
                    or controller_id.get("enabled") is not True or controller_id.get("armed") is not True
                    or any(controller_id.get(k) != cfg[k] for k in
                           ("enable_pin", "phase_pin", "adc_pin", "active_high_enable"))):
                raise RuntimeError("Pico must already be armed with the exact reviewed config; no ARM is sent")
            initial_adc = observe_adc(ctrl, cfg, transcript, "admission_before_any_mutation")
            if initial_adc.get("rail_on") is not True:
                raise RuntimeError("Admission requires a measured target rail between3.0 and3.6V")
            live["controller_id"] = controller_id
            live["initial_adc"] = initial_adc
            admission = {**late_review, "admitted_utc_ns": time.time_ns(), "live": live,
                         "runner048_sha256": digest(Path(__file__)),
                         "helper048_sha256": digest(Path(continuation.__file__))}
            save_new(args.output / continuation.ADMISSION_NAME, admission)
            summary["late_recovery_reviews"] = [
                {"trial": trial, "original_state": "no_response", "late_state": "old_valid",
                 "late_state_is_not_original_endpoint": True} for trial in (61, 113)]
            summary["continuation048_admission"] = {
                "live_checks_passed": 12, "admission_file": continuation.ADMISSION_NAME,
                "admission_sha256": digest(args.output / continuation.ADMISSION_NAME)}
            summary["protocol_epoch"] = late_review["protocol_epoch"]
            summary["control047_review"] = late_review["control047_review"]
        controller_power_armed = True
        time.sleep(2)
        status = mcu.request("STATUS", {"status"})
        if not continuation.same_identity(status, late_review["expected_identity"]):
            raise RuntimeError("Model identity changed after admission; no new flash update was issued")
        validate_status(status, model, codec)
        if status["build"] != pf["final_status"]["build"]:
            raise RuntimeError("Firmware differs from the preflight build")
        mcu.request("PHASE_DISARM", {"phase_control"})
        phase_instrumentation_started = True
        # Recover a host-interrupted trial BEFORE any new flash mutation.
        # Do not overwrite the only evidence of its selected state by setup.
        for trial in p["trials"]:
            if trial["trial"] in done:
                continue
            pending = args.output / ("trial_%03d_intent.json" % trial["trial"])
            if not pending.exists():
                continue
            attempts = []
            mutations = args.output / "mutations.jsonl"
            if mutations.exists():
                attempts = [json.loads(line) for line in mutations.read_text().splitlines()]
                attempts = [x for x in attempts if x.get("trial") == trial["trial"] and x.get("kind") == "intent"]
            last = attempts[-1] if attempts else {"previous": read(pending)["previous"], "candidate": read(pending)["previous"]}
            ok, controls_observed = control_inference(mcu, status, controls)
            state = classify_recovery(status, last["previous"], last["candidate"], ok)
            recovered = dict(trial=trial["trial"], phase=trial["phase"], state=state,
                             host_interrupted=True, mutation_replayed=False, recovered=status,
                             old=last["previous"], candidate=last["candidate"],
                             numeric_controls=controls_observed, rail_off_confirmed=False,
                             phase_confirmed=False, evidence_gap="controller cut result not bound during original host session")
            append(log, recovered)
            prior.append(recovered)
            done.add(trial["trial"])
            if state not in ("old_valid", "new_valid"):
                raise RuntimeError("Interrupted trial recovered unexpected state; no preparation update was issued")
        # A successful new preparation update establishes known A/B parameters.
        # Resumption never repeats an interrupted signed version.
        max_attempt = status["version"]
        if (args.output / "mutations.jsonl").exists():
            for line in (args.output / "mutations.jsonl").read_text().splitlines():
                row = json.loads(line)
                max_attempt = max(max_attempt, row.get("candidate", {}).get("version", 0))
        for i in range(2):
            max_attempt += 1
            status, _ = install(mcu, model, codec, status, args.output, "run_occupied_setup", max_attempt)
        summary["measurement_origin"] = "actual_mcu"
        for trial in p["trials"]:
            index = trial["trial"]
            if index in done:
                continue
            intent_path = args.output / ("trial_%03d_intent.json" % index)
            if intent_path.exists():
                # A lost host process does not justify replaying a mutation.
                result = dict(trial=index, phase=trial["phase"], state="host_interrupted_not_replayed",
                              phase_confirmed=False, rail_off_confirmed=False)
                append(log, result)
                prior.append(result)
                continue
            delay, width = trial_delay(trial, pf["phase_widths_us"], cfg, not args.allow_unconfirmed_phase_timing)
            # Delay selection is fixed by plan + preflight, never by outcomes.
            phase_arm(mcu, trial["phase"], cfg)
            token = "trial-%03d" % index
            save_new(intent_path, {**trial, "delay_us": delay, "preflight_min_width_us": width, "previous": status})
            ctrl.request("CUT %s %d %d 30000" % (token, delay, cfg["off_ms"]), {"phase_armed"})
            cut = None
            old = status
            cand = None
            update_error = None
            update_rejected = False
            for attempt in range(p["max_preparatory_updates_per_trial"]):
                old = status
                max_attempt += 1
                blob, cand = candidate(model, codec, max_attempt, next_role(old))
                append(args.output / "mutations.jsonl", dict(kind="intent", trial=index, attempt=attempt,
                       phase=trial["phase"], previous=old, candidate=cand))
                try:
                    mcu.send("UPDATE " + blob.hex())
                    reply = mcu.expect({"update"}, .5)
                    append(args.output / "mutations.jsonl", dict(kind="receipt", trial=index, attempt=attempt, response=reply))
                    if reply.get("accepted") is not True:
                        update_rejected = True
                        raise RuntimeError("Unexpected UPDATE rejection: " + str(reply))
                    event = ctrl.receive(.02)
                    if event and event.get("event") in ("cut_started", "cut_result", "phase_timeout"):
                        if event.get("event") != "cut_started":
                            cut = event
                        break
                    status = mcu.request("STATUS", {"status"}, 1)
                except Exception as exc:
                    update_error = str(exc)
                    break  # Expected lost reply during a physical outage; never retry.
                event = ctrl.receive(.02)
                if event and event.get("event") in ("cut_result", "phase_timeout"):
                    cut = event
                    break
            mcu.close()
            mcu = None
            if cut is None:
                cut = ctrl.expect({"cut_result", "phase_timeout"}, 35)
            if cut.get("trial") != token:
                raise RuntimeError("Controller trial token mismatch")
            rail = rail_evidence(cut, cfg)
            observed = None
            numeric_ok = None
            numeric = []
            try:
                mcu, observed = open_mcu(args, transcript, ctrl=ctrl, cfg=cfg)
                if observed.get("ready") is True:
                    numeric_ok, numeric = control_inference(mcu, observed, controls)
            except Exception as exc:
                update_error = (update_error or "") + "; recovery: " + str(exc)
                if observed is not None and observed.get("ready") is True:
                    numeric_ok = False
            state = classify_recovery(observed, old, cand or old, numeric_ok)
            timing_bound = cfg.get("switch_to_rail_collapse_upper_us")
            bounded = (not args.allow_unconfirmed_phase_timing and cfg.get("phase_timing_verified") is True and type(timing_bound) in (int, float)
                       and delay + 3 + timing_bound < width)
            result = {**trial, "delay_us": delay, "old": old, "candidate": cand, "recovered": observed,
                      "state": state, "numeric_controls": numeric, "controller": cut, **rail,
                      "phase_triggered": cut.get("phase_high_at_switch_command") is True,
                      "phase_confirmed": bool(rail["rail_off_confirmed"] and cut.get("phase_high_at_switch_command") is True and bounded),
                      "phase_confirmation_basis": "external fall-time bound plus uncut API-window minimum; not internal flash instruction capture",
                      "update_transport_error": update_error, "update_rejected": update_rejected}
            append(log, result)
            prior.append(result)
            print(json.dumps({"trial": index, "phase": trial["phase"], "state": state,
                              "rail_off_confirmed": rail["rail_off_confirmed"], "phase_confirmed": result["phase_confirmed"]}), flush=True)
            if state not in ("old_valid", "new_valid"):
                raise RuntimeError("Recovered state requires investigation: " + state)
            if update_rejected:
                raise RuntimeError("Explicit UPDATE rejection is not an expected lost reply; inspect mutation receipt")
            if cut.get("switch_command_issued") is True and not rail["rail_off_confirmed"]:
                raise RuntimeError("Switch command without rail-off evidence")
            # Missed phase/timeout trials remain in the denominator; not rerun.
            status = observed
            mcu.request("PHASE_DISARM", {"phase_control"})
            # A selected current release must still reject replay.
            replay, _ = candidate(model, codec, status["version"], selected_role(status))
            rejection = mcu.request("UPDATE " + replay.hex(), {"update"})
            append(args.output / "replay_checks.jsonl", dict(trial=index, response=rejection))
            validate_replay_rejection(rejection)
        summary["status"] = "complete"
        return summary
    except Exception as exc:
        summary["error"] = str(exc)
        raise
    finally:
        cleanup_errors = []
        try:
            if mcu:
                if phase_instrumentation_started:
                    try:
                        summary["phase_cleanup"] = mcu.request("PHASE_DISARM", {"phase_control"})
                    except Exception as exc:
                        cleanup_errors.append({"operation": "PHASE_DISARM", "error": repr(exc)})
                try:
                    mcu.close()
                except Exception as exc:
                    cleanup_errors.append({"operation": "mcu_close", "error": repr(exc)})
            if ctrl:
                final_adc = observe_adc(ctrl, cfg, transcript, "final_readonly_cleanup")
                summary["power_at_end_observation"] = final_adc
                summary["power_at_end_measured"] = final_adc.get("rail_on") is not None
                summary["power_at_end"] = "ON_measured" if final_adc.get("rail_on") is True else (
                    "below_on_or_out_of_range" if final_adc.get("rail_on") is False else "unknown")
                summary["cleanup_power_command_sent"] = False
                try:
                    ctrl.close()
                except Exception as exc:
                    cleanup_errors.append({"operation": "controller_close", "error": repr(exc)})
        finally:
            # This runs on the acquiring thread even on KeyboardInterrupt or cleanup error.
            if awake is not None:
                try:
                    awake.__exit__(*sys.exc_info())
                except Exception as exc:
                    cleanup_errors.append({"operation": "restore_system_awake", "error": repr(exc)})
        if cleanup_errors:
            summary["cleanup_errors"] = cleanup_errors
            summary["status"] = "failed"
            summary.setdefault("error", "Cleanup could not be fully confirmed; inspect cleanup_errors")
        summary.update(attempted_trials=len(prior), state_counts=dict(Counter(x["state"] for x in prior)),
                       rail_off_confirmed=sum(x.get("rail_off_confirmed", False) for x in prior),
                       phase_confirmed=sum(x.get("phase_confirmed", False) for x in prior),
                       physical_power_loss_tested=any(x.get("rail_off_confirmed", False) for x in prior),
                       phase_counts={phase: dict(attempted=sum(x["phase"] == phase for x in prior),
                           confirmed=sum(x["phase"] == phase and x.get("phase_confirmed", False) for x in prior)) for phase in PHASES},
                       exact_flash_instruction_phase_verified=False)
        summary["all_planned_phases_have_confirmed_cut"] = all(
            summary["phase_counts"][phase]["confirmed"] > 0 for phase in PHASES)
        summary["all_planned_trials_confirmed"] = summary["phase_confirmed"] == len(p["trials"])
        # Immutable snapshots allow resume without overwriting an earlier failure.
        name = "summary_%d.json" % time.time_ns()
        save_new(args.output / name, summary)
        print(json.dumps({"summary": str(args.output / name), **summary}), flush=True)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    q = sub.add_parser("plan", help="Prepare model/control hashes and fixed randomized trial schedule; no hardware")
    q.add_argument("--root", type=Path, default=REPO)
    q.add_argument("--prior-run", type=Path)
    q.add_argument("--model", type=Path)
    q.add_argument("--model-a", type=Path)
    q.add_argument("--allow-test-models", action="store_true", help="Software validation only; resulting plan is blocked from physical preflight/run")
    q.add_argument("--output", type=Path, required=True)
    q.add_argument("--repeats-per-phase", type=int, default=25)
    q.add_argument("--seed", type=int, default=23102026)
    q = sub.add_parser("flash", help="ROM-MAC-verified provisioning of the optional phase-enabled image; replaces lab firmware/model storage")
    q.add_argument("--root", type=Path, default=REPO)
    q.add_argument("--plan", type=Path, required=True)
    q.add_argument("--prebuilt-root", type=Path, default=REPO / "revision039/build/prebuilt/phase_gpio4/O2")
    q.add_argument("--port", required=True)
    q.add_argument("--board-id", required=True)
    q.add_argument("--output", type=Path, required=True)
    q.add_argument("--prepare-only", action="store_true", help="Verify binaries and prepare patched factory files, no port access")
    for command in ("preflight", "run"):
        q = sub.add_parser(command)
        q.add_argument("--root", type=Path, default=REPO)
        q.add_argument("--plan", type=Path, required=True)
        q.add_argument("--config", type=Path, required=True)
        q.add_argument("--mcu-port", required=True)
        q.add_argument("--controller-port", required=True)
        q.add_argument("--board-id", required=True)
        q.add_argument("--output", type=Path, required=True)
        if command == "run":
            q.add_argument("--preflight", type=Path, required=True)
            q.add_argument("--resume", action="store_true")
            q.add_argument("--late-recovery", type=Path,
                           help="Only the hash-pinned trial113 diagnostic; not a generic bypass")
            q.add_argument("--control-run", type=Path, required=True,
                           help="Reviewed separate power047100-cycle output directory")
            q.add_argument("--prepare-only", action="store_true",
                           help="Validate incident continuation without device access or file writes")
            q.add_argument("--allow-unconfirmed-phase-timing", action="store_true",
                           help="Exploratory phase-triggered cuts; do NOT claim verified inside-operation interruption")
    return p


def main():
    args = parser().parse_args()
    try:
        result = {"plan": plan, "flash": flash, "preflight": preflight, "run": run}[args.command](args)
        message = {"status": result["status"], "command": args.command, "output": str(args.output)}
        if args.command == "run" and getattr(args, "prepare_only", False):
            message.update(result)
        print(json.dumps(message))
        return 2 if result["status"] == "failed" else 0
    except Exception as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
