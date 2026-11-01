"""Independent power047 tests with mock hardware and immutable real evidence.

Fixture environment variables:
  POWER047_INCIDENT_RUN: extracted incident113/run
  POWER047_LATE_RECOVERY: extracted diagnostic-incident113-* folder
No serial device is ever opened. All test writes use temporary clones.
"""
from __future__ import annotations
import copy
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import control_power047 as control


def hashes(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


class Harness:
    def __init__(self, ctx, late):
        self.ctx = ctx
        self.late = copy.deepcopy(late)
        self.clock = 0.0
        self.events = []
        self.commands = []
        self.mcu_opens = 0
        self.pico_opens = 0
        self.probes = 0
        self.probe_replies = 0
        self.last_probe_start = None
        self.instances = []
        self.fail_open_after_baseline = False
        self.fail_first_close_during_off = False
        self.bad_initial_identity = False
        self.bad_initial_probability = False
        self.bad_cycle_probability = False
        self.armed = True
        self.bad_off = False
        self.adc_values = []
        self.adc_default = 3.3
        self.adc_calls = 0
        self.adc_seconds = 0.001
        self.adc_times = []
        self.dos_times = []
        self.host_times = []
        self.guard = mock.MagicMock()
        self.stop_at_baseline = False
        self.stop_handler = None
        self.controller = None

    def sleep(self, seconds):
        self.clock += seconds

    def log(self, path, name, command):
        self.commands.append((name, command))
        control.append(path, {"direction": "tx", "link": name, "line": command})

    def Link(self, port, transcript, name):
        if name == "mcu":
            self.mcu_opens += 1
            if self.fail_open_after_baseline and self.mcu_opens > 1:
                raise PermissionError("simulated Windows port unavailable")
            link = Mcu(self, transcript, self.mcu_opens)
            self.instances.append(link)
            return link
        if name == "pico":
            self.pico_opens += 1
            # Baseline must be fully checked before even opening Pico.
            initial = self.instances[0]
            if initial.infers != 12 or initial.statuses != 2:
                raise AssertionError("Pico opened before complete baseline verification")
            self.controller = Controller(self, transcript)
            return self.controller
        raise AssertionError(name)

    def install(self, stack):
        stack.enter_context(mock.patch.object(control, "validate", return_value=self.ctx))
        stack.enter_context(mock.patch.object(self.ctx["r"], "Link", side_effect=self.Link))
        stack.enter_context(mock.patch.object(control.time, "monotonic", side_effect=lambda: self.clock))
        stack.enter_context(mock.patch.object(control.time, "sleep", side_effect=self.sleep))
        stack.enter_context(mock.patch.object(self.ctx["d"], "serial_metadata", return_value={"version": "mock"}))
        stack.enter_context(mock.patch.object(self.ctx["d"], "host_snapshot", side_effect=self.host_snapshot))
        stack.enter_context(mock.patch.object(self.ctx["d"], "query_dos_device", side_effect=self.query_dos))
        stack.enter_context(mock.patch.object(self.ctx["r"].continuation, "SleepGuard", return_value=self.guard))
        stack.enter_context(mock.patch.object(control.signal, "signal", side_effect=self.signal))
        stack.enter_context(redirect_stdout(io.StringIO()))

    def signal(self, signum, handler):
        if callable(handler):
            self.stop_handler = handler
        return 1

    def host_snapshot(self, *args, **kwargs):
        self.host_times.append(self.clock)
        return {"mock": True}

    def query_dos(self, *args, **kwargs):
        self.dos_times.append(self.clock)
        return {"mock": True}


class Mcu:
    def __init__(self, host, transcript, index):
        self.h, self.transcript, self.index = host, transcript, index
        self.infers = self.statuses = 0
        self.closed = False

    def request(self, command, expected, timeout=5):
        self.h.log(self.transcript, "mcu", command)
        self.h.clock += 0.001
        if command == "STATUS":
            self.statuses += 1
            response = copy.deepcopy(self.h.late["before"])
            if self.h.bad_initial_identity and self.index == 1:
                response["selector_sequence"] += 1
            if self.h.stop_at_baseline and self.index == 1 and self.statuses == 2:
                self.h.stop_handler(None, None)
            return response
        if command.startswith("INFER "):
            result = copy.deepcopy(self.h.late["checks"][self.infers % 12]["response"])
            self.infers += 1
            if ((self.h.bad_initial_probability and self.index == 1)
                    or (self.h.bad_cycle_probability and self.index > 1)):
                result["probability"] = float("nan")
            return result
        raise AssertionError("Non-readonly MCU command: " + command)

    def receive(self, timeout):
        self.h.clock += timeout
        self.h.events.append(("passive_receive", self.h.clock))
        raise PermissionError("expected mock USB disconnect while OFF")

    def close(self):
        self.closed = True
        self.h.events.append(("mcu_close", self.h.clock))
        if self.h.fail_first_close_during_off and self.index == 1 and self.h.probes:
            self.h.fail_first_close_during_off = False
            raise OSError("simulated close failure during OFF")


class Controller:
    def __init__(self, host, transcript):
        self.h, self.transcript = host, transcript
        self.closed = False

    def request(self, command, expected, timeout=5):
        self.h.log(self.transcript, "pico", command)
        if command == "ID":
            cfg = self.h.ctx["cfg"]
            return {"protocol": "ids-power039-v1", "config_sha256": control.CONFIG_SHA256,
                    "enabled": True, "armed": self.h.armed,
                    **{k: cfg[k] for k in ("enable_pin", "phase_pin", "adc_pin", "active_high_enable")}}
        if command == "ADC":
            self.h.adc_calls += 1
            self.h.adc_times.append(self.h.clock)
            self.h.clock += min(self.h.adc_seconds, timeout)
            voltage = self.h.adc_values.pop(0) if self.h.adc_values else self.h.adc_default
            cfg = self.h.ctx["cfg"]
            raw = round((voltage - cfg["adc_zero_volts"]) / cfg["adc_volts_per_count"])
            return {"event": "adc", "raw": raw}
        raise AssertionError("Unexpected Pico command: " + command)

    def send(self, command):
        self.h.log(self.transcript, "pico", command)
        if command != "PROBE 2000":
            raise AssertionError("Forbidden Pico power command: " + command)
        self.h.probes += 1
        self.h.last_probe_start = self.h.clock
        self.h.events.append(("probe_send", self.h.clock))

    def expect(self, expected, timeout=10):
        if expected != {"probe_result"}:
            raise AssertionError(expected)
        self.h.clock = max(self.h.clock, self.h.last_probe_start + 2)
        self.h.probe_replies += 1
        self.h.events.append(("probe_reply", self.h.clock))
        event = copy.deepcopy(self.h.ctx["incident"]["controller"])
        event["event"] = "probe_result"
        if self.h.bad_off:
            event["rail_samples"] = []
        return event

    def close(self):
        self.closed = True


class Power047Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run = os.environ.get("POWER047_INCIDENT_RUN")
        late = os.environ.get("POWER047_LATE_RECOVERY")
        if not run or not late:
            raise unittest.SkipTest("Set POWER047_INCIDENT_RUN and POWER047_LATE_RECOVERY for real-evidence mock tests")
        cls.source, cls.late_source = Path(run).resolve(), Path(late).resolve()
        if not (cls.source / "results/trial_results.jsonl").is_file():
            raise RuntimeError("POWER047_INCIDENT_RUN must be extracted incident113/run")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.run, self.late, self.runtime = self.base / "run", self.base / "late", self.base / "runtime"
        shutil.copytree(self.source, self.run)
        self.late.mkdir(); self.runtime.mkdir()
        for name in ("summary.json", "serial.jsonl"):
            shutil.copyfile(self.late_source / name, self.late / name)
        for name in ("run_powercut046.py", "continuation046.py", "incident061_hashes.json"):
            shutil.copyfile(self.run / "results/continuation046_sources" / name, self.runtime / name)
        self.args = SimpleNamespace(run=self.run, late_recovery=self.late, runner_dir=self.runtime,
                                    mcu_port="COM13", controller_port="COM5", prepare_only=False)
        self.late_data = json.loads((self.late / "summary.json").read_text())
        self.original = hashes(self.run)

    def unchanged_originals(self):
        for relative, expected in self.original.items():
            self.assertEqual(hashlib.sha256((self.run / relative).read_bytes()).hexdigest(), expected, relative)

    def harness(self):
        return Harness(control.validate(self.args), self.late_data)

    def execute(self, h):
        with ExitStack() as stack:
            h.install(stack)
            result = control.run_control(self.args)
        self.unchanged_originals()
        return result

    def archive_ok(self, out, archive):
        self.assertTrue(archive and archive.is_file())
        expected = archive.with_name(archive.name + ".sha256").read_text().split()[0]
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), expected)
        with zipfile.ZipFile(archive) as z:
            self.assertIsNone(z.testzip())
            saved = json.loads(z.read(out.name + "/summary.json"))
        return saved

    def test_prepare_only_creates_no_files_and_opens_no_ports(self):
        self.args.prepare_only = True
        before = hashes(self.base)
        with mock.patch.dict(sys.modules, {"serial": None}):
            report, out, archive = control.run_control(self.args)
        self.assertEqual(report["status"], "prepared_not_run")
        self.assertEqual(report["planned_cycles"], 100)
        self.assertFalse(report["hardware_access_attempted"])
        self.assertIsNone(out); self.assertIsNone(archive)
        self.assertEqual(hashes(self.base), before)

    def test_config_hash_mismatch_stops_before_ports_or_output(self):
        with (self.run / "setup/powercut_config.json").open("a") as f:
            f.write(" ")
        before = hashes(self.base)
        with mock.patch.dict(sys.modules, {"serial": None}), self.assertRaisesRegex(ValueError, "config changed"):
            control.run_control(self.args)
        self.assertEqual(hashes(self.base), before)

    def test_late_evidence_tampering_stops_before_ports_or_output(self):
        with (self.late / "serial.jsonl").open("a") as f:
            f.write("\n")
        before = hashes(self.base)
        with mock.patch.dict(sys.modules, {"serial": None}), self.assertRaisesRegex(ValueError, "Late113 evidence differs"):
            control.run_control(self.args)
        self.assertEqual(hashes(self.base), before)

    def test_wrong_old_identity_never_opens_pico(self):
        h = self.harness(); h.bad_initial_identity = True
        report, out, archive = self.execute(h)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(h.pico_opens, 0)
        self.assertEqual(h.commands, [("mcu", "STATUS")])
        self.assertEqual(h.probes, 0)
        h.guard.__exit__.assert_called_once()
        self.archive_ok(out, archive)

    def test_bad_initial_inference_never_opens_pico_and_archives_nan(self):
        h = self.harness(); h.bad_initial_probability = True
        report, out, archive = self.execute(h)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(h.pico_opens, 0)
        self.assertEqual(h.probes, 0)
        self.archive_ok(out, archive)

    def test_pico_unarmed_is_not_armed_by_script(self):
        h = self.harness(); h.armed = False
        report, out, archive = self.execute(h)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(h.probes, 0)
        self.assertTrue(all(cmd in ("ID", "ADC") for name, cmd in h.commands if name == "pico"))
        self.archive_ok(out, archive)

    def test_fixed_hundred_cycles_have_separate_ids_and_only_allowed_commands(self):
        h = self.harness()
        report, out, archive = self.execute(h)
        self.assertEqual((report["status"], report["planned_cycles"], report["completed_cycles"], report["attempted_cycles"]), ("complete", 100, 100, 100))
        self.assertEqual(h.probes, 100)
        results = [json.loads(line) for line in (out / "cycle_results.jsonl").read_text().splitlines()]
        self.assertEqual([x["cycle"] for x in results], list(range(1, 101)))
        self.assertTrue(all(x["checks_passed"] == 12 and x["rail_off"]["rail_off_confirmed"] for x in results))
        self.assertTrue(all(x["before"]["version"] == 1136 and x["after"]["selector_sequence"] == 1044 for x in results))
        for name, cmd in h.commands:
            self.assertTrue((name == "mcu" and (cmd == "STATUS" or cmd.startswith("INFER ")))
                            or (name == "pico" and cmd in ("ID", "ADC", "PROBE 2000")), cmd)
        self.assertFalse((out / "trial_results.jsonl").exists())
        self.assertFalse((self.run / control.LOCK_NAME).exists())
        self.assertTrue(all(x.closed for x in h.instances))
        self.assertTrue(h.controller.closed)
        h.guard.__exit__.assert_called_once()
        self.archive_ok(out, archive)

    def test_first_recovery_timeout_stops_without_another_power_command(self):
        h = self.harness(); h.fail_open_after_baseline = True
        report, out, archive = self.execute(h)
        self.assertEqual((report["status"], report["attempted_cycles"], report["completed_cycles"]), ("failed", 1, 0))
        self.assertEqual(h.probes, 1)
        cycle = json.loads((out / "failed_cycle.json").read_text())
        self.assertEqual(cycle["deadline_seconds"], 20)
        self.assertTrue(cycle["rail_on_at_failed_endpoint"])
        self.assertTrue(all(cmd in ("ID", "ADC", "PROBE 2000") for name, cmd in h.commands if name == "pico"))
        self.assertEqual(h.host_times and len(h.host_times), 1)
        self.assertGreaterEqual(h.host_times[0], cycle["probe_reply_monotonic"] + 20)
        h.guard.__exit__.assert_called_once()
        self.archive_ok(out, archive)

    def test_persistent_low_rail_is_reported_at_failed_deadline(self):
        h = self.harness(); h.fail_open_after_baseline = True
        h.adc_values = [3.3]; h.adc_default = 0.1
        report, out, archive = self.execute(h)
        cycle = json.loads((out / "failed_cycle.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertFalse(cycle["rail_on_at_failed_endpoint"])
        self.assertEqual(h.probes, 1)
        self.archive_ok(out, archive)

    def test_delayed_rail_rise_is_allowed_until_status_recovery(self):
        h = self.harness()
        h.adc_values = [3.3, 0.1, 3.3]
        report, out, archive = self.execute(h)
        first = json.loads((out / "cycle_001.json").read_text())
        self.assertEqual(report["status"], "complete")
        self.assertLess(first["adc"][0]["volts"], 3)
        self.assertGreater(first["adc"][1]["volts"], 3)
        self.archive_ok(out, archive)

    def test_missing_off_evidence_stops_before_reopening_mcu(self):
        h = self.harness(); h.bad_off = True
        report, out, archive = self.execute(h)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(h.probes, 1)
        self.assertEqual(h.mcu_opens, 1)
        self.assertTrue((out / "failed_cycle.json").is_file())
        self.archive_ok(out, archive)

    def test_nonfinite_cycle_result_still_retains_partial_archive(self):
        h = self.harness(); h.bad_cycle_probability = True
        report, out, archive = self.execute(h)
        self.assertEqual((report["status"], report["attempted_cycles"], report["completed_cycles"]), ("failed", 1, 0))
        self.assertEqual(h.probes, 1)
        cycle = json.loads((out / "failed_cycle.json").read_text())
        self.assertFalse(cycle["checks"][0]["ok"])
        self.assertTrue((out / "cycle_results.jsonl").is_file())
        h.guard.__exit__.assert_called_once()
        self.archive_ok(out, archive)

    def test_close_during_off_failure_awaits_probe_and_retains_archive(self):
        h = self.harness(); h.fail_first_close_during_off = True
        report, out, archive = self.execute(h)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(h.probes, 1)
        self.assertEqual(h.probe_replies, 1)
        cycle = json.loads((out / "failed_cycle.json").read_text())
        self.assertIn("probe", cycle)
        self.assertTrue(cycle.get("adc"))
        h.guard.__exit__.assert_called_once()
        self.archive_ok(out, archive)

    def test_user_stop_after_baseline_still_returns_archive(self):
        h = self.harness(); h.stop_at_baseline = True
        report, out, archive = self.execute(h)
        self.assertEqual(report["status"], "stopped_before_cycles")
        self.assertEqual(h.probes, 0)
        self.assertEqual(h.pico_opens, 0)
        self.archive_ok(out, archive)


if __name__ == "__main__":
    unittest.main()
