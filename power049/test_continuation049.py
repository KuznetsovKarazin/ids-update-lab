"""Independent continuation049 tests. Hardware is always mocked.

Set POWER049_INCIDENT_RUN to the extracted incident186/run directory for the
fixture-dependent tests. Every test uses a temporary copy; original evidence
is never changed. No external late diagnostic is accepted or required.
"""
from __future__ import annotations
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from contextlib import redirect_stdout
from types import SimpleNamespace
import unittest
from unittest import mock

PACKAGE = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKAGE))
import continuation049 as admission


def load_runner():
    spec = importlib.util.spec_from_file_location("independent_runner049", PACKAGE / "run_powercut049.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeMcu:
    """Deterministic A1696 device; its mocked serial replies retain raw bytes."""
    def __init__(self, old, controls):
        self.before = copy.deepcopy(old)
        self.after = copy.deepcopy(old)
        self.controls = controls
        self.commands = []
        self.infer_index = 0
        self.closed = False
        self.transcript = None
        self.bad_index = None
        self.no_response = False
        self.status_calls = 0

    def record(self, direction, **fields):
        if self.transcript:
            self.transcript.parent.mkdir(parents=True, exist_ok=True)
            with self.transcript.open("a") as stream:
                stream.write(json.dumps(dict(link="mcu", direction=direction, **fields)) + "\n")

    def request(self, command, expected, timeout=5):
        self.commands.append(command)
        self.record("tx", line=command)
        if self.no_response:
            raise TimeoutError("injected late STATUS timeout")
        if command == "STATUS":
            result = self.before if self.status_calls == 0 else self.after
            self.status_calls += 1
        elif command.startswith("INFER "):
            want = self.controls["expected"]["A"][self.infer_index]
            result = {"event": "inference", "version": self.before["version"],
                      "bundle_sha256": self.before["bundle_sha256"], "runtime_abi": self.before["runtime_abi"],
                      "policy": self.before["policy"], "pretransform": self.before["pretransform"],
                      **want}
            if self.infer_index == self.bad_index:
                result["probability"] = want["probability"] + .1
            self.infer_index += 1
        elif command == "PHASE_DISARM":
            result = {"event": "phase_control", "ok": True, "enabled": False}
        else:
            raise AssertionError("Unexpected MCU command: " + command)
        result = copy.deepcopy(result)
        line = json.dumps(result)
        self.record("rx_bytes", bytes_hex=(line + "\n").encode().hex())
        self.record("rx", line=line)
        return result

    def send(self, command):
        self.commands.append(command)
        self.record("tx", line=command)

    def close(self):
        self.closed = True


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = os.environ.get("POWER049_INCIDENT_RUN")
        if not source:
            raise unittest.SkipTest("Set POWER049_INCIDENT_RUN to the extracted incident186/run directory")
        cls.source = Path(source).resolve()
        if not (cls.source / "results/trial_results.jsonl").is_file():
            raise RuntimeError("POWER049_INCIDENT_RUN is not the incident186 run directory")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.run = self.base / "run"
        shutil.copytree(self.source, self.run)
        self.kit = self.base / "kit"
        source_target = self.kit / "revision039/powercut/run_powercut039.py"
        source_target.parent.mkdir(parents=True)
        shutil.copyfile(self.run / "diagnostics-20261027-103428/run_powercut039.py", source_target)
        self.args = SimpleNamespace(root=self.kit, output=self.run / "results",
            config=self.run / "setup/powercut_config.json", preflight=self.run / "preflight",
            plan=self.run / "plan", board_id=admission.BOARD_ID,
            allow_unconfirmed_phase_timing=True, resume=True, verify_incident186=True,
            prepare_only=False, mcu_port="COM13", controller_port="COM5")
        self.plan_path = self.args.plan / "plan.json"
        self.plan = admission.read(self.plan_path)
        self.controls = admission.read(self.args.plan / "controls.json")
        self.prior = [json.loads(line) for line in (self.args.output / "trial_results.jsonl").read_text().splitlines()]
        self.old = self.prior[-1]["old"]
        self.cfg = admission.read(self.args.config)

    def review(self):
        return admission.validate_evidence(self.args, self.prior, self.controls, self.plan_path)

    def hashes(self):
        return {str(p.relative_to(self.run)): admission.digest(p) for p in self.run.rglob("*") if p.is_file()}

    def codec(self):
        return SimpleNamespace(ABI={"mlp_float": 4}, SCHEMA=bytes.fromhex(self.old["schema"]))

    def late_summary(self):
        return admission.read(self.args.output / "incident186_late049/summary.json")

    def controller(self, mcu, *, armed=True, raw=33944):
        ctrl = SimpleNamespace(commands=[], closed=False)
        def request(command, expected, timeout=5):
            self.assertEqual(mcu.infer_index, 12)
            ctrl.commands.append(command)
            if command == "ID":
                return dict(protocol=load_runner().PROTOCOL, enabled=True, armed=armed,
                            config_sha256=admission.digest(self.args.config),
                            **{k:self.cfg[k] for k in ("enable_pin", "phase_pin", "adc_pin", "active_high_enable")})
            if command == "ADC":
                return {"event": "adc", "raw": raw}
            if command.startswith("CUT "):
                return {"event": "phase_armed"}
            raise AssertionError("Forbidden Pico command: " + command)
        ctrl.request = request
        ctrl.close = lambda: setattr(ctrl, "closed", True)
        return ctrl

    def link_factory(self, mcu, ctrl=None):
        def link(port, transcript, name):
            if name == "mcu":
                self.assertEqual(port, "COM13")
                mcu.transcript = Path(transcript)
                return mcu
            self.assertEqual((port, name), ("COM5", "pico"))
            self.assertEqual(mcu.infer_index, 12)
            self.assertIsNotNone(ctrl, "Pico opened before admission")
            return ctrl
        return link

    def test_offline_exact_checkpoint_readonly_and_no_late_state_invented(self):
        before = self.hashes()
        review = self.review()
        self.assertEqual(self.hashes(), before)
        self.assertEqual(review["original_states"], {"61":"no_response", "113":"no_response", "186":"no_response"})
        self.assertEqual(review["first_continued_trial"], 187)
        self.assertEqual(review["remaining_trials"], 14)
        self.assertEqual(review["expected_identity"]["version"], 1696)
        self.assertEqual(review["expected_identity"]["release"], "p39A-1696")
        self.assertNotEqual(review.get("late_states", {}).get("186"), "old_valid")
        self.assertEqual(review["protocol_epoch"]["recovery_window_seconds"], 20)

    def test_prepare_only_no_ports_no_evidence_change(self):
        runner = load_runner()
        self.args.prepare_only = True
        before = self.hashes()
        with mock.patch.object(runner, "dependencies", return_value=(self.codec(), None)), mock.patch.object(runner, "Link", side_effect=AssertionError("Hardware accessed")):
            result = runner.run(self.args)
        self.assertEqual(result["status"], "prepared_not_run")
        self.assertFalse(result["hardware_access_attempted"])
        self.assertEqual(before, self.hashes())

    def test_all_evidence_tampering_blocks_before_any_port(self):
        runner = load_runner()
        paths = ["results/trial_results.jsonl", "plan/controls.json", "setup/powercut_config.json",
                 "results/continuation048_sources/run_powercut048.py",
                 "control-power047-1793098930288437700/serial.jsonl"]
        for relative in paths:
            path = self.run / relative
            original = path.read_bytes()
            with self.subTest(file=relative):
                path.write_bytes(original + b" ")
                before = self.hashes()
                with mock.patch.object(runner, "dependencies", return_value=(self.codec(), None)), mock.patch.object(runner, "Link", side_effect=AssertionError("Hardware accessed")):
                    with self.assertRaises(ValueError):
                        runner.run(self.args)
                self.assertEqual(before, self.hashes())
                self.assertFalse((self.args.output / admission.ATTEMPT_NAME).exists())
            path.write_bytes(original)

    def test_specific_authorization_board_ports_and_timing_required(self):
        for change in ({"verify_incident186":False}, {"resume":False}, {"board_id":"other"}, {"mcu_port":"COM14"}, {"controller_port":"COM6"}, {"allow_unconfirmed_phase_timing":False}):
            with self.subTest(change=change):
                args = copy.copy(self.args)
                vars(args).update(change)
                with self.assertRaises(ValueError):
                    admission.validate_evidence(args, self.prior, self.controls, self.plan_path)

    def test_cannot_reclassify_any_historical_timeout(self):
        for index in (60,112,185):
            with self.subTest(trial=index+1):
                self.prior[index]["state"] = "old_valid"
                with self.assertRaises(ValueError):
                    self.review()
                self.prior[index]["state"] = "no_response"

    def test_future_timeout_or_pending_intent_not_admitted(self):
        self.prior.append(dict(self.prior[-1], trial=187))
        with self.assertRaises(ValueError):
            self.review()
        self.prior.pop()
        (self.args.output / "trial_187_intent.json").write_text("{}")
        with self.assertRaises(ValueError):
            self.review()

    def test_unknown_unsafe_original_state_is_not_admitted(self):
        self.prior[100]["state"] = "unexpected_or_mixed"
        with self.assertRaises(ValueError):
            self.review()

    def test_changed_installed_runner_refused(self):
        (self.kit / "revision039/powercut/run_powercut039.py").write_text("changed")
        with self.assertRaises(ValueError):
            self.review()

    def assert_live_refusal(self, mcu, regex):
        runner = load_runner()
        before = (self.args.output / "trial_results.jsonl").read_bytes()
        guard = mock.MagicMock()
        with mock.patch.object(runner, "dependencies", return_value=(self.codec(), None)), mock.patch.object(runner, "Link", side_effect=self.link_factory(mcu)), mock.patch.object(runner, "install", side_effect=AssertionError("Flash mutated")), mock.patch.object(admission, "SleepGuard", return_value=guard), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(Exception, regex):
                runner.run(self.args)
        self.assertEqual(before, (self.args.output / "trial_results.jsonl").read_bytes())
        self.assertTrue((self.args.output / admission.ATTEMPT_NAME).is_file())
        self.assertFalse((self.args.output / admission.ADMISSION_NAME).exists())
        self.assertTrue(mcu.closed)
        self.assertTrue(all(c == "STATUS" or c.startswith("INFER ") for c in mcu.commands))
        late = self.late_summary()
        self.assertNotEqual(late.get("status"), "passed")
        self.assertFalse(late.get("flash_mutation_attempted", False))
        self.assertTrue((self.args.output / "incident186_late049/serial.jsonl").is_file())
        guard.__exit__.assert_called_once()
        return late

    def test_new_candidate_identity_never_admitted(self):
        mcu = FakeMcu(self.old, self.controls)
        mcu.before.update(self.prior[-1]["candidate"])
        self.assert_live_refusal(mcu, "Live model differs")
        self.assertEqual(mcu.commands, ["STATUS"])

    def test_wrong_slot_or_selector_never_admitted(self):
        mcu = FakeMcu(self.old, self.controls)
        mcu.before["selector_sequence"] += 1
        self.assert_live_refusal(mcu, "Live model differs")
        self.assertEqual(mcu.commands, ["STATUS"])

    def test_any_changed_identity_field_stops_before_inference(self):
        review = self.review()
        for field in ("version", "release", "bundle_sha256", "active_slot", "selector_sequence", "build", "schema", "runtime_abi", "chip", "pretransform", "ready"):
            with self.subTest(field=field):
                status = copy.deepcopy(self.old)
                original = status[field]
                status[field] = False if field == "ready" else original + 1 if isinstance(original, int) else original + "-changed"
                mcu = FakeMcu(self.old, self.controls)
                with self.assertRaisesRegex(ValueError, "Live model differs"):
                    admission.verify_live(mcu, status, review, self.controls)
                self.assertEqual(mcu.commands, [])

    def test_initial_no_response_preserves_diagnostic_without_retry(self):
        mcu = FakeMcu(self.old, self.controls)
        mcu.no_response = True
        self.assert_live_refusal(mcu, "late STATUS timeout")
        self.assertEqual(mcu.commands, ["STATUS"])

    def test_initial_port_open_failure_is_saved_without_another_open(self):
        runner = load_runner()
        original = (self.args.output / "trial_results.jsonl").read_bytes()
        with mock.patch.object(runner, "dependencies", return_value=(self.codec(), None)), mock.patch.object(runner, "Link", side_effect=OSError("COM13 unavailable")) as constructor, mock.patch.object(runner, "install", side_effect=AssertionError("Flash mutated")), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(OSError, "COM13 unavailable"):
                runner.run(self.args)
        constructor.assert_called_once()
        self.assertEqual(constructor.call_args.args[0], "COM13")
        late = self.late_summary()
        self.assertEqual(late["status"], "failed")
        self.assertEqual(late["checks"], [])
        self.assertIn("COM13 unavailable", late["error"])
        self.assertEqual((self.args.output / "incident186_late049/serial.jsonl").read_bytes(), b"")
        self.assertEqual(original, (self.args.output / "trial_results.jsonl").read_bytes())
        self.assertFalse((self.args.output / admission.ADMISSION_NAME).exists())

    def test_A_control_failure_is_retained_and_never_opens_pico(self):
        mcu = FakeMcu(self.old, self.controls)
        mcu.bad_index = 4
        late = self.assert_live_refusal(mcu, "control mismatch")
        self.assertGreaterEqual(len(late.get("checks", [])), 5)
        self.assertNotIn("PHASE_DISARM", mcu.commands)

    def test_changed_identity_after_controls_is_not_admitted(self):
        mcu = FakeMcu(self.old, self.controls)
        mcu.after["active_slot"] = 1
        self.assert_live_refusal(mcu, "identity changed")
        self.assertEqual(mcu.infer_index, 12)

    def test_failed_live_attempt_blocks_second_start_before_ports(self):
        mcu = FakeMcu(self.old, self.controls)
        mcu.before["selector_sequence"] += 1
        self.assert_live_refusal(mcu, "Live model differs")
        runner = load_runner()
        before = self.hashes()
        with mock.patch.object(runner, "dependencies", return_value=(self.codec(), None)), mock.patch.object(runner, "Link", side_effect=AssertionError("Hardware accessed again")):
            with self.assertRaises(ValueError):
                runner.run(self.args)
        self.assertEqual(before, self.hashes())

    def test_concurrent_attempt_marker_wins_before_any_port(self):
        runner = load_runner()
        original_validate = admission.validate_evidence
        def race(*args):
            review = original_validate(*args)
            (self.args.output / admission.ATTEMPT_NAME).write_text("{\"other_process\":true}")
            return review
        with mock.patch.object(runner, "dependencies", return_value=(self.codec(), None)), mock.patch.object(admission, "validate_evidence", side_effect=race), mock.patch.object(runner, "Link", side_effect=AssertionError("Hardware accessed")):
            with self.assertRaises(FileExistsError):
                runner.run(self.args)
        self.assertEqual(admission.read(self.args.output / admission.ATTEMPT_NAME), {"other_process":True})

    def test_close_error_keeps_late_and_run_summaries_and_restores_awake(self):
        mcu = FakeMcu(self.old, self.controls)
        mcu.before["selector_sequence"] += 1
        mcu.close = mock.Mock(side_effect=OSError("injected close failure"))
        runner = load_runner()
        guard = mock.MagicMock()
        summaries = set(self.args.output.glob("summary_*.json"))
        with mock.patch.object(runner, "dependencies", return_value=(self.codec(), None)), mock.patch.object(runner, "Link", side_effect=self.link_factory(mcu)), mock.patch.object(admission, "SleepGuard", return_value=guard), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(Exception, "Live model differs"):
                runner.run(self.args)
        guard.__exit__.assert_called_once()
        self.assertNotEqual(self.late_summary().get("status"), "passed")
        new = set(self.args.output.glob("summary_*.json")) - summaries
        self.assertEqual(len(new), 1)
        summary = admission.read(new.pop())
        self.assertEqual(summary["status"], "failed")
        self.assertTrue(any(x["operation"] == "mcu_close" for x in summary["cleanup_errors"]))

    def assert_pico_refusal(self, *, armed=True, raw=33944):
        runner = load_runner()
        mcu = FakeMcu(self.old, self.controls)
        ctrl = self.controller(mcu, armed=armed, raw=raw)
        original = (self.args.output / "trial_results.jsonl").read_bytes()
        with mock.patch.object(runner, "dependencies", return_value=(self.codec(), None)), mock.patch.object(runner, "Link", side_effect=self.link_factory(mcu, ctrl)), mock.patch.object(runner, "install", side_effect=AssertionError("Flash mutation reached")), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "Pico must already|Admission requires"):
                runner.run(self.args)
        self.assertEqual(original, (self.args.output / "trial_results.jsonl").read_bytes())
        self.assertEqual(self.late_summary()["status"], "passed")
        self.assertFalse((self.args.output / admission.ADMISSION_NAME).exists())
        self.assertTrue(ctrl.closed)
        self.assertTrue(all(c in ("ID", "ADC") for c in ctrl.commands))
        self.assertNotIn("PHASE_DISARM", mcu.commands)

    def test_unarmed_pico_is_not_repaired(self):
        self.assert_pico_refusal(armed=False)

    def test_low_admission_adc_blocks_any_update(self):
        self.assert_pico_refusal(raw=0)

    def test_successful_late_A_gate_then_only187_and_versions1699_1700_1701(self):
        runner = load_runner()
        mcu = FakeMcu(self.old, self.controls)
        ctrl = self.controller(mcu)
        original = (self.args.output / "trial_results.jsonl").read_bytes()
        versions, candidates, phases = [], [], []
        class StopBeforeSigning(RuntimeError): pass
        def install(_mcu, model, codec, status, output, label, version=None):
            self.assertEqual(self.late_summary()["status"], "passed")
            self.assertTrue((self.args.output / admission.ADMISSION_NAME).is_file())
            versions.append(version)
            return dict(status, version=version, release=f"p39A-{version}", bundle_sha256="synthetic"), {}
        def candidate(model, codec, version, role):
            candidates.append(version)
            raise StopBeforeSigning("stop before signing next UPDATE")
        with mock.patch.object(runner, "dependencies", return_value=(self.codec(), None)), mock.patch.object(runner, "Link", side_effect=self.link_factory(mcu, ctrl)), mock.patch.object(runner, "install", side_effect=install), mock.patch.object(runner, "candidate", side_effect=candidate), mock.patch.object(runner, "phase_arm", side_effect=lambda _m, phase, _c: phases.append(phase)), mock.patch.object(runner.time, "sleep"), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(StopBeforeSigning, "stop before signing"):
                runner.run(self.args)
        self.assertEqual(versions, [1699,1700])
        self.assertEqual(candidates, [1701])
        self.assertEqual(phases, [self.plan["trials"][186]["phase"]])
        cuts = [c for c in ctrl.commands if c.startswith("CUT ")]
        self.assertEqual(len(cuts), 1)
        self.assertTrue(cuts[0].startswith("CUT trial-187 "))
        self.assertEqual(original, (self.args.output / "trial_results.jsonl").read_bytes())
        self.assertTrue(all(c in ("ID","ADC") or c.startswith("CUT trial-187 ") for c in ctrl.commands))
        late = self.late_summary()
        self.assertEqual(len(late["checks"]), 12)
        self.assertEqual([c["expected"] for c in late["checks"]], self.controls["expected"]["A"])
        self.assertEqual(late["before"]["version"], 1696)
        self.assertEqual(late["after"]["version"], 1696)
        serial = [json.loads(x) for x in (self.args.output / "incident186_late049/serial.jsonl").read_text().splitlines()]
        tx = [r["line"] for r in serial if r.get("direction") == "tx"]
        self.assertEqual(tx, admission.expected_commands(self.controls))
        raw = b"".join(bytes.fromhex(r["bytes_hex"]) for r in serial if r.get("direction") == "rx_bytes")
        responses = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(responses, [late["before"]] + [c["response"] for c in late["checks"]] + [late["after"]])
        accepted = admission.read(self.args.output / admission.ADMISSION_NAME)
        self.assertEqual(accepted["original_states"], {"61":"no_response", "113":"no_response", "186":"no_response"})
        self.assertTrue(mcu.closed)
        self.assertTrue(ctrl.closed)


class RecoveryWindowTests(unittest.TestCase):
    def test_mcu_open_uses_inactive_reset_lines_without_extra_commands(self):
        runner = load_runner()
        serial_device = mock.Mock()
        events = []
        serial_device.open.side_effect = lambda: events.append((serial_device.port, serial_device.dtr, serial_device.rts))
        serial_module = SimpleNamespace(Serial=mock.Mock(return_value=serial_device))
        with mock.patch.dict(sys.modules, {"serial": serial_module}):
            link = runner.Link("COM13", Path("unused.jsonl"), "mcu")
        self.assertEqual(events, [("COM13", False, False)])
        serial_device.write.assert_not_called()
        serial_device.setDTR.assert_not_called()
        serial_device.setRTS.assert_not_called()
        link.close()

    def test_status_decision_survives_low_malformed_failed_or_unloggable_adc(self):
        cfg = {"adc_zero_volts": 0, "adc_volts_per_count": .0001, "rail_on_min_volts": 3.0}
        for problem in ("low", "malformed", "timeout", "logging"):
            with self.subTest(problem=problem):
                runner = load_runner()
                order = []
                link = mock.Mock()
                status = {"event": "status", "ready": True}
                link.request.side_effect = lambda *a, **kw: order.append("STATUS") or status
                ctrl = mock.Mock()

                def adc(*args, **kwargs):
                    self.assertEqual(order, ["STATUS"])
                    order.append("ADC")
                    if problem == "timeout":
                        raise TimeoutError("Pico observation timed out")
                    return {"event": "adc", "raw": float("nan") if problem == "malformed" else 0}

                ctrl.request.side_effect = adc

                def append(_path, row):
                    if problem == "logging" and row.get("event") == "rail_observation":
                        raise OSError("Observation log unavailable")

                with mock.patch.object(runner, "Link", return_value=link) as constructor, mock.patch.object(runner.time, "sleep"), mock.patch.object(runner, "append", side_effect=append):
                    got_link, got_status = runner.open_mcu(SimpleNamespace(mcu_port="COM13"), Path("unused.jsonl"), ctrl=ctrl, cfg=cfg)
                self.assertIs(got_link, link)
                self.assertIs(got_status, status)
                self.assertEqual(order, ["STATUS", "ADC"])
                constructor.assert_called_once()
                link.close.assert_not_called()

    def test_twenty_second_budget_is_not_extended_by_failed_open_retries(self):
        runner = load_runner()
        clock = [0.0]
        calls = []
        log = []
        enumerations = []
        query_times = []
        adc_times = []
        ctrl = mock.Mock()

        def adc(*args, **kwargs):
            adc_times.append(clock[0])
            clock[0] += .25
            raise TimeoutError("Read-only endpoint ADC timed out")

        ctrl.request.side_effect = adc

        def sleep(seconds):
            clock[0] += seconds

        def fail_open(*args):
            calls.append(clock[0])
            raise PermissionError("Windows port unavailable")

        def enumerate_ports():
            enumerations.append(clock[0])
            return []

        def query_dos_device(port):
            query_times.append(clock[0])
            self.assertEqual(port, "COM13")
            return {"status": "ok", "targets": ["mock USB serial device"]}

        with mock.patch.object(runner, "Link", side_effect=fail_open), mock.patch.object(runner.time, "monotonic", side_effect=lambda: clock[0]), mock.patch.object(runner.time, "sleep", side_effect=sleep), mock.patch.object(runner, "append", side_effect=lambda path, row: log.append(row)), mock.patch.object(admission, "port_snapshot", side_effect=enumerate_ports), mock.patch.object(admission, "query_dos_device", side_effect=query_dos_device):
            with self.assertRaisesRegex(TimeoutError, "recovery-attempt diagnostics"):
                runner.open_mcu(SimpleNamespace(mcu_port="COM13"), Path("unused.jsonl"), ctrl=ctrl, cfg={})
        self.assertGreaterEqual(clock[0], 20)
        self.assertEqual(len(adc_times), 1)
        self.assertGreaterEqual(adc_times[0], 20)
        self.assertLess(adc_times[0], 20.31)
        self.assertTrue(all(t < 20 for t in calls))
        failed = [row for row in log if row.get("event") == "mcu_recovery_attempt_failed"]
        self.assertEqual(len(failed), len(calls))
        self.assertTrue(all(row["stage"] == "open" and row["error_type"] == "PermissionError" for row in failed))
        self.assertEqual(log[-1]["event"], "mcu_recovery_deadline")
        self.assertEqual(log[-1]["recovery_window_seconds"], 20)
        self.assertEqual(len(enumerations), 1)
        self.assertGreaterEqual(enumerations[0], 20)
        self.assertEqual(len(query_times), 1)
        self.assertGreater(query_times[0], adc_times[0])
        self.assertGreaterEqual(query_times[0], 20)
        self.assertTrue(log[-1]["snapshot_after_deadline"])


class SleepGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.log = Path(self.temp.name) / "sleep.jsonl"
        self.setter = mock.Mock(return_value=0x80000000)
        self.windll = SimpleNamespace(kernel32=SimpleNamespace(SetThreadExecutionState=self.setter))

    def windows_patches(self):
        # Replace only the module's os object: changing global os.name on POSIX
        # would incorrectly make pathlib instantiate WindowsPath.
        return mock.patch.object(admission, "os", SimpleNamespace(name="nt")), mock.patch.object(admission.ctypes, "windll", self.windll, create=True)

    def test_sleep_guard_restores_request_on_exception(self):
        p1, p2 = self.windows_patches()
        with p1, p2:
            with self.assertRaisesRegex(RuntimeError, "simulated failure"):
                with admission.SleepGuard(self.log):
                    raise RuntimeError("simulated failure")
        self.assertEqual(self.setter.call_args_list, [mock.call(0x80000001), mock.call(0x80000000)])
        self.assertEqual([json.loads(x)["event"] for x in self.log.read_text().splitlines()], ["system_awake_requested", "system_awake_restored"])

    def test_sleep_guard_restores_if_logging_enter_fails(self):
        p1, p2 = self.windows_patches()
        with p1, p2, mock.patch.object(admission, "append", side_effect=OSError("disk error")):
            with self.assertRaisesRegex(OSError, "disk error"):
                with admission.SleepGuard(self.log):
                    self.fail("Body must not run")
        self.assertEqual(self.setter.call_args_list, [mock.call(0x80000001), mock.call(0x80000000)])

    def test_sleep_guard_refuses_when_system_request_fails(self):
        self.setter.return_value = 0
        p1, p2 = self.windows_patches()
        with p1, p2:
            with self.assertRaisesRegex(OSError, "SetThreadExecutionState failed"):
                with admission.SleepGuard(self.log):
                    self.fail("Body must not run")
        self.setter.assert_called_once_with(0x80000001)


if __name__ == "__main__":
    unittest.main()
