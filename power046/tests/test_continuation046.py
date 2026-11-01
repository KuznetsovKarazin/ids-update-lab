"""Independent incident046 admission tests; never access hardware.

Integration fixtures are supplied explicitly, not bundled:
  POWER046_INCIDENT_RUN=/path/to/extracted/run
  POWER046_LATE_RECOVERY=/path/containing/summary.json/and/serial.jsonl
Missing fixtures skip only the fixture-dependent class with an explicit reason.
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

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))
import continuation046 as admission


def load_runner():
    spec = importlib.util.spec_from_file_location("independent_runner046", PACKAGE / "run_powercut046.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeMcu:
    def __init__(self, diagnostic):
        self.diagnostic = copy.deepcopy(diagnostic)
        self.commands = []
        self.infer_index = 0
        self.closed = False

    def request(self, command, expected, timeout=5):
        self.commands.append(command)
        if command.startswith("INFER "):
            result = self.diagnostic["checks"][self.infer_index]["response"]
            self.infer_index += 1
            return copy.deepcopy(result)
        if command == "STATUS":
            return copy.deepcopy(self.diagnostic["after"])
        if command == "PHASE_DISARM":
            return {"event": "phase_control", "ok": True, "enabled": False}
        raise AssertionError("Unexpected MCU command: " + command)

    def close(self):
        self.closed = True


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = os.environ.get("POWER046_INCIDENT_RUN")
        late = os.environ.get("POWER046_LATE_RECOVERY")
        if not source or not late:
            raise unittest.SkipTest("Set POWER046_INCIDENT_RUN and POWER046_LATE_RECOVERY to run incident evidence tests")
        cls.source = Path(source).resolve()
        cls.late_source = Path(late).resolve()
        if not (cls.source / "results/trial_results.jsonl").is_file():
            raise RuntimeError("POWER046_INCIDENT_RUN is not the extracted run directory")
        if not all((cls.late_source / name).is_file() for name in ("summary.json", "serial.jsonl")):
            raise RuntimeError("POWER046_LATE_RECOVERY must contain both reviewed diagnostic files")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.run = self.base / "run"
        shutil.copytree(self.source, self.run)
        self.late = self.base / "late"
        self.late.mkdir()
        for name in ("summary.json", "serial.jsonl"):
            shutil.copyfile(self.late_source / name, self.late / name)
        self.kit = self.base / "kit"
        source_target = self.kit / "revision039/powercut/run_powercut039.py"
        source_target.parent.mkdir(parents=True)
        shutil.copyfile(self.run / "diagnostics-20261027-103428/run_powercut039.py", source_target)
        self.args = SimpleNamespace(
            root=self.kit, output=self.run / "results", config=self.run / "setup/powercut_config.json",
            preflight=self.run / "preflight", plan=self.run / "plan", board_id=admission.BOARD_ID,
            allow_unconfirmed_phase_timing=True, resume=True, late_recovery=self.late,
            prepare_only=False, mcu_port="COM13", controller_port="COM5",
        )
        self.plan_path = self.run / "plan/plan.json"
        self.plan = admission.read(self.plan_path)
        self.controls = admission.read(self.run / "plan/controls.json")
        self.prior = [json.loads(line) for line in (self.run / "results/trial_results.jsonl").read_text().splitlines()]
        self.diagnostic = admission.read(self.late / "summary.json")

    def review(self):
        return admission.validate_evidence(self.args, self.prior, self.controls, self.plan_path)

    def source_hashes(self):
        return {str(p.relative_to(self.run)): admission.digest(p) for p in self.run.rglob("*") if p.is_file()}

    def test_offline_admission_is_read_only_and_preserves_endpoint(self):
        before = self.source_hashes()
        review = self.review()
        self.assertEqual(before, self.source_hashes())
        self.assertEqual(review["original_state"], "no_response")
        self.assertEqual(review["late_state"], "old_valid")
        self.assertTrue(review["late_state_is_not_original_endpoint"])
        self.assertEqual((review["first_continued_trial"], review["remaining_trials"]), (62, 139))
        self.assertEqual(review["protocol_epoch"]["recovery_window_seconds"], 20)

    def test_rejects_changed_original_trial_log(self):
        with (self.run / "results/trial_results.jsonl").open("ab") as stream:
            stream.write(b"\n")
        with self.assertRaisesRegex(ValueError, "Original incident evidence"):
            self.review()

    def test_rejects_changed_late_summary(self):
        with (self.late / "summary.json").open("ab") as stream:
            stream.write(b" ")
        with self.assertRaisesRegex(ValueError, "Late diagnostic files"):
            self.review()

    def test_rejects_changed_late_serial(self):
        with (self.late / "serial.jsonl").open("ab") as stream:
            stream.write(b"\n")
        with self.assertRaisesRegex(ValueError, "Late diagnostic files"):
            self.review()

    def test_rejects_other_unsafe_original_result(self):
        self.prior[20]["state"] = "unexpected_or_mixed"
        with self.assertRaisesRegex(ValueError, "Only the investigated"):
            self.review()

    def test_rejects_reclassifying_original_61(self):
        self.prior[-1]["state"] = "old_valid"
        with self.assertRaisesRegex(ValueError, "Only the investigated"):
            self.review()

    def test_rejects_later_intent_without_replay(self):
        (self.run / "results/trial_062_intent.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "Later trial intents"):
            self.review()

    def test_rejects_duplicate_admission(self):
        (self.run / "results" / admission.ADMISSION_NAME).write_text("{}")
        with self.assertRaisesRegex(ValueError, "already been"):
            self.review()

    def test_rejects_wrong_board_or_timing_protocol(self):
        for change in ({"board_id": "different-board"}, {"allow_unconfirmed_phase_timing": False}):
            with self.subTest(change=change):
                args = copy.copy(self.args)
                vars(args).update(change)
                with self.assertRaisesRegex(ValueError, "original board and timing"):
                    admission.validate_evidence(args, self.prior, self.controls, self.plan_path)

    def test_rejects_installed_runner_change(self):
        (self.kit / "revision039/powercut/run_powercut039.py").write_text("raise RuntimeError('changed')")
        with self.assertRaisesRegex(ValueError, "Installed revision039 runner differs"):
            self.review()

    def test_serial_validator_rejects_update_even_with_matching_summary(self):
        path = self.late / "untrusted.jsonl"
        data = (self.late / "serial.jsonl").read_text()
        data += json.dumps({"direction": "tx", "link": "mcu", "line": "UPDATE 00"}) + "\n"
        path.write_text(data)
        with self.assertRaisesRegex(ValueError, "command sequence"):
            admission.verify_serial(path, self.diagnostic, self.controls)

    def test_serial_validator_checks_raw_bytes_not_just_parsed_reply(self):
        path = self.late / "untrusted.jsonl"
        rows = [json.loads(line) for line in (self.late / "serial.jsonl").read_text().splitlines()]
        rows = [row for row in rows if row.get("direction") != "rx_bytes"]
        path.write_text("\n".join(json.dumps(row) for row in rows))
        with self.assertRaisesRegex(ValueError, "raw USB bytes"):
            admission.verify_serial(path, self.diagnostic, self.controls)

    def test_live_verification_only_issues_twelve_infer_and_status(self):
        mcu = FakeMcu(self.diagnostic)
        result = admission.verify_live(mcu, self.diagnostic["before"], self.review(), self.controls)
        self.assertEqual(mcu.commands, admission.expected_commands(self.controls)[1:])
        self.assertEqual(result["checks_passed"], 12)
        self.assertFalse(result["flash_mutation_attempted"])
        self.assertFalse(result["power_control_attempted"])

    def test_live_bad_initial_identity_stops_before_any_command(self):
        mcu = FakeMcu(self.diagnostic)
        bad = copy.deepcopy(self.diagnostic["before"])
        bad["selector_sequence"] += 1
        with self.assertRaisesRegex(ValueError, "Live model differs"):
            admission.verify_live(mcu, bad, self.review(), self.controls)
        self.assertEqual(mcu.commands, [])

    def test_live_bad_probability_is_rejected_without_power_or_flash(self):
        mcu = FakeMcu(self.diagnostic)
        mcu.diagnostic["checks"][4]["response"]["probability"] = float("nan")
        with self.assertRaisesRegex(ValueError, "control mismatch"):
            admission.verify_live(mcu, self.diagnostic["before"], self.review(), self.controls)
        self.assertTrue(all(command.startswith("INFER ") for command in mcu.commands))

    def test_live_identity_change_after_controls_is_rejected(self):
        mcu = FakeMcu(self.diagnostic)
        mcu.diagnostic["after"]["active_slot"] = 0
        with self.assertRaisesRegex(ValueError, "identity changed"):
            admission.verify_live(mcu, self.diagnostic["before"], self.review(), self.controls)
        self.assertEqual(mcu.commands, admission.expected_commands(self.controls)[1:])

    def fake_codec(self):
        return SimpleNamespace(ABI={"mlp_float": 4}, SCHEMA=bytes.fromhex(self.diagnostic["before"]["schema"]))

    def test_runner_prepare_only_never_opens_ports_or_changes_originals(self):
        runner = load_runner()
        self.args.prepare_only = True
        before = self.source_hashes()
        with mock.patch.object(runner, "dependencies", return_value=(self.fake_codec(), None)), mock.patch.object(runner, "Link", side_effect=AssertionError("Hardware accessed")):
            result = runner.run(self.args)
        self.assertEqual(result["status"], "prepared_not_run")
        self.assertFalse(result["hardware_access_attempted"])
        self.assertEqual(before, self.source_hashes())

    def test_runner_tampered_evidence_stops_before_hardware_and_writes(self):
        runner = load_runner()
        with (self.late / "summary.json").open("a") as stream:
            stream.write(" ")
        before = self.source_hashes()
        with mock.patch.object(runner, "dependencies", return_value=(self.fake_codec(), None)), mock.patch.object(runner, "Link", side_effect=AssertionError("Hardware accessed")), mock.patch.object(runner, "install", side_effect=AssertionError("Flash update reached")):
            with self.assertRaisesRegex(ValueError, "Late diagnostic files"):
                runner.run(self.args)
        self.assertEqual(before, self.source_hashes())

    def test_runner_live_mismatch_never_opens_controller_or_updates(self):
        runner = load_runner()
        mcu = FakeMcu(self.diagnostic)
        wrong = copy.deepcopy(self.diagnostic["before"])
        wrong["selector_sequence"] += 1
        original = (self.run / "results/trial_results.jsonl").read_bytes()
        with mock.patch.object(runner, "dependencies", return_value=(self.fake_codec(), None)), mock.patch.object(runner, "open_mcu", return_value=(mcu, wrong)), mock.patch.object(runner, "Link", side_effect=AssertionError("Controller accessed")), mock.patch.object(runner, "install", side_effect=AssertionError("Flash update reached")), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "Live model differs"):
                runner.run(self.args)
        self.assertEqual(original, (self.run / "results/trial_results.jsonl").read_bytes())
        self.assertFalse((self.run / "results" / admission.ADMISSION_NAME).exists())
        self.assertEqual(mcu.commands, [])
        self.assertTrue(mcu.closed)

    def test_failed_first_live_attempt_blocks_second_start_before_hardware(self):
        runner = load_runner()
        mcu = FakeMcu(self.diagnostic)
        wrong = copy.deepcopy(self.diagnostic["before"])
        wrong["selector_sequence"] += 1
        with mock.patch.object(runner, "dependencies", return_value=(self.fake_codec(), None)), mock.patch.object(runner, "open_mcu", return_value=(mcu, wrong)), mock.patch.object(runner, "Link", side_effect=AssertionError("Controller accessed")), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "Live model differs"):
                runner.run(self.args)
        self.assertTrue((self.args.output / admission.ATTEMPT_NAME).is_file())
        self.assertFalse((self.args.output / admission.ADMISSION_NAME).exists())
        before_second = self.source_hashes()
        with mock.patch.object(runner, "dependencies", return_value=(self.fake_codec(), None)), mock.patch.object(runner, "open_mcu", side_effect=AssertionError("MCU accessed again")), mock.patch.object(runner, "Link", side_effect=AssertionError("Controller accessed")):
            with self.assertRaisesRegex(ValueError, "already been attempted"):
                runner.run(self.args)
        self.assertEqual(before_second, self.source_hashes())

    def test_close_failure_still_saves_summary_and_restores_sleep_guard(self):
        runner = load_runner()
        mcu = FakeMcu(self.diagnostic)
        mcu.close = mock.Mock(side_effect=OSError("injected close failure"))
        wrong = copy.deepcopy(self.diagnostic["before"])
        wrong["selector_sequence"] += 1
        guard = mock.MagicMock()
        before_summaries = set(self.args.output.glob("summary_*.json"))
        with mock.patch.object(runner, "dependencies", return_value=(self.fake_codec(), None)), mock.patch.object(runner, "open_mcu", return_value=(mcu, wrong)), mock.patch.object(runner, "Link", side_effect=AssertionError("Controller accessed")), mock.patch.object(admission, "SleepGuard", return_value=guard), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "Live model differs"):
                runner.run(self.args)
        guard.__enter__.assert_called_once()
        guard.__exit__.assert_called_once()
        new_summaries = set(self.args.output.glob("summary_*.json")) - before_summaries
        self.assertEqual(len(new_summaries), 1)
        summary = admission.read(new_summaries.pop())
        self.assertEqual(summary["status"], "failed")
        self.assertIn("Live model differs", summary["error"])
        self.assertEqual(summary["cleanup_errors"][0]["operation"], "mcu_close")
        self.assertIn("injected close failure", summary["cleanup_errors"][0]["error"])
        self.assertEqual(mcu.commands, [])

    def test_runner_skips_original61_and_versions_start_above750(self):
        runner = load_runner()
        mcu = FakeMcu(self.diagnostic)
        original = (self.run / "results/trial_results.jsonl").read_bytes()
        cfg = admission.read(self.args.config)
        preparation_versions = []
        signed_versions = []
        control_commands = []
        phase_calls = []

        class StopBeforeSigning(RuntimeError):
            pass

        class FakeController:
            closed = False

            def request(inner, command, expected, timeout=5):
                control_commands.append(command)
                if command == "ID":
                    # Live controls must have completed BEFORE controller access.
                    self.assertEqual(mcu.infer_index, 12)
                    self.assertEqual(mcu.commands[-1], "STATUS")
                    return dict(protocol=runner.PROTOCOL, enabled=True, config_sha256=admission.digest(self.args.config),
                                **{k: cfg[k] for k in ("enable_pin", "phase_pin", "adc_pin")})
                if command == "ARM PHYSICAL":
                    return {"event": "armed"}
                if command.startswith("CUT "):
                    return {"event": "phase_armed"}
                if command == "ON":
                    return {"event": "power_on"}
                raise AssertionError(command)

            def close(inner):
                inner.closed = True

        ctrl = FakeController()

        def install(_mcu, model, codec, status, output, label, version=None):
            preparation_versions.append(version)
            new_status = dict(status, version=version, release=f"p39A-{version}", bundle_sha256="synthetic")
            return new_status, {}

        def candidate(model, codec, version, role):
            signed_versions.append(version)
            raise StopBeforeSigning("stop before new signed UPDATE")

        def link(port, transcript, name):
            self.assertEqual((port, name), ("COM5", "pico"))
            return ctrl

        def phase_arm(_mcu, phase, _cfg):
            phase_calls.append(phase)

        with mock.patch.object(runner, "dependencies", return_value=(self.fake_codec(), None)), mock.patch.object(runner, "open_mcu", return_value=(mcu, copy.deepcopy(self.diagnostic["before"]))), mock.patch.object(runner, "Link", side_effect=link), mock.patch.object(runner, "install", side_effect=install), mock.patch.object(runner, "candidate", side_effect=candidate), mock.patch.object(runner, "phase_arm", side_effect=phase_arm), mock.patch.object(runner.time, "sleep"), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(StopBeforeSigning, "stop before new signed"):
                runner.run(self.args)
        self.assertEqual(preparation_versions, [751, 752])
        self.assertEqual(signed_versions, [753])
        self.assertEqual(phase_calls, [self.plan["trials"][61]["phase"]])
        cuts = [cmd for cmd in control_commands if cmd.startswith("CUT ")]
        self.assertEqual(len(cuts), 1)
        self.assertTrue(cuts[0].startswith("CUT trial-062 "))
        self.assertEqual(original, (self.run / "results/trial_results.jsonl").read_bytes())
        accepted = admission.read(self.run / "results" / admission.ADMISSION_NAME)
        self.assertEqual(accepted["original_state"], "no_response")
        self.assertEqual(accepted["late_state"], "old_valid")
        self.assertTrue(ctrl.closed)
        self.assertTrue(mcu.closed)


class RecoveryWindowTests(unittest.TestCase):
    def test_twenty_second_budget_is_not_extended_by_failed_open_retries(self):
        runner = load_runner()
        clock = [0.0]
        calls = []
        log = []
        enumerations = []

        def sleep(seconds):
            clock[0] += seconds

        def fail_open(*args):
            calls.append(clock[0])
            raise PermissionError("Windows port unavailable")

        def enumerate_ports():
            enumerations.append(clock[0])
            return []

        with mock.patch.object(runner, "Link", side_effect=fail_open), mock.patch.object(runner.time, "monotonic", side_effect=lambda: clock[0]), mock.patch.object(runner.time, "sleep", side_effect=sleep), mock.patch.object(runner, "append", side_effect=lambda path, row: log.append(row)), mock.patch.object(admission, "port_snapshot", side_effect=enumerate_ports):
            with self.assertRaisesRegex(TimeoutError, "recovery-attempt diagnostics"):
                runner.open_mcu(SimpleNamespace(mcu_port="COM13"), Path("unused.jsonl"))
        self.assertGreaterEqual(clock[0], 20)
        self.assertLess(clock[0], 20.31)
        self.assertTrue(all(t < 20 for t in calls))
        failed = [row for row in log if row.get("event") == "mcu_recovery_attempt_failed"]
        self.assertEqual(len(failed), len(calls))
        self.assertTrue(all(row["stage"] == "open" and row["error_type"] == "PermissionError" for row in failed))
        self.assertEqual(log[-1]["event"], "mcu_recovery_deadline")
        self.assertEqual(log[-1]["recovery_window_seconds"], 20)
        self.assertEqual(len(enumerations), 1)
        self.assertGreaterEqual(enumerations[0], 20)
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
