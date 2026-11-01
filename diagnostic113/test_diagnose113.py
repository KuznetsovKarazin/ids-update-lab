"""No-hardware tests; real frozen incident fixtures are required locally."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
spec = importlib.util.spec_from_file_location("diagnose113_under_test", HERE / "diagnose113.py")
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


@unittest.skipUnless((ROOT / "incident113/run/results/trial_results.jsonl").is_file(),
                     "requires the original incident113 fixture")
class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.run = Path(self.temp.name) / "run"
        for relative in d.CASE_HASHES:
            target = self.run / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "incident113/run" / relative, target)
        self.before_hashes = {p: d.digest(self.run / p) for p in d.CASE_HASHES}
        self.runtime = d.load_runner(ROOT / "power046")
        self.incident = json.loads((self.run / "results/trial_results.jsonl").read_text().splitlines()[-1])
        self.controls = d.read(self.run / "plan/controls.json")
        self.args = SimpleNamespace(run=self.run, runner_dir=ROOT / "power046", mcu_port="COM13")
        self.commands = []
        self.opens = []

    def tearDown(self):
        self.assertEqual(self.before_hashes, {p: d.digest(self.run / p) for p in d.CASE_HASHES})
        self.temp.cleanup()

    def execute(self, role="old", open_error=False, mismatch=False, bad_control=None, close_error=False):
        initial = copy.deepcopy(self.incident["old"])
        if role == "candidate":
            initial.update({k: self.incident["candidate"][k] for k in d.MODEL_KEYS})
            initial.update(active_slot=0, selector_sequence=1045)
        if mismatch:
            initial["bundle_sha256"] = "0" * 64
        case = self
        class Link:
            def __init__(self, port, transcript, name):
                case.opens.append((port, name))
                if open_error:
                    raise PermissionError(13, "port unavailable")
                self.index = 0
                self.transcript = transcript
            def request(self, command, expected, timeout=5):
                case.commands.append(command)
                if command == "STATUS":
                    response = copy.deepcopy(initial)
                else:
                    index = self.index
                    self.index += 1
                    key = "A" if role == "candidate" else "B"
                    response = {k: initial[k] for k in ("version", "bundle_sha256", "runtime_abi", "policy", "pretransform")}
                    response.update(event="inference", **case.controls["expected"][key][index])
                    if index == bad_control:
                        response["probability"] = float("nan")
                with self.transcript.open("a") as stream:
                    stream.write(json.dumps({"direction": "tx", "line": command}) + "\n")
                    stream.write(json.dumps({"direction": "rx", "response": response}) + "\n")
                return response
            def close(self):
                if close_error:
                    raise OSError("close failed")
        with patch.object(d, "load_runner", return_value=self.runtime), \
             patch.object(self.runtime, "Link", Link), \
             patch.object(d, "serial_metadata", return_value={"version": "test"}), \
             patch.object(d, "host_snapshot", side_effect=lambda port, include_events=False: {"mock": True, "events": include_events}):
            return d.diagnose(self.args)

    def check_whitelist(self):
        self.assertTrue(all(c == "STATUS" or c.startswith("INFER ") for c in self.commands))
        self.assertEqual(self.opens, [("COM13", "mcu")])

    def test_old_model(self):
        report, out, archive = self.execute()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["late_recovery"], "old_valid")
        self.assertEqual(report["checks_passed"], 12)
        self.assertEqual(len(self.commands), 14)
        self.assertTrue(archive.is_file())
        self.assertTrue((out / "host_after.json").is_file())
        self.check_whitelist()

    def test_candidate_model(self):
        report, _, _ = self.execute(role="candidate")
        self.assertEqual(report["late_recovery"], "new_valid")
        self.assertEqual(report["checks_passed"], 12)
        self.check_whitelist()

    def test_unknown_model_stops_before_infer(self):
        report, _, _ = self.execute(mismatch=True)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(self.commands, ["STATUS"])
        self.check_whitelist()

    def test_open_error_is_single_attempt(self):
        report, out, archive = self.execute(open_error=True)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["failed_stage"], "serial_open")
        self.assertEqual(report["error"]["errno"], 13)
        self.assertEqual(self.commands, [])
        self.assertEqual(report["serial_open_attempts"], 1)
        self.assertTrue(archive.is_file())
        self.check_whitelist()

    def test_partial_and_nonfinite_evidence_preserved(self):
        report, out, _ = self.execute(bad_control=3)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(report["checks"]), 4)
        saved = d.read(out / "summary.json")
        self.assertEqual(saved["checks"][-1]["response"]["probability"], {"nonfinite_float": "nan"})
        self.check_whitelist()

    def test_close_error_saves_failed_result(self):
        report, out, _ = self.execute(close_error=True)
        self.assertEqual(report["status"], "failed")
        self.assertIn("close_error", d.read(out / "summary.json"))
        self.check_whitelist()

    def test_changed_input_blocks_serial(self):
        path = self.run / "plan/controls.json"
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        try:
            report, _, _ = self.execute()
            self.assertEqual(report["status"], "failed")
            self.assertEqual(self.opens, [])
            self.assertEqual(report["serial_open_attempts"], 0)
        finally:
            path.write_bytes(original)

    def test_pico_port_is_rejected_before_open(self):
        self.args.mcu_port = "COM5"
        with self.assertRaisesRegex(ValueError, "pinned to ESP32 COM13"):
            self.execute()
        self.assertEqual(self.opens, [])


if __name__ == "__main__":
    unittest.main()
