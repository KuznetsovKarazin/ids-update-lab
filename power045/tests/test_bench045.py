"""Offline safety/provenance checks. Original software: Oleksandr Kuznetsov."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SOURCE = Path(__file__).resolve().parents[1] / "bench045.py"
spec = importlib.util.spec_from_file_location("bench045", SOURCE)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
PROJECT = Path(__file__).resolve().parents[2]
KIT = next((p for p in (PROJECT / "revision040-kit", PROJECT / "restored045/revision040-kit", PROJECT) if p.is_dir()), PROJECT / "revision040-kit")


class FakeLink:
    commands = []
    info = {}
    raw_values = []
    fail_probe = False

    def __init__(self, *args, **kwargs): pass
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def request(self, command, event, timeout=5):
        self.commands.append(command)
        if command == "ID": return dict(self.info)
        if command == "ADC": return dict(event="adc", raw=self.raw_values.pop(0))
        if command == "PROBE 2000":
            if self.fail_probe: raise TimeoutError("simulated")
            return dict(event="probe_result", rail_samples=[[0, 0], [100000, 0], [1900000, 0]])
        return dict(event=event, power_on=(command == "ARM PHYSICAL"))


class BenchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        FakeLink.commands = []; FakeLink.info = {}; FakeLink.raw_values = []; FakeLink.fail_probe = False

    def disabled(self):
        b.init(argparse.Namespace(kit=KIT, output=self.root / "setup"))
        path = self.root / "setup/disabled_config.json"
        cfg = b.read(path)
        FakeLink.info = dict(event="controller_id", protocol=b.PROTOCOL, config_sha256=b.sha(path),
                             **{k: cfg[k] for k in ("enabled", "active_high_enable", "enable_pin", "phase_pin", "adc_pin")})
        return path

    def enabled(self):
        path = self.disabled()
        cfg = b.read(path)
        for key, _ in b.CHECKS: cfg[key] = True
        cfg.update(enabled=True, adc_calibration_verified=True, adc_volts_per_count=3.3/32768,
                   adc_zero_volts=0, external_switch_model="TPS22919EVM", verification_notes="Offline unit-test configuration; NOT physical validation")
        p = self.root / "reviewed.json"
        b.save(p, cfg)
        FakeLink.info.update(enabled=True, config_sha256=b.sha(p))
        return p

    def test_init_keeps_gate_disabled_and_controller_unchanged(self):
        p = self.disabled()
        self.assertFalse(b.read(p)["enabled"])
        self.assertEqual(b.sha(self.root / "setup/controller_main.py"), b.sha(KIT / "revision039/powercut/pico_power039.py"))
        self.assertFalse(p.read_bytes().startswith(b"\xef\xbb\xbf"))
        with self.assertRaises(FileExistsError): b.init(argparse.Namespace(kit=KIT, output=p.parent))

    def test_calibration_is_two_point_and_never_arms(self):
        p = self.disabled()
        FakeLink.raw_values = [100] * 64 + [32800] * 64
        out = self.root / "cal.json"
        with patch.object(b, "Link", FakeLink), patch("builtins.input", side_effect=["да", ".01", "да", "3.29", "1.645"]):
            b.calibrate(argparse.Namespace(port="TEST", config=p, output=out))
        r = b.read(out)
        self.assertNotIn("ARM PHYSICAL", FakeLink.commands)
        self.assertIn("DISARM", FakeLink.commands)
        self.assertAlmostEqual(r["adc_zero_volts"] + r["adc_volts_per_count"] * 32800, 3.29)
        self.assertEqual(len(r["on"]["raw"]), 64)
        self.assertEqual(r["config_sha256"], b.sha(p))

    def test_invalid_calibration_levels_rejected(self):
        for n0, n1, v0, v1 in [(0, 65535, 0, 3.3), (10000, 33000, 0, 3.3), (0, 33000, 1, 3.3), (0, 33000, 0, float("nan"))]:
            with self.assertRaises(ValueError): b.fit_calibration(dict(mean=n0), dict(mean=n1), v0, v1)

    def test_configuration_requires_each_check_and_does_not_arm(self):
        p = self.disabled(); cal = self.root / "cal.json"
        fit = b.fit_calibration(dict(mean=0), dict(mean=32768), 0, 3.3)
        b.save(cal, dict(schema="bench045_adc_calibration_v1", config_sha256=b.sha(p), off=dict(mean=0), on=dict(mean=32768), off_voltage=0, on_voltage=3.3, **fit))
        out = self.root / "reviewed.json"
        args = argparse.Namespace(port="TEST", config=p, calibration=cal, output=out, kit=KIT)
        with patch("builtins.input", return_value="нет"):
            with self.assertRaises(ValueError): b.configure(args)
        self.assertFalse(out.exists())
        FakeLink.raw_values = [0]*64
        with patch.object(b, "Link", FakeLink), patch("builtins.input", side_effect=["да"]*(len(b.CHECKS)+1)+["0.00", "0.00"]):
            b.configure(args)
        cfg = b.read(out)
        self.assertTrue(cfg["enabled"])
        self.assertFalse(cfg["phase_timing_verified"])
        self.assertNotIn("ARM PHYSICAL", FakeLink.commands)
        b.load_runner(KIT).validate_wiring(cfg)

    def test_probe_disarms_on_trace_timeout_and_preserves_failure(self):
        p = self.enabled()
        FakeLink.raw_values = [32768]*64
        FakeLink.fail_probe = True
        out = self.root / "probe"
        with patch.object(b, "Link", FakeLink), patch.object(b.time, "sleep"):
            with self.assertRaises(TimeoutError): b.probe(argparse.Namespace(port="TEST", config=p, output=out, kit=KIT))
        self.assertEqual(FakeLink.commands[-1], "DISARM")
        self.assertEqual(b.read(out / "summary.json")["status"], "failed")
        self.assertEqual(b.read(out / "summary.json")["error"], "simulated")

    def test_probe_success_is_not_phase_timing_claim(self):
        p = self.enabled()
        FakeLink.raw_values = [32768]*128
        out = self.root / "probe"
        with patch.object(b, "Link", FakeLink), patch.object(b.time, "sleep"):
            b.probe(argparse.Namespace(port="TEST", config=p, output=out, kit=KIT))
        result = b.read(out / "summary.json")
        self.assertEqual(result["status"], "complete")
        self.assertTrue(result["rail_evidence"]["rail_off_confirmed"])
        self.assertFalse(result["phase_timing_verified"])
        self.assertEqual(FakeLink.commands[-1], "DISARM")

    def test_stale_controller_config_blocks_arming(self):
        p = self.enabled(); FakeLink.info["config_sha256"] = "bad"
        with patch.object(b, "Link", FakeLink):
            with self.assertRaises(ValueError): b.probe(argparse.Namespace(port="TEST", config=p, output=self.root / "probe", kit=KIT))
        self.assertNotIn("ARM PHYSICAL", FakeLink.commands)
        self.assertEqual(FakeLink.commands[-1], "DISARM")

    def test_pack_contains_all_files_and_checksums_and_never_overwrites(self):
        src = self.root / "run"; src.mkdir()
        (src / "raw.bin").write_bytes(b"\0\1\xff")
        (src / "summary.json").write_text('{"status":"failed"}')
        out = self.root / "evidence.zip"
        args = argparse.Namespace(run=src, output=out)
        b.pack(args)
        with zipfile.ZipFile(out) as z:
            manifest = json.loads(z.read("MANIFEST045.json"))
            for row in manifest["files"]:
                self.assertEqual(hashlib.sha256(z.read(row["path"])).hexdigest(), row["sha256"])
            self.assertEqual(z.read("run/raw.bin"), b"\0\1\xff")
        self.assertEqual(out.with_name(out.name + ".sha256").read_text().split()[0], b.sha(out))
        with self.assertRaises(ValueError): b.pack(args)


if __name__ == "__main__": unittest.main()
