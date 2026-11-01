"""Software checks of evidence gates; these are not physical recovery results."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("powercut039_tested", HERE / "run_powercut039.py")
pc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pc)


def valid_config():
    cfg = json.loads((HERE / "powercut_config.example.json").read_text())
    for k, v in list(cfg.items()):
        if v is False:
            cfg[k] = True
    cfg.update(external_switch_model="verified external test switch",
               verification_notes="Scope-checked rail isolation and independently recorded divider calibration",
               adc_volts_per_count=3.3 / 32768, switch_to_rail_collapse_upper_us=5.0)
    return cfg


class PowercutTests(unittest.TestCase):
    def test_schedule_balanced_and_frozen(self):
        a = pc.make_trials()
        self.assertEqual(len(a), 200)
        self.assertEqual(a, pc.make_trials())
        self.assertNotEqual(a, pc.make_trials(seed=1))
        self.assertEqual({p: sum(x["phase"] == p for x in a) for p in pc.PHASES}, dict.fromkeys(pc.PHASES, 25))
        self.assertTrue(all(.05 <= x["phase_width_fraction"] <= .75 for x in a))

    def test_unconfigured_hardware_cannot_run(self):
        with self.assertRaisesRegex(ValueError, "Wiring is not ready"):
            pc.validate_wiring(json.loads((HERE / "powercut_config.example.json").read_text()))
        pc.validate_wiring(valid_config())
        cfg = valid_config()
        cfg["no_usb_vbus_bypass"] = False
        with self.assertRaisesRegex(ValueError, "no_usb_vbus_bypass"):
            pc.validate_wiring(cfg)

    def test_external_timing_claim_requires_bound_evidence_hash(self):
        cfg = valid_config()
        with self.assertRaisesRegex(ValueError, "timing evidence"):
            pc.validate_wiring(cfg, require_phase_timing=True)
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "waveform.json"
            f.write_text('{"test_fixture": true}')
            cfg["phase_timing_evidence_file"] = str(f)
            cfg["phase_timing_evidence_sha256"] = pc.digest(f)
            pc.validate_wiring(cfg, require_phase_timing=True)
            f.write_text("changed")
            with self.assertRaises(ValueError):
                pc.validate_wiring(cfg, require_phase_timing=True)

    def test_rail_proof_requires_persistent_off_not_single_low_sample(self):
        cfg = valid_config()
        event = {"rail_samples": [[0, 32000], [500, 100], [100000, 100], [1000000, 100]]}
        self.assertTrue(pc.rail_evidence(event, cfg)["rail_off_confirmed"])
        event["rail_samples"][-1][1] = 32000
        self.assertFalse(pc.rail_evidence(event, cfg)["rail_off_confirmed"])
        self.assertFalse(pc.rail_evidence({"rail_samples": [[0, 0], [100, 0]]}, cfg)["rail_off_confirmed"])
        with self.assertRaises(ValueError):
            pc.rail_evidence({"rail_samples": [[1, 0], [1, 0]]}, cfg)

    def test_unknown_identity_or_bad_decision_never_counts_as_valid(self):
        old = {"ready": True, "version": 7, "bundle_sha256": "old"}
        new = {"ready": True, "version": 8, "bundle_sha256": "new"}
        self.assertEqual(pc.classify_recovery(old, old, new, True), "old_valid")
        self.assertEqual(pc.classify_recovery(new, old, new, True), "new_valid")
        self.assertEqual(pc.classify_recovery(dict(new, bundle_sha256="old"), old, new), "unexpected_or_mixed")
        self.assertEqual(pc.classify_recovery(new, old, new, False), "unexpected_or_mixed")
        self.assertEqual(pc.classify_recovery({"ready": False}, old, new), "fail_closed")
        self.assertEqual(pc.classify_recovery(None, old, new), "no_response")

    def test_switch_latency_must_fit_inside_phase(self):
        cfg = valid_config()
        item = {"phase": "slot_commit", "phase_width_fraction": .75}
        delay, width = pc.trial_delay(item, {"slot_commit": [40, 42, 39]}, cfg, True)
        self.assertLess(delay + 3 + cfg["switch_to_rail_collapse_upper_us"], width)
        with self.assertRaisesRegex(ValueError, "shorter"):
            pc.trial_delay(item, {"slot_commit": [8, 9, 8]}, cfg, True)
        # Exploratory mode is permitted, but cannot manufacture a timing bound.
        self.assertEqual(pc.trial_delay(item, {"slot_commit": [8]}, cfg, False)[0], 0)

    def test_bundle_replay_reason_is_not_whole_image_reason(self):
        pc.validate_replay_rejection({"event": "update", "accepted": False, "reason": "replay_or_downgrade"})
        with self.assertRaises(RuntimeError):
            pc.validate_replay_rejection({"event": "update", "accepted": False, "reason": "non_monotonic_version"})
        with self.assertRaises(RuntimeError):
            pc.validate_replay_rejection({"event": "update", "accepted": True, "reason": "ok"})

    def test_candidate_role_depends_on_selected_parameters_not_version_parity(self):
        self.assertEqual(pc.next_role({"release": "p39A-5", "version": 5}), "B")
        self.assertEqual(pc.next_role({"release": "p39A-6", "version": 6}), "B")
        self.assertEqual(pc.next_role({"release": "p39B-7", "version": 7}), "A")

    def test_offline_flash_preparation_checks_phase_image_and_real_model(self):
        root = HERE.parents[1]
        prebuilt = root / "revision039/build/prebuilt/phase_gpio4/O2"
        if not (prebuilt / "mlp_float_bundle/metadata.json").is_file():
            self.skipTest("Optional phase prebuilt is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            pc.plan(SimpleNamespace(root=root,
                    model=root / "paper037/evidence_inputs/training/models/B_mlp_float.json",
                    model_a=root / "paper037/evidence_inputs/training/models/A_mlp_float.json",
                    prior_run=None, output=tmp / "plan", repeats_per_phase=1, seed=42,
                    allow_test_models=False))
            result = pc.flash(SimpleNamespace(root=root, plan=tmp / "plan", prebuilt_root=prebuilt,
                    port="NO_HARDWARE", board_id="esp32s3-a0f262ebb558", output=tmp / "flash",
                    prepare_only=True))
            self.assertEqual(result["status"], "prepared_not_flashed")
            self.assertFalse(result["hardware_access_attempted"])
            self.assertEqual(result["factory_model_identity"]["release"], "p39A-1")
            self.assertEqual(result["phase_gpio"], 4)
            self.assertNotEqual(result["template_image_sha256"], result["patched_image"]["image_sha256"])
            self.assertEqual(pc.read(tmp / "flash/summary.json"), result)

    def test_plan_signs_real_codec_and_checks_all_controls(self):
        root = HERE.parents[1]
        codec, reference = pc.dependencies(root)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            model = codec.bootstrap("mlp_float")
            src = tmp / "model.json"
            src.write_text(json.dumps(model))
            model_a = copy.deepcopy(model)
            model_a["layers"][-1]["bias"][0] = .25
            src_a = tmp / "model_a.json"
            src_a.write_text(json.dumps(model_a))
            output = tmp / "plan"
            args = SimpleNamespace(root=root, model=src, model_a=src_a, prior_run=None, output=output,
                                   repeats_per_phase=2, seed=42, allow_test_models=True)
            result = pc.plan(args)
            self.assertEqual(result["status"], "prepared_not_run")
            self.assertFalse(result["physical_power_loss_tested"])
            self.assertEqual(len(result["trials"]), 16)
            loaded, _, m, c = pc.load_plan(SimpleNamespace(plan=output))
            self.assertEqual(loaded["model_sha256"], pc.digest(output / "model.json"))
            self.assertEqual(len(c["raw"]), 12)
            b, meta = pc.candidate(m, codec, 123)
            self.assertEqual(meta["version"], 123)
            self.assertEqual(codec.envelope_metadata(b), meta)
            with self.assertRaises(FileExistsError):
                pc.plan(args)
            (output / "model.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                pc.load_plan(SimpleNamespace(plan=output))

    def test_changed_real_model_source_rejected_before_any_output(self):
        root = HERE.parents[1]
        codec, _ = pc.dependencies(root)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            a = codec.bootstrap("mlp_float")
            b = copy.deepcopy(a)
            b["threshold"] = .4
            pa, pb = tmp / "A.json", tmp / "B.json"
            pa.write_text(json.dumps(a))
            pb.write_text(json.dumps(b))
            output = tmp / "out"
            args = SimpleNamespace(root=root, model=pb, model_a=pa, prior_run=None, output=output,
                                   repeats_per_phase=1, seed=42, allow_test_models=False)
            with self.assertRaisesRegex(ValueError, "published frozen"):
                pc.plan(args)
            self.assertFalse(output.exists())

    def test_serialized_records_are_append_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "intent.json"
            pc.save_new(path, {"version": 1})
            with self.assertRaises(FileExistsError):
                pc.save_new(path, {"version": 2})
            self.assertEqual(pc.read(path)["version"], 1)


if __name__ == "__main__":
    unittest.main()
