"""Synthetic validation, never TON/MCU evidence. Author: Oleksandr Kuznetsov."""
import argparse
from collections import Counter
import copy
import contextlib
import csv
import importlib.util
import json
import io
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest

import numpy as np

MODULE = Path(__file__).resolve().parents[1] / "run_science039.py"
REPO = MODULE.parents[2]
SPEC = importlib.util.spec_from_file_location("science039", MODULE)
s = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(s)


def protocol():
    edges = [i * 3600 for i in range(6)]
    intervals = {r: [[s.utc(edges[i]), s.utc(edges[i + 1])]] for i, r in enumerate(s.ROLES)}
    intervals["B_fit"] = intervals["A_fit"] + intervals["B_fit_added"]
    return s.protocol_from_intervals(intervals, "synthetic")


class ScienceTests(unittest.TestCase):
    def test_reused_training_end_to_end_on_synthetic_csv(self):
        """Real 030 sampler, four families, exports, SQLite evaluator; no TON claim."""
        training, _ = s.load_modules(REPO)
        rng = np.random.default_rng(39)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "synthetic.csv"
            with source.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([*training.FEATURES, "ts", "label", "type"])
                for role_index in range(5):
                    for i in range(240):
                        raw = rng.lognormal(1, .5, 8).astype(np.float32)
                        label = i % 2
                        raw[1] += label * 6
                        kind = "normal" if not label else "old" if role_index < 2 or (role_index == 4 and i % 4 == 1) else "new"
                        writer.writerow([*raw.tolist(), role_index * 3600 + 120 + i * 7, label, kind])
            stat = source.stat()
            provenance = {"path": str(source), "file": source.name, "ordinal": 0,
                          "bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns}
            before = s.sha(source)
            target = root / "run"
            for name in ("samples", "models", "hardware_vectors"):
                (target / name).mkdir(parents=True)
            with contextlib.redirect_stdout(io.StringIO()):
                arrays, support = training.prepare_data([provenance], protocol(), target, subset=True)
                models = training.fit_models(arrays, target)
                result = training.evaluate(models, support, target)
            self.assertEqual(result["test_rows"], 240)
            self.assertTrue(23 <= result["models_evaluated"] <= 24)
            self.assertEqual(s.sha(source), before)
            with np.load(target / "samples/A_cal.npz") as ac, np.load(target / "samples/B_fit.npz") as bf, np.load(target / "samples/B_cal.npz") as bc:
                self.assertFalse(np.intersect1d(ac["row_ids"], bf["row_ids"]).size)
                self.assertFalse(np.intersect1d(bc["row_ids"], bf["row_ids"]).size)
            evaluation = json.loads((target / "evaluation.json").read_text())
            self.assertGreater(evaluation["cohorts"]["attack_type_seen_in_A_fit"]["rows"]["B_lr"]["mass"], 0)
            self.assertGreater(evaluation["cohorts"]["attack_type_added_in_B_fit"]["rows"]["B_lr"]["mass"], 0)

    def test_chronology_and_no_calibration_in_training(self):
        p = protocol()
        s.validate_protocol(p)
        bad = copy.deepcopy(p)
        bad["intervals"]["B_fit"].append(bad["intervals"]["A_cal"][0])
        with self.assertRaisesRegex(ValueError, "exclude"):
            s.validate_protocol(bad)
        bad = copy.deepcopy(p)
        bad["intervals"]["B_cal"][0][0] = bad["intervals"]["B_fit_added"][0][0]
        with self.assertRaisesRegex(ValueError, "overlap"):
            s.validate_protocol(bad)

    def test_frozen_plan_tampering_stops_before_fit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan.json"
            document = {"schema": "revision039_science_plan_v1", "settings": s.SETTINGS,
                        "code_sha256": s.code_hashes(REPO)}
            s.write_json(path, document)
            path.with_suffix(".sha256").write_text(s.sha(path))
            self.assertEqual(s.verify_plan(path, REPO), document)
            document["settings"] = {**s.SETTINGS, "seed": 1}
            s.write_json(path, document)
            with self.assertRaisesRegex(ValueError, "hash differs"):
                s.verify_plan(path, REPO)

    def test_public_prior_rejects_modified_models_and_protocol(self):
        public = REPO / "paper037/evidence_inputs/training"
        protocol, models, provenance = s.verified_prior(REPO, public)
        self.assertEqual(len(models), 8)
        self.assertEqual(provenance["origin"], "pinned_public_models_and_original030_protocol")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy2(REPO / "release/provenance/MANIFEST_1.0.0_2da88c0.json", root / "MANIFEST.sha256.json")
            (root / "research030/protocol").mkdir(parents=True)
            protocol_path = root / "research030/protocol/coverage_selection.json"
            shutil.copy2(REPO / "research030/protocol/coverage_selection.json", protocol_path)
            prior = root / "prior"
            shutil.copytree(public / "models", prior / "models")
            model_path = prior / "models/B_lr.json"
            original = model_path.read_bytes()
            model_path.write_bytes(original + b"\n")
            with self.assertRaisesRegex(ValueError, "model mismatch"):
                s.verified_prior(root, prior)
            model_path.write_bytes(original)
            protocol_path.write_bytes(protocol_path.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "protocol mismatch"):
                s.verified_prior(root, prior)

    def test_completed_run_manifest_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            prior = Path(tmp)
            shutil.copytree(REPO / "paper037/evidence_inputs/training/models", prior / "models")
            lock = prior / "protocol_lock_before_data_and_predictions.json"
            s.write_json(lock, {"temporal_protocol": protocol()})
            pins = {"models/" + p.name: s.sha(p) for p in (prior / "models").glob("*.json")}
            pins[lock.name] = s.sha(lock)
            s.write_json(prior / "result_manifest.json", {"sha256": pins})
            self.assertEqual(s.verified_prior(REPO, prior)[2]["origin"], "completed_run_result_manifest")
            lock.write_bytes(lock.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "manifest mismatch"):
                s.verified_prior(REPO, prior)

    def test_missing_original_data_has_explicit_failed_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "missing_csv").mkdir()
            result = subprocess.run([sys.executable, str(MODULE), "plan", "--root", str(REPO),
                                     "--data-root", str(root / "missing_csv"), "--output", str(root / "out")],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            summary = json.loads((root / "out/summary.json").read_text())
            self.assertEqual(summary["status"], "failed")
            self.assertTrue(summary["models_or_measurements_not_claimed_complete"])
            self.assertTrue((root / "out/selection_rules_before_data.json").is_file())
            self.assertFalse((root / "out/plan.json").exists())

    def test_exact_coverage_csv_reuses_flow_purge(self):
        training, _ = s.load_modules(REPO)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.csv"
            rows = [
                # fit old; calibration old; added new; B calibration; future both.
                (100, 0, 1, "old"), (3800, 0, 1, "old"),
                (7400, 0, 1, "new"), (11000, 0, 0, "normal"),
                (14600, 0, 1, "old"), (14700, 0, 1, "new"),
                (14800, 0, 1, "unseen"),
                (3590, 0, 1, "purged_margin"),
                (3500, 100, 1, "purged_flow_end"),
                (14430, 0, 1, "purged_test_start"),
            ]
            with path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([*training.FEATURES, "ts", "label", "type"])
                for ts, duration, label, kind in rows:
                    writer.writerow([duration, 1, 2, 3, 4, 5, 6, 7, ts, label, kind])
            stat = path.stat()
            source = {"path": str(path), "file": path.name, "ordinal": 0,
                      "bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns}
            candidates = [{"id": "original030", "protocol": protocol()}]
            s.exact_candidate_counts(training, [source], candidates)
            coverage = candidates[0]["coverage"]
            self.assertEqual(coverage["future_attack_cohorts"],
                             {"known_A": 1, "added_B": 1, "fully_unexposed": 1, "calibration_exposed_only": 0})
            self.assertEqual(coverage["roles"]["A_fit"]["attack_types"], ["old"])
            self.assertNotIn("purged_test_start", coverage["roles"]["common_test"]["types"])
            self.assertFalse(candidates[0]["eligible"])

    def test_selection_old_plus_new_does_not_require_unseen(self):
        def candidate(name, known, added, unseen):
            return {"id": name, "protocol": protocol(), "eligible": True,
                    "coverage": {"future_attack_cohorts": {"known_A": known, "added_B": added, "fully_unexposed": unseen}}}
        original = candidate("original030", 0, 1001, 1001)
        mixed = candidate("mixed", 1001, 1001, 0)
        other = candidate("other", 0, 1001, 1001)
        # Distinct protocols, with original future start retained in other.
        mixed["protocol"]["intervals"]["A_fit"][0][0] = s.utc(-3600)
        other["protocol"]["intervals"]["A_fit"][0][0] = s.utc(-7200)
        self.assertEqual([v["id"] for v in s.select_scenarios([original, other, mixed])],
                         ["original030", "mixed", "other"])

    def test_threshold_rule_ties_float_and_integer(self):
        scores = np.r_[np.zeros(978), np.full(20, .9), np.ones(2)].astype(np.float32)
        before = scores.copy()
        cut = s.weighted_cut(scores, np.ones(1000, np.int64))
        self.assertEqual(cut, float(np.float32(.9)))
        self.assertEqual(s.score_metrics(scores, np.zeros(1000), cut)["FP"], 2)
        integer = np.r_[np.zeros(978), np.full(20, 21), np.full(2, 22)]
        self.assertEqual(s.weighted_cut(integer, np.ones(1000, np.int64), True), 22)
        np.testing.assert_array_equal(before, scores)
        with self.assertRaises(ValueError):
            s.weighted_cut(np.array([1.5]), np.array([1]), True)

    def test_weighted_cut_matches_expanded_observations(self):
        scores = np.array([0, 1, 2, 2, 3], np.float32)
        weights = np.array([100, 50, 10, 20, 1])
        expanded = np.repeat(scores, weights)
        self.assertEqual(s.weighted_cut(scores, weights), s.weighted_cut(expanded, np.ones(len(expanded), int)))

    def test_fast_holdout_metrics_match_direct_for_ties_and_empty_class(self):
        scores = np.array([0, 1, 1, 2, 3, 3], np.float32)
        for labels in (np.array([0, 0, 1, 1, 0, 1]), np.ones(6)):
            distribution = s.ScoreDistribution(scores, labels)
            for integer in (False, True):
                for cut in (-1, 0, 1, 1.5, 3, 4):
                    self.assertEqual(distribution.metrics(cut, integer), s.score_metrics(scores, labels, cut, integer))

    def test_block_bootstrap_keeps_whole_blocks_and_is_reproducible(self):
        # Two distinct score blocks. Drawing [high, high] or [low, low] must be
        # possible; row-level resampling almost never omits the high block.
        scores = np.r_[np.zeros(100), np.ones(100)].astype(np.float32)
        times = np.r_[np.full(100, 1.), np.full(100, 61.)]
        one = s.bootstrap_thresholds(scores, times, repeats=100, block_minutes=1, interval=(0, 120))
        two = s.bootstrap_thresholds(scores, times, repeats=100, block_minutes=1, interval=(0, 120))
        self.assertEqual(one, two)
        self.assertEqual(set(one["cuts"]), {0.0, 1.0})
        self.assertEqual(one["occupied_blocks"], 2)
        self.assertEqual(one["empty_draws"], 0)

    def test_longer_windows_purge_crossing_flows_and_share_holdout(self):
        # Row at 3400 spills past first effective end (3540), so is excluded
        # there and included in the second window. Holdout metrics are never
        # used to choose the normal-score order statistic.
        scores = np.array([.1, .2, .9, .3], np.float32)
        times = np.array([100, 200, 3400, 4000], float)
        ends = np.array([100, 200, 3600, 4000], float)
        reports = s.summarize_scores(scores, times, ends, np.array([.1, .5]), np.array([0, 1]),
                                     0, [3600, 7200], repeats=10, blocks=(15,))
        self.assertEqual([r["normal_rows"] for r in reports], [2, 4])
        self.assertEqual([r["common_holdout"]["normal"] for r in reports], [1, 1])
        self.assertEqual(reports[0]["cut"], float(np.float32(.2)))
        self.assertEqual(reports[1]["cut"], float(np.float32(.9)))

    def test_cli_score_fixture_and_fresh_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "scores.npz"
            np.savez(source, cal_scores=np.array([.1, .2, .3], np.float32), cal_ts=np.array([100, 200, 4000]),
                     cal_end=np.array([100, 200, 4000]), test_scores=np.array([.2, .8], np.float32),
                     test_labels=np.array([0, 1]), test_ts=np.array([8000, 8100]), cal_start=np.array(0),
                     cal_ends=np.array([3600, 7200]), integer=np.array(False))
            digest = s.sha(source)
            command = [sys.executable, str(MODULE), "threshold", "--scores", str(source), "--repeats", "8", "--output", str(root / "out")]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads((root / "out/summary.json").read_text())
            self.assertEqual(summary["status"], "complete_score_analysis")
            self.assertEqual(digest, s.sha(source))
            manifest = s.sha(root / "out/result_manifest.json")
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(manifest, s.sha(root / "out/result_manifest.json"))

    def test_cli_rejects_temporal_leakage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "scores.npz"
            np.savez(source, cal_scores=np.array([.1]), cal_ts=np.array([100]), cal_end=np.array([100]),
                     test_scores=np.array([.2]), test_labels=np.array([0]), test_ts=np.array([1000]),
                     cal_start=np.array(0), cal_ends=np.array([3600]), integer=np.array(False))
            result = subprocess.run([sys.executable, str(MODULE), "threshold", "--scores", str(source),
                                     "--output", str(root / "out")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("holdout", json.loads((root / "out/summary.json").read_text())["error"])


if __name__ == "__main__":
    unittest.main()
