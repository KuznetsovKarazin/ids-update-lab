"""Synthetic schema/statistics tests; no data are represented as MCU evidence.

Original software author: Oleksandr Kuznetsov.
"""
import copy
import importlib.util
import itertools
from pathlib import Path
import tempfile
import unittest

import numpy as np

SPEC = importlib.util.spec_from_file_location("cost_analysis039", Path(__file__).resolve().parents[1] / "analyze_costs039.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
BOARD = "esp32s3-001122334455"


def synthetic_summary(board=BOARD):
    """Construct all 240 schema fixtures, not measured experiment results."""
    rows = []
    for block, family, policy, transition in sorted(M.EXPECTED_CELLS):
        active = block * 1000 + {"bundle": 10, "whole": 100, "compressed": 60}[policy]
        row = {"block": block, "family": family, "policy": policy, "transition": transition,
               "board_id": board, "version": M.TRANSITIONS[transition], "measured": True,
               "device_active_us": active, "host_elapsed_ns": active * 2000,
               "artifact_bytes": 448 if policy == "bundle" else (10000 if policy == "whole" else 6000) + 340,
               "tx_wire_bytes": 1000 if policy == "bundle" else 22000}
        if policy == "bundle":
            row.update(model_erase_bytes=4096, model_write_bytes=456, journal_erase_bytes=0,
                       journal_write_bytes=128, response={"timing_us": {"total": active}})
        else:
            row.update(raw_image_bytes=10000, encoded_bytes=10000 if policy == "whole" else 6000,
                       image_partition_erase_bytes=12288, image_partition_write_bytes=10000,
                       otadata_flash_work_included=False, ready={"device_active_us": active})
        rows.append(row)
    return {"stage": "039", "status": "complete", "board_id": board,
            "measurement_origin": "actual_mcu", "hardware_access_attempted": True,
            "expected_measured_observations": 240, "completed_trials": 120,
            "cost_observations": rows}


def pin(directory):
    M.save(directory / "evidence_manifest.json", {"sha256": {
        p.relative_to(directory).as_posix(): M.sha(p) for p in directory.rglob("*")
        if p.is_file() and p.name != "evidence_manifest.json"}})


def write_run(campaign, board=BOARD, optimization="Og", summary=None):
    prepared = campaign / "prepared" / ("costs-" + optimization)
    if not prepared.is_dir():
        prepared.mkdir(parents=True)
        M.save(prepared / "artifacts.json", {"stage": "039", "families": {
            family: {"policies": {policy: {"build_metadata": {
                "stage": "039", "family": family, "policy": policy, "optimization": optimization,
                "phase_gpio": None}} for policy in ("bundle", "whole")}} for family in M.FAMILIES}})
        pin(prepared)
    directory = campaign / "mcu" / board / optimization / "costs"
    directory.mkdir(parents=True)
    M.save(directory / "summary.json", summary if summary is not None else synthetic_summary(board))
    M.save(directory / "plan.json", {"stage": "039", "board_id": board,
           "artifact_manifest_sha256": M.sha(prepared / "evidence_manifest.json"),
           "plan": [{"block": b, "family": f, "policy": p}
                    for b, f, p in itertools.product(M.BLOCKS, M.FAMILIES, M.POLICIES)]})
    pin(directory)
    return directory


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_missing_completed_block_is_rejected(self):
        summary = synthetic_summary()
        summary["cost_observations"].pop()
        with self.assertRaisesRegex(ValueError, "missing measured block"):
            M.validate_summary(summary, BOARD)

    def test_duplicate_block_is_rejected_even_in_incomplete_run(self):
        summary = synthetic_summary()
        summary["status"] = "failed"
        summary["cost_observations"].append(copy.deepcopy(summary["cost_observations"][0]))
        with self.assertRaisesRegex(ValueError, "Duplicate measured block"):
            M.validate_summary(summary, BOARD)

    def test_failed_acquisition_reports_missing_without_partial_estimates(self):
        summary = synthetic_summary()
        summary["status"] = "failed"
        summary["completed_trials"] = 119
        summary["cost_observations"].pop()
        write_run(self.root, summary=summary)
        result = M.analyze_campaign(self.root)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(len(result["missing_cells"]), 241)  # one Og cell and all O2 cells
        self.assertEqual(result["policy_summary"], [])
        self.assertEqual(result["paired_comparisons"], [])
        self.assertEqual(result["runs"][0]["observations"], 239)

    def test_median_of_paired_differences_is_not_difference_of_medians(self):
        left_values = [0, 0, 0, 0, 0, 100, 100, 100, 100, 100]
        right_values = [0, 0, 0, 0, 100, 100, 100, 100, 100, 100]
        result = M.paired_statistics(dict(zip(M.BLOCKS, left_values)), dict(zip(M.BLOCKS, right_values)))
        self.assertEqual(result["paired_median_difference"], 0)
        self.assertEqual(float(np.median(left_values) - np.median(right_values)), -50)

    def test_paired_bootstrap_keeps_shared_block_noise(self):
        right = {b: float(b * b * 100) for b in M.BLOCKS}
        left = {b: value + 7 for b, value in right.items()}
        result = M.paired_statistics(left, right)
        self.assertEqual((result["paired_median_difference"], result["ci95_low"], result["ci95_high"]), (7, 7, 7))
        self.assertEqual(result["bootstrap_draws"], 10000)
        self.assertEqual(result, M.paired_statistics(left, right))
        with self.assertRaisesRegex(ValueError, "same ten complete"):
            M.paired_statistics(left, {b: value for b, value in right.items() if b != 10})

    def test_source_tamper_rejected(self):
        directory = write_run(self.root)
        with (directory / "summary.json").open("a") as stream:
            stream.write("\n")
        with self.assertRaisesRegex(ValueError, "Evidence SHA256 mismatch"):
            M.analyze_campaign(self.root)

    def test_optimization_is_verified_from_artifact_metadata(self):
        directory = write_run(self.root)
        prepared = self.root / "prepared/costs-Og"
        artifacts = M.read(prepared / "artifacts.json")
        artifacts["families"]["lr"]["policies"]["bundle"]["build_metadata"]["optimization"] = "O2"
        M.save(prepared / "artifacts.json", artifacts)
        pin(prepared)
        plan = M.read(directory / "plan.json")
        plan["artifact_manifest_sha256"] = M.sha(prepared / "evidence_manifest.json")
        M.save(directory / "plan.json", plan)
        pin(directory)
        with self.assertRaisesRegex(ValueError, "build metadata disagrees"):
            M.analyze_campaign(self.root)

    def test_complete_run_has_separate_timing_and_flash_scopes(self):
        write_run(self.root)
        result = M.analyze_campaign(self.root)
        self.assertEqual(result["status"], "incomplete")  # O2 and second board not run
        self.assertEqual(len(result["observations"]), 240)
        times = [r for r in result["policy_summary"] if r["family"] == "lr" and r["transition"] == "A_to_B_reused" and r["policy"] == "bundle"]
        metrics = {r["metric"]: r for r in times}
        self.assertAlmostEqual(metrics["handler_active_ms"]["median"], 5.51)
        self.assertAlmostEqual(metrics["usb_total_ms"]["median"], 11.02)
        self.assertIn("journal_write_bytes", metrics)
        self.assertNotIn("image_partition_write_bytes", metrics)
        comparison = next(r for r in result["paired_comparisons"] if r["family"] == "lr" and r["transition"] == "A_to_B_reused" and r["policy"] == "bundle" and r["reference_policy"] == "whole" and r["metric"] == "handler_active_ms")
        self.assertAlmostEqual(comparison["paired_median_difference"], -.09)
        self.assertEqual(comparison["n_pairs"], 10)
        self.assertFalse(result["all_reviewer_experiments_complete"])

    def test_cli_writes_fresh_outputs_and_no_measurements_for_empty_campaign(self):
        campaign = self.root / "campaign"
        campaign.mkdir()
        out = self.root / "analysis"
        self.assertEqual(M.main(["--campaign", str(campaign), "--output", str(out)]), 0)
        result = M.read(out / "analysis.json")
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["additional_distinct_boards_required"], 2)
        self.assertEqual(result["observations"], [])
        self.assertTrue((out / "policy_summary.csv").is_file())
        self.assertEqual(len((out / "policy_summary.csv").read_text().splitlines()), 1)
        for name, digest in M.read(out / "result_manifest.json")["sha256"].items():
            self.assertEqual(M.sha(out / name), digest)
        with self.assertRaises(FileExistsError):
            M.main(["--campaign", str(campaign), "--output", str(out)])

    def test_two_boards_and_builds_remain_separate_in_complete_cli_output(self):
        campaign = self.root / "campaign"
        expected = {}
        for index, (board, optimization) in enumerate(itertools.product((BOARD, "esp32s3-aabbccddeeff"), M.OPTIMIZATIONS)):
            summary = synthetic_summary(board)
            offset = index * 100000
            for row in summary["cost_observations"]:
                row["device_active_us"] += offset
                row["host_elapsed_ns"] += offset * 2000
                if row["policy"] == "bundle":
                    row["response"]["timing_us"]["total"] += offset
                else:
                    row["ready"]["device_active_us"] += offset
            write_run(campaign, board, optimization, summary)
            expected[(board, optimization)] = 5.51 + offset / 1000
        out = self.root / "analysis"
        self.assertEqual(M.main(["--campaign", str(campaign), "--output", str(out)]), 0)
        result = M.read(out / "analysis.json")
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["observations"]), 960)
        self.assertEqual(result["missing_cells"], [])
        self.assertTrue(result["cost_matrix_complete"])
        for row in result["policy_summary"]:
            self.assertEqual(row["n_blocks"], 10)
            if row["family"] == "lr" and row["transition"] == "A_to_B_reused" and row["policy"] == "bundle" and row["metric"] == "handler_active_ms":
                self.assertAlmostEqual(row["median"], expected[(row["board_id"], row["optimization"])])
        for row in result["paired_comparisons"]:
            self.assertEqual(row["n_pairs"], 10)
        self.assertFalse(result["all_reviewer_experiments_complete"])
        self.assertGreater(len((out / "observations.csv").read_text().splitlines()), 960)


if __name__ == "__main__":
    unittest.main()
