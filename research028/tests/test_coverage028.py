"""Coverage tests guard chronology, class membership, and empty-group reporting."""
import csv
import importlib.util
import json
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "tools" / "coverage028.py"
SPEC = importlib.util.spec_from_file_location("coverage028", MODULE)
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)
UTC = timezone.utc


class CoverageTests(unittest.TestCase):
    def test_known_groups_use_fit_not_calibration(self):
        start = datetime(2019, 4, 23, tzinfo=UTC)
        day = timedelta(days=1)
        bins = {
            start: Counter({(0, "normal"): 2, (1, "scan"): 3}),
            start + day: Counter({(0, "normal"): 4, (1, "calibration_only"): 5}),
            start + 2 * day: Counter({(0, "normal"): 6, (1, "dos"): 7}),
            start + 3 * day: Counter({(0, "normal"): 8, (1, "other_cal_only"): 9}),
            start + 4 * day: Counter({(0, "normal"): 10, (1, "scan"): 11,
                                      (1, "dos"): 12, (1, "calibration_only"): 13,
                                      (1, "other_cal_only"): 14, (1, "new"): 15}),
        }
        counts = coverage.Counts(bins, day)
        roles, groups, _, known_a, known_b = coverage.candidate_coverage(
            counts, *(start + i * day for i in range(1, 5)))
        self.assertEqual(known_a, {"scan"})
        self.assertEqual(known_b, {"scan", "dos"})
        self.assertEqual(groups, {"normal": 10, "attack_known_A": 11,
                                  "attack_added_B": 12, "attack_unseen_B": 42})
        self.assertEqual(sum(roles["B_fit"].values()), 18)
        self.assertNotIn((1, "calibration_only"), roles["B_fit"])
        self.assertEqual(sum(groups.values()), sum(roles["common_test"].values()))

    def test_half_open_boundaries(self):
        start = datetime(2019, 4, 23, tzinfo=UTC)
        hour = timedelta(hours=1)
        counts = coverage.Counts({start + i * hour: Counter({(0, "normal"): i + 1})
                                  for i in range(6)}, hour)
        self.assertEqual(sum(counts.between(start, start + 2 * hour).values()), 3)
        self.assertEqual(sum(counts.between(start + 2 * hour, start + 4 * hour).values()), 7)

    def test_daily_metadata_empty_groups_and_no_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "daily_counts.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["utc_day", "stage", "label", "type", "rows"])
                writer.writeheader()
                for d in range(1, 9):
                    writer.writerow({"utc_day": f"2019-04-{d:02}", "stage": "valid_raw_contract",
                                     "label": 0, "type": "normal", "rows": 1})
                    writer.writerow({"utc_day": f"2019-04-{d:02}", "stage": "all_source",
                                     "label": 0, "type": "normal", "rows": 100})
            result = coverage.build_coverage(path, root / "out")
            summary = json.loads((root / "out" / "coverage_summary.json").read_text())
            self.assertGreater(result["candidate_count"], 0)
            self.assertEqual(summary["rows"], 8)
            self.assertEqual(summary["calibration_hours"], [24])
            self.assertFalse(summary["split_selected"])
            self.assertEqual(summary["candidates_with_all_four_test_groups"], 0)
            with (root / "out" / "coverage_test_groups.csv").open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 4 * result["candidate_count"])
            self.assertTrue(all(int(r["rows"]) == 0 for r in rows if r["group"] != "normal"))

    def test_rejects_naive_hour_and_negative_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hourly.csv"
            for timestamp, count in (("2019-04-01T00:00:00", 1),
                                     ("2019-04-01T00:00:00+00:00", -1)):
                path.write_text("utc_hour,stage,label,type,rows\n"
                                f"{timestamp},valid_raw_contract,0,normal,{count}\n")
                with self.assertRaises(ValueError):
                    coverage.read_histogram(path)

    def test_six_hour_grid_and_calibration_exposure_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "hourly_counts.csv"
            start = datetime(2019, 4, 23, tzinfo=UTC)
            with path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["utc_hour", "stage", "label", "type", "rows"])
                writer.writeheader()
                # For the first 6-hour candidate: scan in A_fit, calibration_only
                # in A_cal, dos in B_added, other_cal in B_cal, then all in test.
                by_hour = {0: ["scan"], 6: ["calibration_only"], 12: ["dos"],
                           18: ["other_cal"], 24: ["scan", "dos", "calibration_only", "other_cal", "new"]}
                for hour, kinds in by_hour.items():
                    for kind in ["normal"] + kinds:
                        writer.writerow({"utc_hour": (start + timedelta(hours=hour)).isoformat(),
                                         "stage": "valid_raw_contract", "label": int(kind != "normal"),
                                         "type": kind, "rows": 1})
            coverage.build_coverage(path, root / "out")
            with (root / "out" / "coverage_candidates.csv").open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            row = next(r for r in rows if r["calibration_hours"] == "6" and
                       r["B_added_fit_hours"] == "6" and r["A_fit_end_utc"] == "2019-04-23T06:00:00+00:00")
            self.assertEqual(int(row["test_attack_unseen_B_rows"]), 3)
            self.assertEqual(int(row["test_attack_unseen_in_fit_but_seen_in_calibration_rows"]), 2)
            self.assertEqual(int(row["test_attack_unseen_in_all_fit_and_calibration_rows"]), 1)
            self.assertEqual(row["all_four_test_groups_present"], "True")


if __name__ == "__main__":
    unittest.main()
