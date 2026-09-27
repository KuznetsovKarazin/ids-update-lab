"""Protocol accounting gates; measured zero is valid, absent stages are not."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import stage_timing_support as timing


class TimingSchemaTests(unittest.TestCase):
    def bundle(self):
        return {"timing_schema": 2, "timing_measured": True, "timing_executed_mask": 63, "latency_us": 10,
            "timing_us": {**{name: 1 for name in timing.BUNDLE_STAGES}, "total": 8}}

    def test_true_zero_stages_are_distinct_from_missing_execution(self):
        row = self.bundle()
        row["timing_us"] = {name: 0 for name in row["timing_us"]}
        self.assertEqual(timing.validate_bundle_timing(row)["total"], 0)
        row["timing_executed_mask"] = 31
        with self.assertRaisesRegex(RuntimeError, "mask 63"):
            timing.validate_bundle_timing(row)

    def test_stage_types_nonfinite_and_missing_fields_fail(self):
        for value in (True, -1, 1.0, float("nan"), None):
            with self.subTest(value=value):
                row = self.bundle()
                row["timing_us"]["erase"] = value
                with self.assertRaises(RuntimeError):
                    timing.validate_bundle_timing(row)
        row = self.bundle()
        del row["timing_us"]["readback"]
        with self.assertRaises(RuntimeError):
            timing.validate_bundle_timing(row)

    def test_status_requires_actual_shared_context_measurements(self):
        row = {"timing_schema": 2, "crypto_context": "shared_warm", "crypto_key_setup_us": 0, "crypto_first_verify_us": 0}
        timing.validate_status_timing(row)
        row["crypto_key_setup_us"] = None
        with self.assertRaises(RuntimeError):
            timing.validate_status_timing(row)

    def test_fw_stage_accounting_rejects_boolean_counts_and_double_counted_total(self):
        begin = {"timing_schema": 2, "crypto_context": "shared_warm", "signature_verify_us": 2, "partition_prepare_us": 3, "begin_us": 6}
        cumulative = timing.validate_fw_begin(begin)
        chunk = {"timing_schema": 2, "write_us": 2, "hash_us": 1, "chunk_us": 4,
            "write_sum_us": 2, "hash_sum_us": 1, "chunk_sum_us": 4, "chunk_count": 1}
        cumulative = timing.validate_fw_chunk(chunk, cumulative)
        ready = {"timing_schema": 2, **cumulative, "finalize_us": 5, "device_active_us": 15}
        timing.validate_fw_ready(ready, cumulative)
        ready["device_active_us"] += cumulative["write_sum_us"]
        with self.assertRaisesRegex(RuntimeError, "does not equal"):
            timing.validate_fw_ready(ready, cumulative)
        chunk["chunk_count"] = True
        with self.assertRaises(RuntimeError):
            timing.validate_fw_chunk(chunk, timing.validate_fw_begin(begin))


if __name__ == "__main__":
    unittest.main()
