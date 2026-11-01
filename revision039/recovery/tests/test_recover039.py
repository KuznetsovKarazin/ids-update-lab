"""Evidence-preservation regression checks. Original author: Oleksandr Kuznetsov."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "recover039.py"
spec = importlib.util.spec_from_file_location("recovery040_tested", SCRIPT)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryEvidenceTests(unittest.TestCase):
    def make_step(self, root):
        product = root / "prepared/numerics"
        product.mkdir(parents=True)
        recovery.coord.save(product / "summary.json", {"status": "prepared"})
        log = root / "logs/prepare-numerics.log"
        log.parent.mkdir()
        log.write_text("historical log\n")
        receipt = {"status": "complete", "returncode": 0, "argv": ["historical", "command"],
                   "outputs_sha256": recovery.coord.evidence_files(product),
                   "log_sha256": recovery.coord.sha(log)}
        recovery.coord.save(root / "steps/prepare-numerics.json", receipt)
        return product

    def test_valid_receipt_import_preserves_original_command_and_all_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            source, out = Path(temp) / "source", Path(temp) / "new"
            self.make_step(source)
            before = recovery.coord.evidence_files(source)
            entry = recovery.verify_completed(source, "prepare-numerics", "prepared/numerics")
            (out / "logs").mkdir(parents=True)
            recovery.copy_import(out, source, entry)
            imported = recovery.coord.read(out / "steps/prepare-numerics.json")
            self.assertEqual(imported["argv"], ["historical", "command"])
            self.assertEqual(imported["evidence_origin"], "imported_unchanged_historical_measurement")
            self.assertEqual(before, recovery.coord.evidence_files(source))
            self.assertEqual(entry["outputs_sha256"], recovery.coord.evidence_files(out / "prepared/numerics"))

    def test_changed_source_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            product = self.make_step(source)
            (product / "summary.json").write_text("changed")
            with self.assertRaisesRegex(ValueError, "Source evidence changed"):
                recovery.verify_completed(source, "prepare-numerics", "prepared/numerics")

    def test_untracked_file_and_failed_step_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            product = self.make_step(source)
            (product / "untracked.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "untracked"):
                recovery.verify_completed(source, "prepare-numerics", "prepared/numerics")
            p = source / "steps/prepare-numerics.json"
            receipt = recovery.coord.read(p)
            receipt["status"] = "failed"
            recovery.coord.save(p, receipt)
            with self.assertRaisesRegex(ValueError, "Only completed"):
                recovery.verify_completed(source, "prepare-numerics", "prepared/numerics")

    def test_invalid_output_never_packs_or_changes_source(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"
            source.mkdir()
            recovery.coord.save(source / "campaign.json", {"kind": "original"})
            report = {"historical_numerics": {"label_mismatches": 7}}
            before = recovery.coord.evidence_files(source)
            with patch.object(recovery, "inspect_source", return_value=report), patch.object(recovery.coord, "pack") as pack:
                code = recovery.main(["run", "--source", str(source), "--output", str(source), "--port", "COM13"])
                self.assertEqual(code, 1)
                pack.assert_not_called()
            self.assertEqual(before, recovery.coord.evidence_files(source))

    def test_rejected_existing_output_is_never_rewritten_or_archived(self):
        with tempfile.TemporaryDirectory() as temp:
            source, out = Path(temp) / "source", Path(temp) / "old-output"
            source.mkdir()
            out.mkdir()
            recovery.coord.save(out / "campaign.json", {"kind": "recovery040"})
            recovery.coord.save(out / "RECOVERY_BINDING.json", {"old": "binding"})
            before = recovery.coord.evidence_files(out)
            report = {"historical_numerics": {"label_mismatches": 7}}
            with patch.object(recovery, "inspect_source", return_value=report), patch.object(recovery, "initialize", side_effect=ValueError("changed binding")), patch.object(recovery.coord, "pack") as pack, patch.object(recovery.coord, "summarize") as summarize:
                code = recovery.main(["run", "--source", str(source), "--output", str(out), "--port", "COM13"])
                self.assertEqual(code, 1)
                pack.assert_not_called()
                summarize.assert_not_called()
            self.assertEqual(before, recovery.coord.evidence_files(out))

    def test_smoke_precedes_all_primary_costs_and_never_runs_Og_numerics(self):
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args = Namespace(source=str(root / "source"), port="COM13", board_id="esp32s3-a0f262ebb558")
            report = {"training": str(root / "training")}
            calls = []
            with patch.object(recovery, "initialize"), patch.object(recovery.coord, "run_step", side_effect=lambda out, name, argv, product: calls.append((name, argv))), patch.object(recovery.coord, "analyze"):
                recovery.run(args, report, root / "new")
            names = [n for n, _ in calls]
            self.assertEqual(len(names), 7)
            self.assertTrue(names[2].endswith("-Og-smoke"))
            self.assertTrue(names[3].endswith("-O2-smoke"))
            self.assertTrue(names[4].endswith("-Og-costs"))
            self.assertTrue(names[5].endswith("-O2-numerics"))
            self.assertTrue(names[6].endswith("-O2-costs"))
            self.assertFalse(any(n.endswith("-Og-numerics") for n in names))
            for name, argv in calls[2:]:
                if name.endswith("smoke"):
                    self.assertEqual(argv[argv.index("--repetitions") + 1], "1")
                    self.assertEqual(argv[argv.index("--families") + 1], "lr")
                elif name.endswith("costs"):
                    self.assertEqual(argv[argv.index("--repetitions") + 1], "10")


if __name__ == "__main__":
    unittest.main()
