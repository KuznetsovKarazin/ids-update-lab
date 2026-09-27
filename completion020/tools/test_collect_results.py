import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("collect_results.py"))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "lab"
        self.run = self.root / "runs" / "failed-001"
        self.run.mkdir(parents=True)
        (self.run / "summary.json").write_text('{"status":"failed","error":"timeout"}')
        (self.run / "transcript.jsonl").write_bytes(b'{"direction":"tx","line":"STATUS"}\r\n')
        self.out = Path(self.tmp.name) / "result.zip"

    def test_failed_and_partial_preserved_original_bytes(self):
        (self.root / "runs" / "partial").mkdir()
        (self.root / "runs" / "partial" / "raw.bin").write_bytes(bytes(range(255)))
        result = c.collect(self.root, self.out)
        self.assertEqual(result["files"], 3)
        with zipfile.ZipFile(self.out) as z:
            self.assertEqual(z.read("project/runs/failed-001/transcript.jsonl"), (self.run / "transcript.jsonl").read_bytes())
            manifest = json.loads(z.read("COLLECTION_MANIFEST.json"))
            self.assertEqual(manifest["run_summaries"][0]["reported_status"], "failed")
            self.assertFalse(manifest["claims_independently_verified"])

    def test_secret_content_and_paths_excluded(self):
        (self.run / "private.pem").write_bytes(b"sensitive")
        (self.run / "ordinary.txt").write_bytes(b"-----BEGIN " + b"RSA PRIVATE KEY-----\nsecret")
        (self.run / "copy.zip").write_bytes(b"archive")
        c.collect(self.root, self.out)
        with zipfile.ZipFile(self.out) as z:
            manifest = json.loads(z.read("COLLECTION_MANIFEST.json"))
            self.assertEqual(len(manifest["omitted"]), 3)
            self.assertFalse(any(name.endswith(("private.pem", "ordinary.txt", "copy.zip")) for name in z.namelist()))

    def test_no_overwrite(self):
        self.out.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            c.collect(self.root, self.out)
        self.assertEqual(self.out.read_bytes(), b"existing")

    def test_symlink_and_ancestor_are_not_followed(self):
        external = Path(self.tmp.name) / "outside"
        external.mkdir()
        (external / "secret.txt").write_text("do not copy")
        try:
            (self.root / "shortcut").symlink_to(external, target_is_directory=True)
            (self.run / "link.txt").symlink_to(external / "secret.txt")
        except OSError:
            self.skipTest("symlinks unavailable")
        c.collect(self.root, self.out, ["shortcut/secret.txt"])
        with zipfile.ZipFile(self.out) as z:
            manifest = json.loads(z.read("COLLECTION_MANIFEST.json"))
            self.assertEqual(len(manifest["omitted"]), 2)
            self.assertFalse(any("secret.txt" in name or "link.txt" in name for name in z.namelist()))

    def test_path_traversal_refused(self):
        for value in ("../outside", "C:\\outside", "/outside", "runs/../../outside"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                c.collect(self.root, self.out, [value])
        self.assertFalse(self.out.exists())

    def test_incomplete_nonjson_summary_is_kept(self):
        (self.run / "summary.json").write_text('{"status":')
        c.collect(self.root, self.out)
        with zipfile.ZipFile(self.out) as z:
            manifest = json.loads(z.read("COLLECTION_MANIFEST.json"))
            self.assertIn("parse_error", manifest["run_summaries"][0])

    def test_empty_root_refused(self):
        other = Path(self.tmp.name) / "empty"
        other.mkdir()
        with self.assertRaises(ValueError):
            c.collect(other, self.out)

    def cli(self, *extra):
        return subprocess.run(
            [sys.executable, str(Path(c.__file__).resolve()),
             "--root", str(self.root), "--output", str(self.out), *extra],
            capture_output=True, text=True, encoding="utf-8", timeout=30,
        )

    def test_cli_with_requested_include_relative(self):
        support = self.root / "completion020" / "tools"
        support.mkdir(parents=True)
        (support / "example.py").write_bytes(b"# public research script\n")
        result = self.cli("--include-relative", "completion020")
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(response["status"], "complete")
        self.assertFalse(response["hardware_access_attempted"])
        with zipfile.ZipFile(self.out) as z:
            self.assertEqual(z.read("project/completion020/tools/example.py"), b"# public research script\n")
            self.assertEqual(z.read("project/runs/failed-001/transcript.jsonl"),
                             (self.run / "transcript.jsonl").read_bytes())

    def test_cli_without_optional_include(self):
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "complete")

    def test_cli_existing_output_preserved(self):
        self.out.write_bytes(b"existing archive")
        result = self.cli("--include-relative", "completion020")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Refusing to overwrite", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.out.read_bytes(), b"existing archive")


if __name__ == "__main__":
    unittest.main()
