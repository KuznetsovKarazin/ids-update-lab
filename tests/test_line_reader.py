"""Compiles and executes the exact byte framer used by ESP32-S3 firmware."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("g++"), "g++ unavailable for portable firmware framer test")
class LineReaderTests(unittest.TestCase):
    def test_framing_and_bad_byte_evidence(self):
        with tempfile.TemporaryDirectory(prefix="ids-framer-") as directory:
            executable = Path(directory) / "test_line_reader"
            subprocess.run(["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                "-I" + str(ROOT / "firmware/components/ids_core/include"),
                str(ROOT / "tests/test_line_reader.cpp"), "-o", str(executable)], check=True)
            subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    unittest.main()
