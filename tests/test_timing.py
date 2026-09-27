"""Compile actual core with a deterministic clock and NOR/failure test doubles."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TimingTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("g++"), "g++ is required for shared-core timing tests")
    def test_disjoint_stages_failures_and_optional_clock(self):
        with tempfile.TemporaryDirectory(prefix="ids-timing-test-") as directory:
            binary = Path(directory) / "timing"
            command = ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                       "-ffp-contract=off", "-I" + str(ROOT / "firmware/components/ids_core/include"),
                       "-I" + str(ROOT / "firmware/main/generated"), str(ROOT / "tests/test_timing.cpp"),
                       str(ROOT / "firmware/components/ids_core/ids_core.cpp"), "-o", str(binary)]
            subprocess.run(command, check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
