"""Configuration regression checks. Author: Oleksandr Kuznetsov."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("build039", Path(__file__).with_name("build039.py"))
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)

class BuildConfigTests(unittest.TestCase):
    def test_production_does_not_keep_debug_or_instrumentation(self):
        base = 'CONFIG_COMPILER_OPTIMIZATION_DEBUG=y\nCONFIG_IDS_PHASE_GPIO_ENABLED=y\n'
        text = build.settings_text(base, "whole", "O2", None)
        self.assertEqual(text.count("CONFIG_COMPILER_OPTIMIZATION_DEBUG="), 1)
        self.assertIn("CONFIG_COMPILER_OPTIMIZATION_DEBUG=n\n", text)
        self.assertIn("CONFIG_COMPILER_OPTIMIZATION_PERF=y\n", text)
        self.assertIn("CONFIG_IDS_PHASE_GPIO_ENABLED=n\n", text)
        self.assertIn("CONFIG_IDS_WHOLE_FIRMWARE_BASELINE=y\n", text)
        self.assertIn("CONFIG_IDS_BUNDLE_POLICY=n\n", text)

    def test_powercut_build_explicit(self):
        text = build.settings_text("", "bundle", "Og", 4)
        self.assertIn("CONFIG_IDS_PHASE_GPIO_ENABLED=y\n", text)
        self.assertIn("CONFIG_IDS_PHASE_GPIO=4\n", text)
        self.assertIn("CONFIG_IDS_ERASE_NECESSARY_SECTORS=y\n", text)
        self.assertIn("CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_160=y\n", text)
        with self.assertRaises(ValueError):
            build.settings_text("", "bundle", "Og", 49)

    def test_configuration_gate_rejects_accidental_secure_boot(self):
        settings = {
            "CONFIG_IDF_TARGET": '"esp32s3"', "CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ": "160",
            "CONFIG_FREERTOS_HZ": "100", "CONFIG_ESPTOOLPY_FLASHMODE": '"dio"',
            "CONFIG_ESPTOOLPY_FLASHFREQ": '"80m"', "CONFIG_ESP_MAIN_TASK_STACK_SIZE": "65536",
            "CONFIG_IDS_ERASE_NECESSARY_SECTORS": "y", "CONFIG_COMPILER_OPTIMIZATION_PERF": "y",
            "CONFIG_IDS_BUNDLE_POLICY": "y",
        }
        build.verify_config(settings, "O2", "bundle", None)
        settings["CONFIG_SECURE_BOOT"] = "y"
        with self.assertRaises(RuntimeError):
            build.verify_config(settings, "O2", "bundle", None)

    def test_duplicate_matrix_selection_rejected(self):
        with self.assertRaises(Exception):
            build.choices("lr,lr", build.FAMILIES)

if __name__ == "__main__":
    unittest.main()
