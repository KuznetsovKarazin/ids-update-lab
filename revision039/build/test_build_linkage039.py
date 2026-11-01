"""Author: Oleksandr Kuznetsov. Guard the MCU decoder's linked implementation."""
import unittest

from revision039.build.build039 import verify_inflater_symbols


class InflaterLinkageTests(unittest.TestCase):
    def test_application_decoder_with_unrelated_rom_symbol_is_allowed(self):
        result = verify_inflater_symbols(
            "40000828 A tinfl_decompress\n42012340 T ids039_tinfl_decompress\n",
            "         U ids039_tinfl_decompress\n         U esp_ota_write\n")
        self.assertEqual(result["status"], "verified")

    def test_original_rom_binding_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "namespaced"):
            verify_inflater_symbols("40000828 A tinfl_decompress\n", " U tinfl_decompress\n")

    def test_renamed_absolute_symbol_is_still_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "executable"):
            verify_inflater_symbols("40000828 A ids039_tinfl_decompress\n", " U ids039_tinfl_decompress\n")

    def test_mixed_calls_cannot_pass_by_merely_retaining_project_code(self):
        with self.assertRaisesRegex(RuntimeError, "exclusively"):
            verify_inflater_symbols("42012340 T ids039_tinfl_decompress\n",
                                    " U ids039_tinfl_decompress\n U tinfl_decompress\n")


if __name__ == "__main__":
    unittest.main()
