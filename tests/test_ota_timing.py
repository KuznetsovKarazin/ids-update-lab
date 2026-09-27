"""Test actual F dispatcher accounting using deterministic hardware doubles."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEADERS = {
    "sdkconfig.h": "#define CONFIG_IDS_WHOLE_FIRMWARE_BASELINE 1\n",
    "esp_timer.h": "#pragma once\n#include <cstdint>\nint64_t esp_timer_get_time();\n",
    "esp_app_desc.h": "#pragma once\nstruct esp_app_desc_t { char version[32]; };\nconst esp_app_desc_t* esp_app_get_description();\n",
    "esp_ota_ops.h": """#pragma once
#include <cstddef>
#include "esp_app_desc.h"
using esp_err_t = int;
using esp_ota_handle_t = unsigned;
constexpr esp_err_t ESP_OK = 0;
struct esp_partition_t { size_t size; };
const esp_partition_t* esp_ota_get_next_update_partition(const esp_partition_t*);
esp_err_t esp_ota_begin(const esp_partition_t*, size_t, esp_ota_handle_t*);
esp_err_t esp_ota_write(esp_ota_handle_t, const void*, size_t);
esp_err_t esp_ota_abort(esp_ota_handle_t);
esp_err_t esp_ota_end(esp_ota_handle_t);
esp_err_t esp_ota_get_partition_description(const esp_partition_t*, esp_app_desc_t*);
esp_err_t esp_ota_set_boot_partition(const esp_partition_t*);
""",
    "mbedtls/sha256.h": """#pragma once
#include <cstddef>
struct mbedtls_sha256_context { unsigned char value; };
void mbedtls_sha256_init(mbedtls_sha256_context*);
void mbedtls_sha256_free(mbedtls_sha256_context*);
int mbedtls_sha256_starts(mbedtls_sha256_context*, int);
int mbedtls_sha256_update(mbedtls_sha256_context*, const unsigned char*, size_t);
int mbedtls_sha256_finish(mbedtls_sha256_context*, unsigned char*);
""",
}


class OtaTimingTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("g++"), "g++ required for dispatcher timing test")
    def test_cumulative_timings_reset_after_rejected_image(self):
        with tempfile.TemporaryDirectory(prefix="ids-ota-timing-") as directory:
            temporary = Path(directory)
            for filename, text in HEADERS.items():
                target = temporary / filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text)
            binary = temporary / "ota_timing"
            command = ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                       "-I" + str(temporary), "-I" + str(ROOT / "firmware/main"),
                       "-I" + str(ROOT / "firmware/components/ids_core/include"),
                       str(ROOT / "tests/test_ota_timing.cpp"), str(ROOT / "firmware/main/firmware_ota.cpp"),
                       "-o", str(binary)]
            subprocess.run(command, check=True, capture_output=True, text=True)
            completed = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=10)
            events = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(len(events), 9)
        for phase in (events[:4], events[4:8]):
            begin, chunk1, chunk2, terminal = phase
            self.assertEqual(begin["crypto_context"], "shared_warm")
            self.assertEqual(begin["signature_verify_us"], 13)
            self.assertEqual(begin["partition_prepare_us"], 17)
            self.assertEqual(begin["begin_us"], 35)
            for count, chunk in enumerate((chunk1, chunk2), 1):
                self.assertEqual(chunk["timing_schema"], 2)
                self.assertEqual((chunk["write_us"], chunk["hash_us"], chunk["chunk_us"]), (7, 11, 18))
                self.assertEqual(chunk["chunk_count"], count)
                self.assertEqual(chunk["write_sum_us"], 7 * count)
                self.assertEqual(chunk["hash_sum_us"], 11 * count)
                self.assertEqual(chunk["chunk_sum_us"], 18 * count)
            self.assertEqual(terminal["chunk_count"], 2)
            self.assertEqual(terminal["device_active_us"], 35 + 36 + terminal["finalize_us"])
        self.assertEqual(events[3]["error"], "image_sha256")
        self.assertEqual(events[3]["finalize_us"], 29)  # includes abort and SHA cleanup
        self.assertEqual(events[7]["event"], "fw_ready")
        self.assertEqual(events[7]["finalize_us"], 30)
        self.assertEqual(events[8]["error"], "reboot_required")


if __name__ == "__main__":
    unittest.main()
