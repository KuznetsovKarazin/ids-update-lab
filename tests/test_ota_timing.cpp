// Exercise the actual firmware_ota.cpp through small deterministic IDF doubles.
// This checks timing/accounting and lifecycle, NOT real flash, SHA or RSA.
#include "firmware_ota.h"
#include "esp_ota_ops.h"
#include "esp_timer.h"
#include "mbedtls/sha256.h"
#include <array>
#include <cassert>
#include <cstring>
#include <string>

namespace {
int64_t now = 0;
unsigned aborts = 0, completed = 0, selected = 0;
esp_partition_t partition{1024 * 1024};
esp_app_desc_t description{"2"};
struct Crypto final : ids::Crypto {
    unsigned calls = 0;
    bool verify(const uint8_t*, size_t, const uint8_t* signature) override {
        now += 13; ++calls; return signature[0] == 0xaa;
    }
    bool sha256(const uint8_t*, size_t, uint8_t*) override { assert(false); return false; }
};
std::string hex(const uint8_t* bytes, size_t count) {
    const char* digits = "0123456789abcdef"; std::string out;
    for (size_t i = 0; i < count; ++i) { out += digits[bytes[i] >> 4]; out += digits[bytes[i] & 15]; }
    return out;
}
void command(const std::string& text) { assert(firmware_ota_process(text.c_str())); }
}

int64_t esp_timer_get_time() { return now; }
const esp_partition_t* esp_ota_get_next_update_partition(const esp_partition_t*) { return &partition; }
esp_err_t esp_ota_begin(const esp_partition_t*, size_t, esp_ota_handle_t* handle) {
    now += 17; *handle = 1; return ESP_OK;
}
esp_err_t esp_ota_write(esp_ota_handle_t, const void*, size_t) { now += 7; return ESP_OK; }
esp_err_t esp_ota_abort(esp_ota_handle_t) { now += 23; ++aborts; return ESP_OK; }
esp_err_t esp_ota_end(esp_ota_handle_t) { now += 19; ++completed; return ESP_OK; }
esp_err_t esp_ota_get_partition_description(const esp_partition_t*, esp_app_desc_t* out) {
    now += 2; *out = description; return ESP_OK;
}
esp_err_t esp_ota_set_boot_partition(const esp_partition_t*) { now += 3; ++selected; return ESP_OK; }
const esp_app_desc_t* esp_app_get_description() { return &description; }
void mbedtls_sha256_init(mbedtls_sha256_context* context) { now += 2; context->value = 0; }
int mbedtls_sha256_starts(mbedtls_sha256_context* context, int) { now += 3; context->value = 0; return 0; }
void mbedtls_sha256_free(mbedtls_sha256_context*) { now += 1; }
int mbedtls_sha256_update(mbedtls_sha256_context* context, const unsigned char* bytes, size_t length) {
    now += 11; for (size_t i = 0; i < length; ++i) context->value ^= bytes[i]; return 0;
}
int mbedtls_sha256_finish(mbedtls_sha256_context* context, unsigned char* out) {
    now += 5; std::memset(out, context->value, 32); return 0;
}

int main() {
    Crypto shared;
    std::array<uint8_t, 32> schema{};
    std::array<uint8_t, 84> metadata{};
    std::memcpy(metadata.data(), "SIDSFW1\0", 8);
    metadata[8] = 2; metadata[12] = 3; metadata[48] = 1;
    std::array<uint8_t, 256> signature{}; signature[0] = 0xaa;
    // Mimic the factory verification that warms the retained context at boot.
    assert(shared.verify(nullptr, 0, signature.data()));
    firmware_ota_init(shared, 1, schema.data());
    const std::string begin = "FW_BEGIN " + hex(metadata.data(), metadata.size()) + " " + hex(signature.data(), signature.size());
    command(begin);
    command("FW_CHUNK 0 0102");
    command("FW_CHUNK 2 04"); // checksum mismatch; full length has been written.
    command("FW_END");
    assert(aborts == 1 && completed == 0 && selected == 0);
    command(begin); // New transfer must reset cumulative counters.
    command("FW_CHUNK 0 0102");
    command("FW_CHUNK 2 03");
    command("FW_END");
    assert(shared.calls == 3 && aborts == 1 && completed == 1 && selected == 1);
    command(begin); // Selected image requires reboot; no further verification.
    assert(shared.calls == 3);
}
