#include "firmware_ota.h"
#include "stream_inflate.h"
// Revision039 streaming compressed-image path authored by Oleksandr Kuznetsov.

#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <cstdlib>

#include "sdkconfig.h"
#include "esp_app_desc.h"
#include "esp_ota_ops.h"
#include "esp_timer.h"
#include "mbedtls/sha256.h"

namespace {
constexpr size_t kMetadataBytes = 84;
constexpr size_t kSignatureBytes = 256;
constexpr size_t kChunkBytes = 1024;
constexpr uint8_t kMagic[8] = {'S','I','D','S','F','W','1',0};
ids::Crypto *trusted_crypto = nullptr;
uint32_t current_version = 0;
uint32_t trusted_runtime_abi = 1;
const uint8_t *trusted_schema = nullptr;
bool pending = false;
bool selected_ready = false;
esp_ota_handle_t ota = 0;
const esp_partition_t *target = nullptr;
mbedtls_sha256_context sha;
uint32_t expected_size = 0, written = 0, next_version = 0;
uint8_t expected_digest[32];
int64_t begin_us = 0, write_sum_us = 0, hash_sum_us = 0, chunk_sum_us = 0;
uint32_t chunk_count = 0;
bool compressed = false;
uint32_t encoded_size = 0, encoded_received = 0;
int64_t inflate_sum_us = 0;
StreamInflate inflater;

bool decimal(const char* text, uint32_t& value) {
    if (!text || !*text) return false;
    uint64_t n = 0;
    for (const char* p = text; *p; ++p) {
        if (*p < '0' || *p > '9' || n > UINT32_MAX / 10) return false;
        n = n * 10 + unsigned(*p - '0'); if (n > UINT32_MAX) return false;
    }
    value = uint32_t(n); return value != 0;
}
const char* encoding() { return compressed ? "zlib" : "identity"; }
bool write_reconstructed(void*, const uint8_t* bytes, size_t length) {
    if (length > expected_size - written) return false;
    int64_t started = esp_timer_get_time();
    if (esp_ota_write(ota, bytes, length) != ESP_OK) return false;
    write_sum_us += esp_timer_get_time() - started;
    started = esp_timer_get_time();
    if (mbedtls_sha256_update(&sha, bytes, length) != 0) return false;
    hash_sum_us += esp_timer_get_time() - started;
    written += uint32_t(length); return true;
}

uint32_t read_le32(const uint8_t *p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
           (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
bool hex(const char *s, size_t n, uint8_t *out, size_t bytes) {
    if (n != 2 * bytes) return false;
    for (size_t i = 0; i < bytes; ++i) {
        int h = nibble(s[2*i]), l = nibble(s[2*i+1]);
        if (h < 0 || l < 0) return false;
        out[i] = uint8_t((h << 4) | l);
    }
    return true;
}
void abort_pending() {
    if (pending) {
        esp_ota_abort(ota);
        mbedtls_sha256_free(&sha);
    }
    pending = false;
    ota = 0;
    target = nullptr;
    written = 0;
}
void error(const char *code, bool abort_transfer = false, int64_t finalize_start = -1) {
    if (abort_transfer) abort_pending();
    const int64_t finalize_us = finalize_start >= 0 ? esp_timer_get_time() - finalize_start : -1;
    std::printf("{\"event\":\"fw_error\",\"ok\":false,\"error\":\"%s\",\"timing_schema\":2", code);
    if (finalize_us >= 0) {
        std::printf(",\"begin_us\":%" PRId64 ",\"write_sum_us\":%" PRId64
                    ",\"hash_sum_us\":%" PRId64 ",\"chunk_sum_us\":%" PRId64
                    ",\"chunk_count\":%" PRIu32 ",\"finalize_us\":%" PRId64
                    ",\"device_active_us\":%" PRId64,
                    begin_us, write_sum_us, hash_sum_us, chunk_sum_us, chunk_count,
                    finalize_us, begin_us + chunk_sum_us + finalize_us);
    }
    std::printf("}\n");
}
bool version_string_equals(const char *s, size_t capacity, uint32_t v) {
    char expected[16];
    std::snprintf(expected, sizeof(expected), "%" PRIu32, v);
    size_t n = strnlen(s, capacity);
    return n < capacity && std::strlen(expected) == n && std::memcmp(s, expected, n) == 0;
}
bool verify_signature(const uint8_t *metadata, const uint8_t *signature) {
    // Reuse exactly the context warmed by Engine factory verification. This
    // includes metadata SHA-256 and RSA, but no PEM parse or fresh RN setup.
    return trusted_crypto && trusted_crypto->verify(metadata, kMetadataBytes, signature);
}
[[maybe_unused]] void begin(const char *args, bool use_compression) {
    if (selected_ready) { error("reboot_required"); return; }
    if (pending) { error("transfer_busy"); return; }
    const char *space = std::strchr(args, ' ');
    const char *size_arg = space && use_compression ? std::strchr(space + 1, ' ') : nullptr;
    uint32_t transport_size = 0;
    uint8_t metadata[kMetadataBytes], signature[kSignatureBytes];
    if (!space || (use_compression && (!size_arg || !decimal(size_arg + 1, transport_size))) ||
        !hex(args, size_t(space-args), metadata, sizeof(metadata)) ||
        !hex(space+1, size_arg ? size_t(size_arg-space-1) : std::strlen(space+1), signature, sizeof(signature))) {
        error("begin_encoding"); return;
    }
    const int64_t begin_start = esp_timer_get_time();
    const int64_t verify_start = esp_timer_get_time();
    if (!verify_signature(metadata, signature)) { error("signature"); return; }
    const int64_t verify_us = esp_timer_get_time() - verify_start;
    if (std::memcmp(metadata, kMagic, sizeof(kMagic)) != 0 ||
        (trusted_runtime_abi < 1 || trusted_runtime_abi > 5) ||
        read_le32(metadata+48) != trusted_runtime_abi) {
        error("metadata_format_or_abi"); return;
    }
    const uint32_t version = read_le32(metadata+8), length = read_le32(metadata+12);
    if (!version || version <= current_version) { error("non_monotonic_version"); return; }
    if (!trusted_schema || std::memcmp(metadata+52, trusted_schema, 32) != 0) {
        error("feature_schema"); return;
    }
    target = esp_ota_get_next_update_partition(nullptr);
    if (!target || !length || length > target->size) { target = nullptr; error("image_size_or_partition"); return; }
    // Only the reconstructed target identity is signed. Encoded length is
    // untrusted framing, bounded here and never used to authorize selection.
    if (use_compression && transport_size > uint64_t(length) + length / 100 + 128) {
        target = nullptr; error("compressed_size"); return;
    }
    compressed = use_compression;
    encoded_size = compressed ? transport_size : length;
    encoded_received = 0; inflate_sum_us = 0;
    if (compressed) inflater.reset(length);
    const int64_t prepare_start = esp_timer_get_time();
    esp_err_t result = esp_ota_begin(target, length, &ota);
    const int64_t prepare_us = esp_timer_get_time() - prepare_start;
    if (result != ESP_OK) { target = nullptr; error("ota_begin"); return; }
    mbedtls_sha256_init(&sha);
    if (mbedtls_sha256_starts(&sha, 0) != 0) {
        esp_ota_abort(ota); mbedtls_sha256_free(&sha); target = nullptr; error("sha_init"); return;
    }
    pending = true;
    written = 0;
    next_version = version;
    expected_size = length;
    std::memcpy(expected_digest, metadata+16, 32);
    write_sum_us = hash_sum_us = chunk_sum_us = 0;
    chunk_count = 0;
    begin_us = esp_timer_get_time() - begin_start;
    std::printf("{\"event\":\"fw_begin\",\"ok\":true,\"version\":%" PRIu32
                ",\"size\":%" PRIu32 ",\"signature_verify_us\":%" PRId64
                ",\"partition_prepare_us\":%" PRId64 ",\"timing_schema\":2"
                ",\"crypto_context\":\"shared_warm\",\"begin_us\":%" PRId64
                ",\"encoding\":\"%s\",\"encoded_size\":%" PRIu32
                ",\"decoder_static_bytes\":%u}\n",
                next_version, expected_size, verify_us, prepare_us, begin_us,
                encoding(), encoded_size, unsigned(sizeof(inflater)));
}
[[maybe_unused]] void chunk(const char *args, bool use_compression) {
    if (!pending) { error("no_transfer"); return; }
    if (compressed != use_compression) { error("encoding_mismatch", true); return; }
    const char *space = std::strchr(args, ' ');
    if (!space || space == args || size_t(space-args) > 10) { error("chunk_offset", true); return; }
    uint64_t offset = 0;
    for (const char *p = args; p != space; ++p) {
        if (*p < '0' || *p > '9') { error("chunk_offset", true); return; }
        offset = offset * 10 + unsigned(*p-'0');
    }
    const size_t chars = std::strlen(space+1), length = chars / 2;
    uint8_t buffer[kChunkBytes];
    if (!length || length > sizeof(buffer) || !hex(space+1, chars, buffer, length) ||
        offset != encoded_received || length > encoded_size-encoded_received) {
        error("chunk_order_or_size", true); return;
    }
    const int64_t chunk_start = esp_timer_get_time();
    const int64_t old_write = write_sum_us, old_hash = hash_sum_us;
    const bool ok = compressed ? inflater.feed(buffer, length,
        encoded_received + length == encoded_size, write_reconstructed, nullptr) :
        write_reconstructed(nullptr, buffer, length);
    if (!ok) { error(compressed ? "decompression_or_write" : "chunk_write", true); return; }
    encoded_received += uint32_t(length); ++chunk_count;
    const int64_t chunk_us = esp_timer_get_time() - chunk_start;
    const int64_t write_us = write_sum_us - old_write, hash_us = hash_sum_us - old_hash;
    const int64_t inflate_us = compressed ? chunk_us - write_us - hash_us : 0;
    inflate_sum_us += inflate_us; chunk_sum_us += chunk_us;
    std::printf("{\"event\":\"fw_chunk\",\"ok\":true,\"offset\":%" PRIu32
                ",\"image_bytes\":%" PRIu32 ",\"encoding\":\"%s\""
                ",\"timing_schema\":2,\"write_us\":%" PRId64 ",\"hash_us\":%" PRId64
                ",\"chunk_us\":%" PRId64 ",\"write_sum_us\":%" PRId64
                ",\"hash_sum_us\":%" PRId64 ",\"chunk_sum_us\":%" PRId64
                ",\"inflate_and_dispatch_us\":%" PRId64 ",\"inflate_and_dispatch_sum_us\":%" PRId64
                ",\"chunk_count\":%" PRIu32 "}\n",
                encoded_received, written, encoding(), write_us, hash_us, chunk_us,
                write_sum_us, hash_sum_us, chunk_sum_us, inflate_us, inflate_sum_us, chunk_count);
}
[[maybe_unused]] void finish(bool use_compression) {
    const int64_t finalize_start = esp_timer_get_time();
    if (!pending) { error("no_transfer"); return; }
    if (compressed != use_compression) { error("encoding_mismatch", true, finalize_start); return; }
    if (encoded_received != encoded_size || written != expected_size ||
        (compressed && !inflater.complete())) { error("incomplete_image", true, finalize_start); return; }
    uint8_t digest[32];
    if (mbedtls_sha256_finish(&sha, digest) != 0 || std::memcmp(digest, expected_digest, 32) != 0) {
        error("image_sha256", true, finalize_start); return;
    }
    mbedtls_sha256_free(&sha);
    // esp_ota_end consumes the handle even on failure.
    const esp_err_t ended = esp_ota_end(ota);
    pending = false;
    ota = 0;
    if (ended != ESP_OK) { target = nullptr; error("image_validation", false, finalize_start); return; }
    esp_app_desc_t description;
    if (esp_ota_get_partition_description(target, &description) != ESP_OK ||
        !version_string_equals(description.version, sizeof(description.version), next_version)) {
        target = nullptr; error("embedded_version", false, finalize_start); return;
    }
    if (esp_ota_set_boot_partition(target) != ESP_OK) {
        target = nullptr; error("select_partition", false, finalize_start); return;
    }
    selected_ready = true;
    const int64_t finalize_us = esp_timer_get_time() - finalize_start;
    std::printf("{\"event\":\"fw_ready\",\"ok\":true,\"version\":%" PRIu32
                ",\"bytes\":%" PRIu32 ",\"finalize_us\":%" PRId64 ",\"reboot_required\":true"
                ",\"timing_schema\":2,\"begin_us\":%" PRId64 ",\"write_sum_us\":%" PRId64
                ",\"hash_sum_us\":%" PRId64 ",\"chunk_sum_us\":%" PRId64
                ",\"chunk_count\":%" PRIu32 ",\"device_active_us\":%" PRId64
                ",\"encoding\":\"%s\",\"encoded_bytes\":%" PRIu32
                ",\"inflate_and_dispatch_sum_us\":%" PRId64
                ",\"image_partition_write_bytes\":%" PRIu32 "}\n",
                next_version, written, finalize_us, begin_us, write_sum_us, hash_sum_us,
                chunk_sum_us, chunk_count, begin_us + chunk_sum_us + finalize_us,
                encoding(), encoded_received, inflate_sum_us, written);
    target = nullptr;
}
}  // namespace

void firmware_ota_init(ids::Crypto& crypto, uint32_t factory_version,
                       const uint8_t feature_schema[32], uint32_t runtime_abi) {
    trusted_crypto = &crypto;
    current_version = factory_version;
    trusted_schema = feature_schema;
    trusted_runtime_abi = runtime_abi;
}

bool firmware_ota_image_version_matches(uint32_t factory_version) {
    const esp_app_desc_t *desc = esp_app_get_description();
    return desc && version_string_equals(desc->version, sizeof(desc->version), factory_version);
}

bool firmware_ota_boot_check() {
    return firmware_ota_image_version_matches(current_version);
}

bool firmware_ota_process(const char *line) {
    const bool recognized = !std::strncmp(line, "FW_BEGIN", 8) || !std::strncmp(line, "FW_CHUNK", 8) ||
        !std::strncmp(line, "FW_END", 6) || !std::strncmp(line, "FW_ABORT", 8) ||
        !std::strncmp(line, "FWZ_", 4);
    if (!recognized) return false;
#if !CONFIG_IDS_WHOLE_FIRMWARE_BASELINE
    error("whole_firmware_mode_disabled");
#else
    if (!std::strncmp(line, "FW_BEGIN ", 9)) begin(line+9, false);
    else if (!std::strncmp(line, "FWZ_BEGIN ", 10)) begin(line+10, true);
    else if (!std::strncmp(line, "FW_CHUNK ", 9)) chunk(line+9, false);
    else if (!std::strncmp(line, "FWZ_CHUNK ", 10)) chunk(line+10, true);
    else if (!std::strcmp(line, "FW_END")) finish(false);
    else if (!std::strcmp(line, "FWZ_END")) finish(true);
    else if (!std::strcmp(line, "FW_ABORT") || !std::strcmp(line, "FWZ_ABORT")) {
        abort_pending();
        std::printf("{\"event\":\"fw_abort\",\"ok\":true}\n");
    } else error("command_syntax");
#endif
    return true;
}
