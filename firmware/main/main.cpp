#include "ids_core.h"
#include "ids_protocol.h"
#include "ids_line_reader.h"
#include "generated/model_contract.h"
#include "firmware_ota.h"

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "hal/usb_serial_jtag_ll.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace {
// ESP-IDF 5.3.2 has no public usb_serial_jtag_wait_tx_done(). Its installed
// driver's ISR disables SERIAL_IN_EMPTY once the software queue/stash are empty
// and it has queued the final USB zero-length packet. Read that state without
// writing the FIFO or competing with the driver's ISR. This helper is tied to
// the pinned SDK; re-review it when upgrading ESP-IDF.
bool wait_console_tx_done(uint32_t timeout_ms) {
    const int64_t deadline = esp_timer_get_time() + int64_t(timeout_ms) * 1000;
    while ((usb_serial_jtag_ll_get_intr_ena_status() & USB_SERIAL_JTAG_INTR_SERIAL_IN_EMPTY) ||
           !usb_serial_jtag_ll_txfifo_writable()) {
        if (esp_timer_get_time() >= deadline) return false;
        vTaskDelay(1);
    }
    return true;
}

std::string hex_bytes(const uint8_t* bytes, size_t count) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(2 * count);
    for (size_t i = 0; i < count; ++i) {
        result += digits[bytes[i] >> 4];
        result += digits[bytes[i] & 15];
    }
    return result;
}
}

class EspCrypto final : public ids::Crypto {
public:
    EspCrypto() {
        const int64_t started = esp_timer_get_time();
        mbedtls_pk_init(&key_);
        valid_ = mbedtls_pk_parse_public_key(&key_, ids_generated::kPublicKeyPem,
            sizeof(ids_generated::kPublicKeyPem)) == 0 &&
            mbedtls_pk_can_do(&key_, MBEDTLS_PK_RSA) && mbedtls_pk_get_bitlen(&key_) == 2048;
        if (valid_) mbedtls_rsa_set_padding(mbedtls_pk_rsa(key_), MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);
        setup_us_ = uint64_t(esp_timer_get_time() - started);
    }
    ~EspCrypto() override { mbedtls_pk_free(&key_); }
    bool verify(const uint8_t* payload, size_t length, const uint8_t* signature) override {
        const int64_t started = first_recorded_ ? 0 : esp_timer_get_time();
        uint8_t digest[32];
        const bool result = valid_ && sha256(payload, length, digest) &&
            mbedtls_pk_verify(&key_, MBEDTLS_MD_SHA256, digest, sizeof(digest), signature, 256) == 0;
        if (!first_recorded_) {
            first_verify_us_ = uint64_t(esp_timer_get_time() - started);
            first_recorded_ = true;
        }
        return result;
    }
    bool sha256(const uint8_t* bytes, size_t length, uint8_t* digest) override {
        return mbedtls_sha256(bytes, length, digest, 0) == 0;
    }
    uint64_t setup_us() const { return setup_us_; }
    uint64_t first_verify_us() const { return first_verify_us_; }
    bool warmed() const { return valid_ && first_recorded_; }
private:
    mbedtls_pk_context key_{};
    bool valid_ = false;
    bool first_recorded_ = false;
    uint64_t setup_us_ = 0, first_verify_us_ = 0;
};

class EspStorage final : public ids::Storage {
public:
    EspStorage() {
        partitions_[0] = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "ids_a");
        partitions_[1] = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "ids_b");
    }
    bool read(unsigned slot, size_t offset, void* target, size_t length) override {
        return valid_range(slot, offset, length) && esp_partition_read(partitions_[slot], offset, target, length) == ESP_OK;
    }
    bool write(unsigned slot, size_t offset, const void* source, size_t length) override {
        return valid_range(slot, offset, length) && esp_partition_write(partitions_[slot], offset, source, length) == ESP_OK;
    }
    bool erase(unsigned slot) override {
        return valid_range(slot, 0, ids::kSlotBytes) && esp_partition_erase_range(partitions_[slot], 0, ids::kSlotBytes) == ESP_OK;
    }
private:
    bool valid_range(unsigned slot, size_t offset, size_t length) const {
        return slot < 2 && partitions_[slot] && partitions_[slot]->size == ids::kSlotBytes &&
            !partitions_[slot]->encrypted && offset <= ids::kSlotBytes && length <= ids::kSlotBytes - offset;
    }
    const esp_partition_t* partitions_[2]{};
};

class EspPlatform final : public ids::Platform {
public:
    explicit EspPlatform(const EspCrypto& crypto) : crypto_(crypto) {}
    uint64_t microseconds() override { return uint64_t(esp_timer_get_time()); }
    size_t free_heap() override { return esp_get_free_heap_size(); }
    const char* chip() override { return "esp32s3"; }
    const char* build() override {
        if (build_.empty()) {
            const esp_app_desc_t* app = esp_app_get_description();
            char sha[65];
            esp_app_get_elf_sha256(sha, sizeof(sha));
            build_ = std::string("esp-idf-") + esp_get_idf_version() + ";app=" + app->version + ";elf=" + sha;
        }
        return build_.c_str();
    }
    const char* origin() override { return ids_generated::kDataOrigin; }
    bool crypto_metrics(uint64_t& setup_us, uint64_t& first_verify_us) const override {
        setup_us = crypto_.setup_us();
        first_verify_us = crypto_.first_verify_us();
        return crypto_.warmed();
    }
    void output(const std::string& json) override { std::printf("%s\n", json.c_str()); std::fflush(stdout); }
    void restart() override {
        std::fflush(stdout);
        // This remains a software restart, not a physical power interruption.
        // An absent host must not prevent the restart indefinitely.
        if (!wait_console_tx_done(1500)) {
            std::printf("{\"event\":\"console_warning\",\"reason\":\"tx_drain_timeout_before_restart\"}\n");
            std::fflush(stdout);
            wait_console_tx_done(100);
        }
        // The driver's final zero-length packet can still be in flight when
        // its queue becomes idle. Preserve a bounded USB settle interval; this
        // is not an application-level acknowledgement of receipt by the host.
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
    }
private:
    const EspCrypto& crypto_;
    std::string build_;
};

extern "C" void app_main(void) {
    // Allocate RX/TX queues before emitting application evidence. All printf
    // output, including firmware_ota.cpp, uses the SAME interrupt-driven VFS.
    // RX below calls the driver directly, never newlib getchar()/EOF polling.
    usb_serial_jtag_driver_config_t console_config{};
    console_config.rx_buffer_size = 4096;
    console_config.tx_buffer_size = 4096;
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&console_config));
    usb_serial_jtag_vfs_use_driver();
    usb_serial_jtag_vfs_set_tx_line_endings(ESP_LINE_ENDINGS_LF);
    usb_serial_jtag_vfs_set_rx_line_endings(ESP_LINE_ENDINGS_LF);
    setvbuf(stdin, nullptr, _IONBF, 0);
    setvbuf(stdout, nullptr, _IONBF, 0);
    EspStorage storage;
    EspCrypto crypto;
    EspPlatform platform(crypto);
#ifdef CONFIG_IDS_MODEL_ONLY_BASELINE
    constexpr bool model_only = true;
#else
    constexpr bool model_only = false;
#endif
#ifdef CONFIG_IDS_WHOLE_FIRMWARE_BASELINE
    constexpr bool factory_only = true;
#else
    constexpr bool factory_only = false;
#endif
    ids::Engine engine(storage, crypto, ids_generated::kFactoryEnvelope, sizeof(ids_generated::kFactoryEnvelope),
        ids_generated::kFeatureCount, ids_generated::kFeatureContractHash, model_only);
    const auto result = factory_only ? engine.boot_factory_only() : engine.boot();
    ids::Protocol protocol(engine, platform, ids_generated::kFeatureContractHash, ids_generated::kFeatureCount, factory_only);
    firmware_ota_init(crypto, ids_generated::kFactoryVersion, ids_generated::kFeatureContractHash);
    bool healthy = result.ok;
    if (factory_only && healthy) healthy = firmware_ota_boot_check();
    if (healthy) {
        esp_ota_img_states_t state;
        const esp_partition_t* running = esp_ota_get_running_partition();
        if (esp_ota_get_state_partition(running, &state) == ESP_OK && state == ESP_OTA_IMG_PENDING_VERIFY)
            healthy = esp_ota_mark_app_valid_cancel_rollback() == ESP_OK;
    }
    if (!healthy) engine.fail_closed();
    protocol.status("boot", healthy ? "ok" : (result.ok ? "firmware_boot_check" : result.reason));
    if (!healthy && factory_only) {
        // Do not serve classifications or approve a pending full-image update after failed self-check.
        esp_ota_mark_app_invalid_rollback_and_reboot();
        for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
    }
    ids::LineReader line;
    static_assert(ids::LineReader::kLimit == ids::kMaxLine, "framing limit differs from protocol limit");
    std::array<uint8_t, 256> incoming{};
    for (;;) {
        const int received = usb_serial_jtag_read_bytes(incoming.data(), incoming.size(), pdMS_TO_TICKS(100));
        if (received <= 0) continue;
        if (size_t(received) > incoming.size()) {
            protocol.line_error("console_driver_invalid_length");
            engine.fail_closed();
            for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
        }
        for (int i = 0; i < received; ++i) {
            const auto frame = line.push(incoming[size_t(i)]);
            if (frame == ids::LineReader::Result::Pending) continue;
            if (frame == ids::LineReader::Result::InvalidControl || frame == ids::LineReader::Result::TooLong) {
                const char* reason = frame == ids::LineReader::Result::TooLong ? "line_too_long" : "invalid_control_character";
                const uint8_t bad = uint8_t(line.bad_byte());
                platform.output("{\"event\":\"error\",\"reason\":" + ids::json_quote(reason) +
                    ",\"first_bad_byte\":" + (line.invalid() ? std::to_string(line.bad_byte()) : "null") +
                    ",\"first_bad_byte_hex\":" + (line.invalid() ? ids::json_quote(hex_bytes(&bad, 1).c_str()) : "null") +
                    ",\"first_bad_offset\":" + (line.invalid() ? std::to_string(line.bad_offset()) : "null") +
                    ",\"received_bytes\":" + std::to_string(line.received()) +
                    ",\"rx_prefix_hex\":" + ids::json_quote(hex_bytes(line.prefix(), line.prefix_size()).c_str()) +
                    ",\"rx_prefix_truncated\":" + (line.received() > line.prefix_size() ? "true" : "false") + "}");
            } else if (line.length()) {
                if (!(factory_only && firmware_ota_process(line.line()))) protocol.process(line.line());
            }
            line.reset();
        }
    }
}
