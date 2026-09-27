#include "ids_protocol.h"
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace ids {
std::string json_quote(const char* text) {
    std::string result = "\"";
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(text); *p; ++p) {
        if (*p == '\\' || *p == '"') { result += '\\'; result += char(*p); }
        else if (*p < 32) { char code[7]; std::snprintf(code, sizeof(code), "\\u%04x", *p); result += code; }
        else result += char(*p);
    }
    return result + "\"";
}
std::string digest_hex(const std::array<uint8_t, 32>& digest) {
    constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (uint8_t byte : digest) { result += alphabet[byte >> 4]; result += alphabet[byte & 15]; }
    return result;
}
namespace {
int unhex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
}
Protocol::Protocol(Engine& engine, Platform& platform, const uint8_t* schema, unsigned features,
                   bool factory_only)
    : engine_(engine), platform_(platform), schema_(schema), features_(features), factory_only_(factory_only) {}

void Protocol::status(const char* event, const char* reason) {
    std::array<uint8_t, 32> schema{};
    std::memcpy(schema.data(), schema_, 32);
    const Model& model = engine_.model();
    uint64_t setup_us = 0, first_verify_us = 0;
    const bool crypto_measured = platform_.crypto_metrics(setup_us, first_verify_us);
    platform_.output("{\"event\":" + json_quote(event) + ",\"ready\":" + (engine_.ready() ? "true" : "false") +
      ",\"reason\":" + json_quote(reason) + ",\"version\":" + std::to_string(engine_.ready() ? model.version : 0) +
      ",\"release\":" + json_quote(engine_.ready() ? model.release : "") +
      ",\"policy\":" + json_quote(factory_only_ ? "whole_firmware" : engine_.policy()) +
      ",\"storage_layout\":2,\"storage_scheme\":\"journal_dualrail_v1\",\"selector_sequence\":" + std::to_string(engine_.selector_sequence()) +
      ",\"sizeof_model_bytes\":" + std::to_string(sizeof(Model)) + ",\"sizeof_engine_bytes\":" + std::to_string(sizeof(Engine)) +
      ",\"runtime_abi\":" + std::to_string(engine_.runtime_abi()) +
      ",\"pretransform\":" + json_quote(engine_.pretransform()) +
      ",\"schema\":\"" + digest_hex(schema) + "\",\"feature_count\":" + std::to_string(features_) +
      ",\"bundle_sha256\":\"" + digest_hex(model.digest) + "\",\"active_slot\":" + std::to_string(engine_.active_slot()) +
      ",\"chip\":" + json_quote(platform_.chip()) + ",\"build\":" + json_quote(platform_.build()) +
      ",\"data_origin\":" + json_quote(platform_.origin()) + ",\"free_heap\":" + std::to_string(platform_.free_heap()) +
      ",\"timing_schema\":3,\"crypto_context\":" + json_quote(crypto_measured ? "shared_warm" : "unavailable") +
      ",\"crypto_key_setup_us\":" + (crypto_measured ? std::to_string(setup_us) : "null") +
      ",\"crypto_first_verify_us\":" + (crypto_measured ? std::to_string(first_verify_us) : "null") + "}");
}

void Protocol::line_error(const char* reason) {
    platform_.output("{\"event\":\"error\",\"reason\":" + json_quote(reason) + "}");
}

bool Protocol::fail_hook(Checkpoint checkpoint, void* context) {
    auto& protocol = *static_cast<Protocol*>(context);
    if (protocol.armed_ != checkpoint) return false;
    protocol.armed_ = Checkpoint::None;
    protocol.platform_.output("{\"event\":\"fault_checkpoint\",\"checkpoint\":" + json_quote(checkpoint_name(checkpoint)) +
                             ",\"fault_kind\":\"software_restart\"}");
    protocol.platform_.restart();
    return true;
}

void Protocol::process(const char* line) {
    if (std::strlen(line) > kMaxLine) { line_error("line_too_long"); return; }
    if (std::strcmp(line, "STATUS") == 0) { status(); return; }
    if (std::strcmp(line, "REBOOT") == 0) {
        platform_.output("{\"event\":\"reboot\",\"fault_kind\":\"software_restart\"}");
        platform_.restart(); return;
    }
    if (std::strncmp(line, "ARM_FAIL ", 9) == 0) {
        Checkpoint checkpoint;
        if (factory_only_) { line_error("unsupported_in_whole_firmware_policy"); return; }
        if (!parse_checkpoint(line + 9, checkpoint)) { line_error("unknown_checkpoint"); return; }
        armed_ = checkpoint;
        platform_.output("{\"event\":\"armed\",\"checkpoint\":" + json_quote(checkpoint_name(armed_)) + "}");
        return;
    }
    if (std::strncmp(line, "UPDATE ", 7) == 0) {
        if (factory_only_) { line_error("use_FW_BEGIN_FW_CHUNK_FW_END"); return; }
        const char* hex = line + 7;
        const size_t chars = std::strlen(hex);
        if (chars % 2 || chars > 2 * kMaxEnvelope || chars < 32) { line_error("hex_length"); return; }
        std::array<uint8_t, kMaxEnvelope> envelope{};
        for (size_t i = 0; i < chars / 2; ++i) {
            int hi = unhex(hex[2 * i]), lo = unhex(hex[2 * i + 1]);
            if (hi < 0 || lo < 0) { line_error("invalid_hex"); return; }
            envelope[i] = uint8_t(hi * 16 + lo);
        }
        const uint64_t start = platform_.microseconds();
        UpdateTimings timings;
        const Result result = engine_.update(envelope.data(), chars / 2, fail_hook, this, &timings, &platform_);
        const uint64_t elapsed = platform_.microseconds() - start;
        platform_.output("{\"event\":\"update\",\"accepted\":" + std::string(result.ok ? "true" : "false") +
          ",\"reason\":" + json_quote(result.reason) + ",\"latency_us\":" + std::to_string(elapsed) +
          ",\"version\":" + std::to_string(engine_.model().version) + ",\"ready\":" + (engine_.ready() ? "true" : "false") +
          ",\"policy\":" + json_quote(engine_.policy()) + ",\"free_heap\":" + std::to_string(platform_.free_heap()) +
          ",\"timing_schema\":3,\"timing_measured\":" + (timings.measured ? "true" : "false") +
          ",\"timing_executed_mask\":" + std::to_string(timings.executed_mask) +
          ",\"timing_us\":{\"candidate_verify\":" + std::to_string(timings.candidate_verify) +
          ",\"erase\":" + std::to_string(timings.erase) + ",\"body_write\":" + std::to_string(timings.body_write) +
          ",\"readback\":" + std::to_string(timings.readback) + ",\"readback_verify\":" + std::to_string(timings.readback_verify) +
          ",\"commit\":" + std::to_string(timings.commit) +
          ",\"journal_prepare\":" + std::to_string(timings.journal_prepare) +
          ",\"journal_body\":" + std::to_string(timings.journal_body) +
          ",\"journal_commit\":" + std::to_string(timings.journal_commit) + ",\"total\":" + std::to_string(timings.total) + "}}");
        return;
    }
    if (std::strncmp(line, "INFER ", 6) == 0) {
        float values[kMaxFeatures]{};
        size_t n = 0;
        const char* input = line + 6;
        while (true) {
            if (n >= kMaxFeatures || !*input) { line_error("input_count"); return; }
            if (*input == ' ' || *input == '\t') { line_error("invalid_number"); return; }
            char* end = nullptr;
            errno = 0;
            const float value = std::strtof(input, &end);
            if (end == input || (*end != ',' && *end != '\0')) { line_error("invalid_number"); return; }
            if (!std::isfinite(value)) { line_error("nonfinite_input"); return; }
            // Underflowed subnormal inputs are allowed; overflow is caught by isfinite.
            values[n++] = value;
            if (!*end) break;
            input = end + 1;
        }
        float probability = 0;
        int label = 0;
        const uint64_t start = platform_.microseconds();
        const Result result = engine_.infer(values, n, probability, label);
        const uint64_t elapsed = platform_.microseconds() - start;
        if (!result.ok) { line_error(result.reason); return; }
        char number[32];
        std::snprintf(number, sizeof(number), "%.9g", double(probability));
        platform_.output("{\"event\":\"inference\",\"version\":" + std::to_string(engine_.model().version) +
          ",\"policy\":" + json_quote(factory_only_ ? "whole_firmware" : engine_.policy()) +
          ",\"runtime_abi\":" + std::to_string(engine_.model().runtime_abi) +
          ",\"pretransform\":" + json_quote(engine_.pretransform()) +
          ",\"probability\":" + number + ",\"label\":" + std::to_string(label) +
          ",\"bundle_sha256\":\"" + digest_hex(engine_.model().digest) + "\",\"latency_us\":" + std::to_string(elapsed) +
          ",\"data_origin\":" + json_quote(platform_.origin()) + ",\"free_heap\":" + std::to_string(platform_.free_heap()) + "}");
        return;
    }
    line_error("unknown_command");
}
}
