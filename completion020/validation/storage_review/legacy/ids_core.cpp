#include "ids_core.h"

#include <cmath>
#include <cstring>

namespace ids {
namespace {
uint32_t get32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
void put32(uint8_t* p, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) p[i] = uint8_t(value >> (8 * i));
}
float get_float(const uint8_t* p) {
    uint32_t value = get32(p);
    float result;
    static_assert(sizeof(result) == 4, "float32 required");
    std::memcpy(&result, &value, 4);
    return result;
}
Result pass() { return {true, "ok"}; }
Result fail(const char* reason) { return {false, reason}; }
bool interrupted(Hook hook, void* context, Checkpoint checkpoint) {
    return hook && hook(checkpoint, context);
}

// RAII also records an attempted stage when its operation fails. Stages are
// disjoint; the encompassing total includes instrumentation/control overhead.
class Duration {
public:
    Duration(UpdateTimings* timings, Clock* clock, uint64_t UpdateTimings::* field, uint32_t mask = 0)
        : timings_(timings), clock_(clock), field_(field) {
        if (timings_ && clock_) {
            timings_->executed_mask |= mask;
            start_ = clock_->microseconds();
        }
    }
    ~Duration() {
        if (timings_ && clock_) timings_->*field_ += clock_->microseconds() - start_;
    }
private:
    UpdateTimings* timings_;
    Clock* clock_;
    uint64_t UpdateTimings::* field_;
    uint64_t start_ = 0;
};
}

const char* checkpoint_name(Checkpoint checkpoint) {
    switch (checkpoint) {
        case Checkpoint::AfterErase: return "after_erase";
        case Checkpoint::AfterWrite: return "after_write";
        case Checkpoint::AfterVerify: return "after_verify";
        case Checkpoint::AfterCommit: return "after_commit";
        default: return "none";
    }
}
bool parse_checkpoint(const char* text, Checkpoint& checkpoint) {
    for (auto c : {Checkpoint::None, Checkpoint::AfterErase, Checkpoint::AfterWrite,
                   Checkpoint::AfterVerify, Checkpoint::AfterCommit}) {
        if (std::strcmp(text, checkpoint_name(c)) == 0) { checkpoint = c; return true; }
    }
    return false;
}

Engine::Engine(Storage& storage, Crypto& crypto, const uint8_t* factory, size_t factory_size,
               unsigned feature_count, const uint8_t* contract_hash, bool model_only, uint32_t runtime_abi)
    : storage_(storage), crypto_(crypto), factory_(factory), factory_size_(factory_size),
      count_(feature_count), contract_hash_(contract_hash), model_only_(model_only), runtime_abi_(runtime_abi) {}

Result Engine::validate(const uint8_t* envelope, size_t length, Model& model) {
    if (!envelope || length < 16 || length > kMaxEnvelope) return fail("envelope_length");
    if (std::memcmp(envelope, "SIDSPK1\0", 8) != 0) return fail("envelope_magic");
    const uint32_t plen = get32(envelope + 8), slen = get32(envelope + 12);
    if (slen != 256 || plen < 92 || plen > 272 || size_t(plen) + 272 != length)
        return fail("envelope_length");
    const uint8_t* p = envelope + 16;
    if (!crypto_.verify(p, plen, p + plen)) return fail("signature");
    if (std::memcmp(p, "SIDSB01\0", 8) != 0) return fail("payload_magic");
    if (get32(p + 8) != 1) return fail("format");
    if ((runtime_abi_ != 1 && runtime_abi_ != 2) || get32(p + 12) != runtime_abi_)
        return fail("runtime_abi");
    const uint32_t version = get32(p + 16), n = get32(p + 20);
    if (!version) return fail("version_zero");
    if (!n || n > kMaxFeatures || n != count_ || plen != 80 + 12 * n) return fail("feature_count");
    if (std::memcmp(p + 24, contract_hash_, 32) != 0) return fail("feature_contract");
    if (p[56] == 0) return fail("release_identifier");
    bool nul_seen = false;
    for (unsigned i = 0; i < 16; ++i) {
        const uint8_t ch = p[56 + i];
        if (ch == 0) nul_seen = true;
        else if (nul_seen || ch < 33 || ch > 126) return fail("release_identifier");
    }
    Model candidate{};
    candidate.runtime_abi = runtime_abi_;
    candidate.version = version;
    candidate.count = n;
    std::memcpy(candidate.release, p + 56, 16);
    candidate.threshold = get_float(p + 72);
    candidate.bias = get_float(p + 76);
    if (!std::isfinite(candidate.threshold) || candidate.threshold <= 0 || candidate.threshold >= 1)
        return fail("threshold");
    if (!std::isfinite(candidate.bias)) return fail("nonfinite_parameter");
    for (unsigned i = 0; i < n; ++i) {
        candidate.means[i] = get_float(p + 80 + 4 * i);
        candidate.scales[i] = get_float(p + 80 + 4 * n + 4 * i);
        candidate.weights[i] = get_float(p + 80 + 8 * n + 4 * i);
        if (!std::isfinite(candidate.means[i]) || !std::isfinite(candidate.scales[i]) ||
            !std::isfinite(candidate.weights[i])) return fail("nonfinite_parameter");
        if (candidate.scales[i] <= 0) return fail("scale");
    }
    if (!crypto_.sha256(p, plen, candidate.digest.data())) return fail("crypto_error");
    model = candidate;
    return pass();
}

bool Engine::is_erased(unsigned slot, bool& erased) {
    uint8_t buffer[256];
    erased = true;
    for (size_t offset = 0; offset < kSlotBytes; offset += sizeof(buffer)) {
        if (!storage_.read(slot, offset, buffer, sizeof(buffer))) return false;
        for (uint8_t byte : buffer) if (byte != 0xff) erased = false;
    }
    return true;
}

Result Engine::read_committed(unsigned slot, Model& model) {
    uint8_t head[8];
    if (!storage_.read(slot, 0, head, sizeof(head))) return fail("storage_read");
    if (get32(head) != kCommit) return fail("not_committed");
    const uint32_t length = get32(head + 4);
    if (length > kMaxEnvelope || length < 16) return fail("stored_length");
    std::array<uint8_t, kMaxEnvelope> envelope{};
    if (!storage_.read(slot, 8, envelope.data(), length)) return fail("storage_read");
    return validate(envelope.data(), length, model);
}

Result Engine::boot() {
    ready_ = false;
    active_slot_ = -1;
    auto factory_result = validate(factory_, factory_size_, factory_model_);
    if (!factory_result.ok) return fail("invalid_factory");
    Model models[2];
    const auto r0 = read_committed(0, models[0]);
    const auto r1 = read_committed(1, models[1]);
    // An inaccessible slot could hide a newer committed version; never ignore an I/O failure.
    if (std::strcmp(r0.reason, "storage_read") == 0 || std::strcmp(r1.reason, "storage_read") == 0)
        return fail("storage_read");
    if ((!r0.ok && std::strcmp(r0.reason, "not_committed") != 0) ||
        (!r1.ok && std::strcmp(r1.reason, "not_committed") != 0))
        return fail("committed_slot_invalid");
    if (r0.ok || r1.ok) {
        if (r0.ok && r1.ok && models[0].version == models[1].version && models[0].digest != models[1].digest)
            return fail("ambiguous_equal_version");
        active_slot_ = !r0.ok ? 1 : (!r1.ok ? 0 : (models[1].version > models[0].version ? 1 : 0));
        active_ = models[active_slot_];
        // A new firmware factory may impose a higher floor than an old external slot.
        if (active_.version < factory_model_.version) { active_slot_ = -1; return fail("below_factory_version"); }
        ready_ = true;
        return pass();
    }
    bool erased0 = false, erased1 = false;
    if (!is_erased(0, erased0) || !is_erased(1, erased1)) return fail("storage_read");
    if (!erased0 || !erased1) return fail("corrupt_store_no_valid_slot");
    // Persist the factory before permitting updates, preserving rollback after the first interrupted install.
    auto install_result = install(0, factory_, factory_size_, nullptr, nullptr);
    if (!install_result.ok) return install_result;
    active_ = factory_model_;
    active_slot_ = 0;
    ready_ = true;
    return pass();
}

Result Engine::boot_factory_only() {
    ready_ = false;
    active_slot_ = -1;
    auto result = validate(factory_, factory_size_, factory_model_);
    if (!result.ok) return result;
    active_ = factory_model_;
    ready_ = true;
    return pass();
}

Result Engine::install(unsigned slot, const uint8_t* envelope, size_t length, Hook hook, void* context,
                       UpdateTimings* timings, Clock* clock) {
    {
        Duration duration(timings, clock, &UpdateTimings::erase, 1u << 1);
        if (!storage_.erase(slot)) return fail("storage_erase");
    }
    if (interrupted(hook, context, Checkpoint::AfterErase)) return fail("interrupted_after_erase");
    std::array<uint8_t, 4 + kMaxEnvelope> body{};
    put32(body.data(), uint32_t(length));
    std::memcpy(body.data() + 4, envelope, length);
    {
        Duration duration(timings, clock, &UpdateTimings::body_write, 1u << 2);
        if (!storage_.write(slot, 4, body.data(), length + 4)) return fail("storage_write");
    }
    if (interrupted(hook, context, Checkpoint::AfterWrite)) return fail("interrupted_after_write");
    std::array<uint8_t, 4 + kMaxEnvelope> readback{};
    {
        Duration duration(timings, clock, &UpdateTimings::readback, 1u << 3);
        if (!storage_.read(slot, 4, readback.data(), length + 4)) return fail("storage_read");
        if (std::memcmp(body.data(), readback.data(), length + 4) != 0) return fail("readback_mismatch");
    }
    Model verified{};
    {
        Duration duration(timings, clock, &UpdateTimings::readback_verify, 1u << 4);
        auto verification = validate(readback.data() + 4, length, verified);
        if (!verification.ok) return verification;
    }
    if (interrupted(hook, context, Checkpoint::AfterVerify)) return fail("interrupted_after_verify");
    uint8_t marker[4];
    put32(marker, kCommit);
    {
        Duration duration(timings, clock, &UpdateTimings::commit, 1u << 5);
        if (!storage_.write(slot, 0, marker, sizeof(marker))) return fail("storage_commit");
        uint8_t committed[4];
        if (!storage_.read(slot, 0, committed, sizeof(committed))) return fail("storage_read");
        if (std::memcmp(marker, committed, sizeof(marker)) != 0) return fail("commit_readback");
    }
    if (interrupted(hook, context, Checkpoint::AfterCommit)) return fail("interrupted_after_commit");
    return pass();
}

Result Engine::update(const uint8_t* envelope, size_t length, Hook hook, void* context,
                      UpdateTimings* timings, Clock* clock) {
    if (timings) { *timings = {}; timings->measured = clock != nullptr; }
    Duration total(timings, clock, &UpdateTimings::total);
    if (!ready_) return fail("not_ready");
    if (active_slot_ < 0) return fail("factory_only_policy");
    Model candidate{};
    {
        Duration duration(timings, clock, &UpdateTimings::candidate_verify, 1u << 0);
        auto result = validate(envelope, length, candidate);
        if (!result.ok) return result;
    }
    if (candidate.version <= active_.version) return fail("replay_or_downgrade");
    const unsigned target = unsigned(1 - active_slot_);
    auto result = install(target, envelope, length, hook, context, timings, clock);
    if (!result.ok) {
        // After any installation failure force revalidation before accepting further operations.
        ready_ = false;
        return result;
    }
    active_ = candidate;
    active_slot_ = int(target);
    return pass();
}

Result Engine::infer(const float* values, size_t count, float& probability, int& label) const {
    if (!ready_) return fail("not_ready");
    if (!values || count != active_.count) return fail("input_count");
    const Model& preprocessing = model_only_ ? factory_model_ : active_;
    float z = active_.bias;
    for (unsigned i = 0; i < count; ++i) {
        if (!std::isfinite(values[i])) return fail("nonfinite_input");
        // ABI 2 receives raw float32 network features. The signed ABI and
        // schema bind this transform; a host must not precompute logarithms.
        if (runtime_abi_ == 2 && values[i] < 0.0f) return fail("negative_raw_input");
        const float transformed = runtime_abi_ == 2 ? ::log1pf(values[i]) : values[i];
        const float shifted = transformed - preprocessing.means[i];
        const float scaled = shifted / preprocessing.scales[i];
        const float term = active_.weights[i] * scaled;
        z = z + term;
        if (!std::isfinite(transformed) || !std::isfinite(shifted) || !std::isfinite(scaled) ||
            !std::isfinite(term) || !std::isfinite(z))
            return fail("arithmetic_overflow");
    }
    if (z >= 0) probability = 1.0f / (1.0f + std::exp(-z));
    else { const float e = std::exp(z); probability = e / (1.0f + e); }
    label = probability > preprocessing.threshold ? 1 : 0;
    return pass();
}
}
