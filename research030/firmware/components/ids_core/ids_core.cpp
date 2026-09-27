#include "ids_core.h"

#include <cmath>
#include <cstring>
#include <limits>

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

const char* erase_policy_name(ErasePolicy policy) {
    switch (policy) {
        case ErasePolicy::FullSlot: return "full_slot";
        case ErasePolicy::NecessarySectors: return "necessary_sectors";
        default: return "unsupported";
    }
}
bool parse_erase_policy(const char* text, ErasePolicy& policy) {
    if (!text) return false;
    for (auto candidate : {ErasePolicy::FullSlot, ErasePolicy::NecessarySectors}) {
        if (std::strcmp(text, erase_policy_name(candidate)) == 0) { policy = candidate; return true; }
    }
    return false;
}

const char* checkpoint_name(Checkpoint checkpoint) {
    switch (checkpoint) {
        case Checkpoint::AfterErase: return "after_erase";
        case Checkpoint::AfterWrite: return "after_write";
        case Checkpoint::AfterVerify: return "after_verify";
        case Checkpoint::AfterSlotCommit: return "after_slot_commit";
        case Checkpoint::AfterJournalBody: return "after_journal_body";
        case Checkpoint::AfterCommit: return "after_commit";
        default: return "none";
    }
}
bool parse_checkpoint(const char* text, Checkpoint& checkpoint) {
    for (auto c : {Checkpoint::None, Checkpoint::AfterErase, Checkpoint::AfterWrite,
                   Checkpoint::AfterVerify, Checkpoint::AfterSlotCommit,
                   Checkpoint::AfterJournalBody, Checkpoint::AfterCommit}) {
        if (std::strcmp(text, checkpoint_name(c)) == 0) { checkpoint = c; return true; }
    }
    return false;
}

Engine::Engine(Storage& storage, Crypto& crypto, const uint8_t* factory, size_t factory_size,
               unsigned feature_count, const uint8_t* contract_hash, bool model_only, uint32_t runtime_abi,
               ErasePolicy erase_policy)
    : storage_(storage), crypto_(crypto), factory_(factory), factory_size_(factory_size),
      count_(feature_count), contract_hash_(contract_hash), model_only_(model_only), runtime_abi_(runtime_abi),
      erase_policy_(erase_policy) {}

Result Engine::validate(const uint8_t* envelope, size_t length, Model& model) {
    if (!envelope || length < 16 || length > kMaxEnvelope) return fail("envelope_length");
    if (std::memcmp(envelope, "SIDSPK1\0", 8) != 0) return fail("envelope_magic");
    const uint32_t plen = get32(envelope + 8), slen = get32(envelope + 12);
    if (slen != 256 || plen < 80 || plen > kMaxEnvelope - 272 || size_t(plen) + 272 != length)
        return fail("envelope_length");
    const uint8_t* p = envelope + 16;
    if (!crypto_.verify(p, plen, p + plen)) return fail("signature");
    if (std::memcmp(p, runtime_abi_ == 3 ? "SIDST01\0" : (runtime_abi_ >= 4 ? "SIDSM01\0" : "SIDSB01\0"), 8) != 0) return fail("payload_magic");
    if (get32(p + 8) != 1) return fail("format");
    if ((runtime_abi_ < 1 || runtime_abi_ > 5) || get32(p + 12) != runtime_abi_)
        return fail("runtime_abi");
    const uint32_t version = get32(p + 16), n = get32(p + 20);
    if (!version) return fail("version_zero");
    if (!n || n > kMaxFeatures || n != count_ || (runtime_abi_ <= 2 && plen != 80 + 12 * n)) return fail("feature_count");
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
    candidate.bias = runtime_abi_ >= 3 ? 0.0f : get_float(p + 76);
    if (!std::isfinite(candidate.threshold) || candidate.threshold < 0 || candidate.threshold > 1.0f)
        return fail("threshold");
    if (!std::isfinite(candidate.bias)) return fail("nonfinite_parameter");
    if (runtime_abi_ == 3) {
        if (!decode_tree_body(p, plen, n, candidate.tree)) return fail("tree_layout");
    } else if (runtime_abi_ >= 4) {
        if (!decode_mlp_body(p, plen, runtime_abi_, candidate.mlp)) return fail("mlp_layout");
        for (unsigned i=0; i<n; ++i) {
            candidate.means[i]=get_float(p+80+4*i); candidate.scales[i]=get_float(p+80+4*n+4*i);
            if (!std::isfinite(candidate.means[i]) || !std::isfinite(candidate.scales[i]) || candidate.scales[i]<=0) return fail("mlp_preprocessing");
        }
    } else for (unsigned i = 0; i < n; ++i) {
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
    for (size_t offset = 0; offset < (slot < 2 ? kSlotBytes : kJournalPageBytes); offset += sizeof(buffer)) {
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

// Each logical byte is stored beside its bitwise complement. For every bit
// pair exactly one zero is required. A torn NOR program (1 -> 0) or erase
// (0 -> 1) can preserve a valid record or invalidate it, never change it into
// a different valid record. The commit code uses the same encoding and is
// programmed in a separate final operation. This is a power-fault code, not
// authentication against an adversary who can rewrite raw flash.
namespace {
constexpr size_t kSelectorBody = 112;
constexpr size_t kRecordsPerPage = kJournalPageBytes / kJournalRecordBytes;
constexpr uint8_t kSelectorCommit[8] = {'S','E','L','C','O','M','0','1'};
uint64_t get64(const uint8_t* p) {
    return uint64_t(get32(p)) | (uint64_t(get32(p + 4)) << 32);
}
void put64(uint8_t* p, uint64_t value) {
    put32(p, uint32_t(value)); put32(p + 4, uint32_t(value >> 32));
}
void rail_encode(const uint8_t* plain, size_t size, uint8_t* encoded) {
    for (size_t i = 0; i < size; ++i) {
        encoded[2 * i] = plain[i]; encoded[2 * i + 1] = uint8_t(~plain[i]);
    }
}
bool rail_decode(const uint8_t* encoded, size_t size, uint8_t* plain) {
    for (size_t i = 0; i < size; ++i) {
        if (uint8_t(encoded[2 * i] ^ encoded[2 * i + 1]) != 0xff) return false;
        plain[i] = encoded[2 * i];
    }
    return true;
}
bool blank_record(const uint8_t* p) {
    for (size_t i = 0; i < kJournalRecordBytes; ++i) if (p[i] != 0xff) return false;
    return true;
}
struct Selector {
    uint64_t sequence = 0;
    uint32_t version = 0, slot = 0;
    std::array<uint8_t, 32> digest{};
};
bool decode_selector(const uint8_t* encoded, Selector& value) {
    uint8_t body[56], commit[8];
    if (!rail_decode(encoded, sizeof(body), body) ||
        !rail_decode(encoded + kSelectorBody, sizeof(commit), commit) ||
        std::memcmp(commit, kSelectorCommit, sizeof(commit)) != 0 ||
        std::memcmp(body, "SJR1", 4) != 0 || get32(body + 4) != 1) return false;
    value.sequence = get64(body + 8);
    value.version = get32(body + 16);
    value.slot = get32(body + 20);
    std::memcpy(value.digest.data(), body + 24, 32);
    return value.sequence != 0 && value.version != 0 && value.slot < 2;
}
}

Result Engine::load_selector(bool& found) {
    found = false;
    selector_sequence_ = 0; selector_page_ = selector_record_ = -1;
    // No read error may be ignored: an inaccessible page can contain the
    // authoritative, newer selector even when the other page is readable.
    for (unsigned page = 0; page < 2; ++page) {
        for (unsigned record = 0; record < kRecordsPerPage; ++record) {
            uint8_t encoded[kJournalRecordBytes];
            if (!storage_.read(2 + page, record * kJournalRecordBytes, encoded, sizeof(encoded)))
                return fail("journal_read");
            Selector selector{};
            if (!decode_selector(encoded, selector)) continue;
            if (found && selector.sequence == selector_sequence_) return fail("journal_ambiguous_sequence");
            if (!found || selector.sequence > selector_sequence_) {
                found = true; selector_sequence_ = selector.sequence;
                selected_version_ = selector.version; selected_slot_ = selector.slot;
                selected_digest_ = selector.digest;
                selector_page_ = int(page); selector_record_ = int(record);
            }
        }
    }
    return pass();
}

Result Engine::select(unsigned slot, const Model& model, Hook hook, void* context,
                      UpdateTimings* timings, Clock* clock) {
    if (selector_sequence_ == std::numeric_limits<uint64_t>::max()) return fail("journal_sequence_exhausted");
    unsigned page = selector_page_ < 0 ? 0u : unsigned(selector_page_);
    int record = -1;
    {
        Duration duration(timings, clock, &UpdateTimings::journal_prepare, 1u << 6);
        const unsigned first = selector_record_ < 0 ? 0u : unsigned(selector_record_ + 1);
        for (unsigned i = first; i < kRecordsPerPage; ++i) {
            uint8_t bytes[kJournalRecordBytes];
            if (!storage_.read(2 + page, i * kJournalRecordBytes, bytes, sizeof(bytes))) return fail("journal_read");
            // A torn record is consumed, never overwritten. Appending only to
            // all-FF records excludes mixing writes from different attempts.
            if (blank_record(bytes)) { record = int(i); break; }
        }
        if (record < 0) {
            page = 1u - page;
            if (!storage_.erase(2 + page)) return fail("journal_erase");
            if (timings) timings->journal_erase_bytes += kJournalPageBytes;
            bool erased = false;
            if (!is_erased(2 + page, erased)) return fail("journal_read");
            if (!erased) return fail("journal_erase_readback");
            record = 0;
        }
    }
    uint8_t plain[56]{};
    std::memcpy(plain, "SJR1", 4); put32(plain + 4, 1);
    const uint64_t next = selector_sequence_ + 1;
    put64(plain + 8, next); put32(plain + 16, model.version); put32(plain + 20, slot);
    std::memcpy(plain + 24, model.digest.data(), 32);
    uint8_t encoded[kJournalRecordBytes];
    rail_encode(plain, sizeof(plain), encoded);
    rail_encode(kSelectorCommit, sizeof(kSelectorCommit), encoded + kSelectorBody);
    const size_t offset = unsigned(record) * kJournalRecordBytes;
    {
        Duration duration(timings, clock, &UpdateTimings::journal_body, 1u << 7);
        if (!storage_.write(2 + page, offset, encoded, kSelectorBody)) return fail("journal_body_write");
        if (timings) timings->journal_write_bytes += kSelectorBody;
        uint8_t check[kSelectorBody];
        if (!storage_.read(2 + page, offset, check, sizeof(check))) return fail("journal_read");
        if (std::memcmp(check, encoded, sizeof(check)) != 0) return fail("journal_body_readback");
    }
    if (interrupted(hook, context, Checkpoint::AfterJournalBody)) return fail("interrupted_after_journal_body");
    {
        Duration duration(timings, clock, &UpdateTimings::journal_commit, 1u << 8);
        if (!storage_.write(2 + page, offset + kSelectorBody, encoded + kSelectorBody,
                            kJournalRecordBytes - kSelectorBody)) return fail("journal_commit_write");
        if (timings) timings->journal_write_bytes += kJournalRecordBytes - kSelectorBody;
        uint8_t check[kJournalRecordBytes];
        if (!storage_.read(2 + page, offset, check, sizeof(check))) return fail("journal_read");
        if (std::memcmp(check, encoded, sizeof(check)) != 0) return fail("journal_commit_readback");
    }
    selector_sequence_ = next; selector_page_ = int(page); selector_record_ = record;
    selected_version_ = model.version; selected_slot_ = slot; selected_digest_ = model.digest;
    if (interrupted(hook, context, Checkpoint::AfterCommit)) return fail("interrupted_after_commit");
    return pass();
}

Result Engine::boot() {
    ready_ = false;
    active_slot_ = -1;
    auto factory_result = validate(factory_, factory_size_, factory_model_);
    if (!factory_result.ok) return fail("invalid_factory");
    bool found = false;
    auto selector_result = load_selector(found);
    if (!selector_result.ok) return selector_result;
    if (found) {
        Model selected{};
        const auto model_result = read_committed(selected_slot_, selected);
        if (!model_result.ok) return fail("selected_slot_invalid");
        if (selected.version != selected_version_ || selected.digest != selected_digest_)
            return fail("selected_slot_binding");
        if (selected.version < factory_model_.version) return fail("below_factory_version");
        active_slot_ = int(selected_slot_);
        active_ = selected;
        ready_ = true;
        return pass();
    }
    // No first selector has ever become authoritative. Only virgin storage is
    // automatically provisioned. An interrupted initial provisioning fails
    // closed, rather than mistaking corrupt/legacy storage for a factory reset.
    for (unsigned area = 0; area < 4; ++area) {
        bool erased = false;
        if (!is_erased(area, erased)) return fail("storage_read");
        if (!erased) return fail("unprovisioned_dirty_store");
    }
    auto install_result = install(0, factory_, factory_size_, nullptr, nullptr);
    if (!install_result.ok) return install_result;
    auto select_result = select(0, factory_model_, nullptr, nullptr);
    if (!select_result.ok) return select_result;
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
    // Bound both the envelope and the slot header before any storage mutation.
    // Do not invalidate or erase the selected slot/journal: until a new selector
    // is committed, a partially erased inactive prefix is not authoritative.
    const size_t erase_bytes = model_erase_bytes_for_length(length, erase_policy_);
    if (!envelope || slot >= 2 || erase_bytes == 0 || erase_bytes > kSlotBytes)
        return fail("storage_capacity");
    {
        Duration duration(timings, clock, &UpdateTimings::erase, 1u << 1);
        if (!storage_.erase_range(slot, 0, erase_bytes)) return fail("storage_erase");
        if (timings) timings->model_erase_bytes += erase_bytes;
    }
    if (interrupted(hook, context, Checkpoint::AfterErase)) return fail("interrupted_after_erase");
    std::array<uint8_t, 4 + kMaxEnvelope> body{};
    put32(body.data(), uint32_t(length));
    std::memcpy(body.data() + 4, envelope, length);
    {
        Duration duration(timings, clock, &UpdateTimings::body_write, 1u << 2);
        if (!storage_.write(slot, 4, body.data(), length + 4)) return fail("storage_write");
        if (timings) timings->model_write_bytes += length + 4;
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
        if (timings) timings->model_write_bytes += sizeof(marker);
        uint8_t committed[4];
        if (!storage_.read(slot, 0, committed, sizeof(committed))) return fail("storage_read");
        if (std::memcmp(marker, committed, sizeof(marker)) != 0) return fail("commit_readback");
    }
    if (interrupted(hook, context, Checkpoint::AfterSlotCommit)) return fail("interrupted_after_slot_commit");
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
    if (result.ok) result = select(target, candidate, hook, context, timings, clock);
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
    if (runtime_abi_ == 3) {
        for (unsigned i = 0; i < count; ++i) {
            if (!std::isfinite(values[i])) return fail("nonfinite_input");
            if (values[i] < 0) return fail("negative_raw_input");
        }
        if (!infer_tree(active_.tree, values, count, probability)) return fail("tree_inference");
        label = probability > preprocessing.threshold ? 1 : 0;
        return pass();
    }
    if (runtime_abi_ >= 4) {
        std::array<float,8> x{};
        for (unsigned i=0; i<count; ++i) {
            if (!std::isfinite(values[i])) return fail("nonfinite_input");
            if (values[i]<0) return fail("negative_raw_input");
            const float transformed=::log1pf(values[i]);
            const float shifted=transformed-preprocessing.means[i];
            x[i]=shifted/preprocessing.scales[i];
            if(!std::isfinite(x[i])) return fail("arithmetic_overflow");
        }
        int qlabel=-1;
        if(!infer_mlp(active_.mlp,runtime_abi_,x.data(),probability,qlabel))return fail("mlp_inference");
        label=runtime_abi_==5?qlabel:(probability>preprocessing.threshold?1:0);
        return pass();
    }
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
