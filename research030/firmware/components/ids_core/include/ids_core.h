#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include "ids_tree.h"
#include "ids_mlp.h"

namespace ids {
constexpr size_t kMaxFeatures = 16;
constexpr size_t kMaxEnvelope = 4096;
constexpr size_t kSlotBytes = 65536;
constexpr size_t kEraseSectorBytes = 4096;
constexpr size_t kJournalPageBytes = 4096;
constexpr size_t kJournalRecordBytes = 128;
constexpr uint32_t kCommit = 0x53494453;
static_assert(kSlotBytes % kEraseSectorBytes == 0, "model slots must contain whole sectors");
static_assert(kMaxEnvelope + 8 <= kSlotBytes, "model envelope and header must fit in a slot");

enum class ErasePolicy { FullSlot, NecessarySectors };
const char* erase_policy_name(ErasePolicy policy);
bool parse_erase_policy(const char* text, ErasePolicy& policy);
// Zero denotes an invalid length/policy. This helper includes the eight-byte
// slot header: a generic 4096-byte envelope therefore requires TWO sectors.
constexpr size_t model_erase_bytes_for_length(size_t length, ErasePolicy policy) {
    if (length < 16 || length > kMaxEnvelope || length > kSlotBytes - 8) return 0;
    if (policy == ErasePolicy::FullSlot) return kSlotBytes;
    if (policy == ErasePolicy::NecessarySectors)
        return ((length + 8 + kEraseSectorBytes - 1) / kEraseSectorBytes) * kEraseSectorBytes;
    return 0;
}

struct Model {
    uint32_t runtime_abi = 0;
    uint32_t version = 0;
    uint32_t count = 0;
    char release[17]{};
    float threshold = 0;
    float bias = 0;
    std::array<float, kMaxFeatures> means{}, scales{}, weights{};
    std::array<uint8_t, 32> digest{};
    TreeData tree{};
    MlpData mlp{};
};

class Crypto {
public:
    virtual ~Crypto() = default;
    virtual bool verify(const uint8_t* payload, size_t length, const uint8_t* signature) = 0;
    virtual bool sha256(const uint8_t* bytes, size_t length, uint8_t* digest) = 0;
};

class Storage {
public:
    virtual ~Storage() = default;
    virtual bool read(unsigned slot, size_t offset, void* target, size_t length) = 0;
    virtual bool write(unsigned slot, size_t offset, const void* source, size_t length) = 0;
    virtual bool erase(unsigned slot) = 0;
    // Erase exactly the requested, sector-aligned range. The conservative
    // default retains compatibility with full-area-only storage adapters;
    // it rejects partial requests instead of silently erasing extra sectors.
    virtual bool erase_range(unsigned slot, size_t offset, size_t length) {
        if (slot >= 4 || offset != 0 || length != (slot < 2 ? kSlotBytes : kJournalPageBytes)) return false;
        return erase(slot);
    }
};

enum class Checkpoint { None, AfterErase, AfterWrite, AfterVerify, AfterSlotCommit, AfterJournalBody, AfterCommit };
const char* checkpoint_name(Checkpoint checkpoint);
bool parse_checkpoint(const char* text, Checkpoint& checkpoint);
using Hook = bool (*)(Checkpoint checkpoint, void* context);

struct Result {
    bool ok;
    const char* reason;
};

// Injected monotonic microsecond source: the portable core never assumes a
// system clock. Omit both clock/timings to retain uninstrumented operation.
class Clock {
public:
    virtual ~Clock() = default;
    virtual uint64_t microseconds() = 0;
};

struct UpdateTimings {
    uint64_t candidate_verify = 0, erase = 0, body_write = 0, readback = 0;
    uint64_t readback_verify = 0, commit = 0, total = 0;
    uint64_t journal_prepare = 0, journal_body = 0, journal_commit = 0;
    // Bits 0..5 correspond to candidate through slot commit; bits 6..8 to journal fields. Zero elapsed
    // time is valid at microsecond resolution; the mask distinguishes skipped.
    uint32_t executed_mask = 0;
    bool measured = false;
    // Bytes in storage calls that returned success. These are requested byte
    // counts, not measurements of internal NOR operations or physical wear.
    // Calls returning failure can have partially changed flash and contribute
    // zero here because their completed physical work is not established.
    uint64_t model_erase_bytes = 0, model_write_bytes = 0;
    uint64_t journal_erase_bytes = 0, journal_write_bytes = 0;
};

class Engine {
public:
    Engine(Storage& storage, Crypto& crypto, const uint8_t* factory, size_t factory_size,
           unsigned feature_count, const uint8_t* contract_hash, bool model_only = false,
           uint32_t runtime_abi = 1, ErasePolicy erase_policy = ErasePolicy::FullSlot);
    Result boot();
    Result boot_factory_only();
    Result update(const uint8_t* envelope, size_t length, Hook hook = nullptr, void* context = nullptr,
                  UpdateTimings* timings = nullptr, Clock* clock = nullptr);
    Result infer(const float* values, size_t count, float& probability, int& label) const;
    bool ready() const { return ready_; }
    void fail_closed() { ready_ = false; active_slot_ = -1; }
    const Model& model() const { return active_; }
    const char* policy() const { return model_only_ ? "model_only_factory_preprocess" : "bundle"; }
    const char* erase_policy() const { return erase_policy_name(erase_policy_); }
    int active_slot() const { return active_slot_; }
    uint64_t selector_sequence() const { return selector_sequence_; }
    uint32_t runtime_abi() const { return runtime_abi_; }
    const char* pretransform() const {
        return (runtime_abi_ == 2 || runtime_abi_ == 4 || runtime_abi_ == 5) ? "log1p" : ((runtime_abi_ == 1 || runtime_abi_ == 3) ? "identity" : "unsupported");
    }
    Result validate(const uint8_t* envelope, size_t length, Model& model);

private:
    Result install(unsigned slot, const uint8_t* envelope, size_t length, Hook hook, void* context,
                   UpdateTimings* timings = nullptr, Clock* clock = nullptr);
    bool is_erased(unsigned slot, bool& erased);
    Result load_selector(bool& found);
    Result select(unsigned slot, const Model& model, Hook hook, void* context,
                  UpdateTimings* timings = nullptr, Clock* clock = nullptr);
    Result read_committed(unsigned slot, Model& model);
    Storage& storage_;
    Crypto& crypto_;
    const uint8_t* factory_;
    size_t factory_size_;
    unsigned count_;
    const uint8_t* contract_hash_;
    bool model_only_;
    uint32_t runtime_abi_;
    ErasePolicy erase_policy_;
    bool ready_ = false;
    int active_slot_ = -1;
    uint64_t selector_sequence_ = 0;
    int selector_page_ = -1, selector_record_ = -1;
    uint32_t selected_version_ = 0;
    unsigned selected_slot_ = 0;
    std::array<uint8_t, 32> selected_digest_{};
    Model active_{}, factory_model_{};
};
}
