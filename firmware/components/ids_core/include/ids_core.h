#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ids {
constexpr size_t kMaxFeatures = 16;
constexpr size_t kMaxEnvelope = 544;
constexpr size_t kSlotBytes = 65536;
constexpr uint32_t kCommit = 0x53494453;

struct Model {
    uint32_t version = 0;
    uint32_t count = 0;
    char release[17]{};
    float threshold = 0;
    float bias = 0;
    std::array<float, kMaxFeatures> means{}, scales{}, weights{};
    std::array<uint8_t, 32> digest{};
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
};

enum class Checkpoint { None, AfterErase, AfterWrite, AfterVerify, AfterCommit };
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
    // Bits 0..5 correspond to the six non-total fields above. Zero elapsed
    // time is valid at microsecond resolution; the mask distinguishes skipped.
    uint32_t executed_mask = 0;
    bool measured = false;
};

class Engine {
public:
    Engine(Storage& storage, Crypto& crypto, const uint8_t* factory, size_t factory_size,
           unsigned feature_count, const uint8_t* contract_hash, bool model_only = false);
    Result boot();
    Result boot_factory_only();
    Result update(const uint8_t* envelope, size_t length, Hook hook = nullptr, void* context = nullptr,
                  UpdateTimings* timings = nullptr, Clock* clock = nullptr);
    Result infer(const float* values, size_t count, float& probability, int& label) const;
    bool ready() const { return ready_; }
    void fail_closed() { ready_ = false; active_slot_ = -1; }
    const Model& model() const { return active_; }
    const char* policy() const { return model_only_ ? "model_only_factory_preprocess" : "bundle"; }
    int active_slot() const { return active_slot_; }
    Result validate(const uint8_t* envelope, size_t length, Model& model);

private:
    Result install(unsigned slot, const uint8_t* envelope, size_t length, Hook hook, void* context,
                   UpdateTimings* timings = nullptr, Clock* clock = nullptr);
    bool is_erased(unsigned slot, bool& erased);
    Result read_committed(unsigned slot, Model& model);
    Storage& storage_;
    Crypto& crypto_;
    const uint8_t* factory_;
    size_t factory_size_;
    unsigned count_;
    const uint8_t* contract_hash_;
    bool model_only_;
    bool ready_ = false;
    int active_slot_ = -1;
    Model active_{}, factory_model_{};
};
}
