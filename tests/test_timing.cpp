// Deterministic timing-boundary/failure tests of actual shared Engine.
// Crypto is deliberately a timing mock here; test_native.py checks real RSA.
#include "ids_core.h"
#include "model_contract.h"
#include <array>
#include <cassert>
#include <cstring>
#include <vector>

struct FakeClock final : ids::Clock {
    uint64_t now = 0;
    unsigned reads = 0;
    uint64_t microseconds() override { ++reads; return now; }
};
struct Crypto final : ids::Crypto {
    explicit Crypto(FakeClock& c) : clock(c) {}
    FakeClock& clock;
    unsigned verifies = 0, fail_verify = 0;
    bool verify(const uint8_t*, size_t, const uint8_t*) override {
        clock.now += 11;
        return ++verifies != fail_verify;
    }
    bool sha256(const uint8_t*, size_t, uint8_t* out) override {
        clock.now += 3; std::memset(out, 0, 32); return true;
    }
};
enum class Fault { None, Erase, BodyWrite, Readback, ReadbackMismatch, CommitWrite, CommitRead };
struct Storage final : ids::Storage {
    explicit Storage(FakeClock& c) : clock(c) { for (auto& slot : data) slot.fill(0xff); }
    FakeClock& clock;
    std::array<std::array<uint8_t, ids::kSlotBytes>, 2> data;
    Fault fault = Fault::None;
    bool read(unsigned slot, size_t offset, void* out, size_t length) override {
        clock.now += 3;
        if ((offset == 4 && fault == Fault::Readback) || (offset == 0 && fault == Fault::CommitRead)) return false;
        std::memcpy(out, data[slot].data() + offset, length);
        if (offset == 4 && fault == Fault::ReadbackMismatch) static_cast<uint8_t*>(out)[4] ^= 1;
        return true;
    }
    bool write(unsigned slot, size_t offset, const void* source, size_t length) override {
        clock.now += 7;
        if ((offset == 4 && fault == Fault::BodyWrite) || (offset == 0 && fault == Fault::CommitWrite)) return false;
        const auto* bytes = static_cast<const uint8_t*>(source);
        for (size_t i = 0; i < length; ++i) {
            assert((data[slot][offset + i] & bytes[i]) == bytes[i]);
            data[slot][offset + i] = bytes[i];
        }
        return true;
    }
    bool erase(unsigned slot) override {
        clock.now += 5;
        if (fault == Fault::Erase) return false;
        data[slot].fill(0xff); return true;
    }
};
struct Fixture {
    FakeClock clock;
    Storage storage{clock};
    Crypto crypto{clock};
    ids::Engine engine{storage, crypto, ids_generated::kFactoryEnvelope, sizeof(ids_generated::kFactoryEnvelope),
                       ids_generated::kFeatureCount, ids_generated::kFeatureContractHash};
    std::vector<uint8_t> candidate{ids_generated::kFactoryEnvelope,
                                 ids_generated::kFactoryEnvelope + sizeof(ids_generated::kFactoryEnvelope)};
    Fixture() {
        assert(engine.boot().ok);
        assert(clock.reads == 0); // Boot has no implicit platform/system clock.
        clock.now = 0; crypto.verifies = 0;
        candidate[32] = 2; candidate[33] = candidate[34] = candidate[35] = 0;
    }
    ids::Result update(ids::UpdateTimings& timing) {
        return engine.update(candidate.data(), candidate.size(), nullptr, nullptr, &timing, &clock);
    }
};
uint64_t sum(const ids::UpdateTimings& t) {
    return t.candidate_verify + t.erase + t.body_write + t.readback + t.readback_verify + t.commit;
}

struct HookContext { FakeClock* clock; ids::Checkpoint wanted; };
bool stop(ids::Checkpoint checkpoint, void* opaque) {
    auto& context = *static_cast<HookContext*>(opaque);
    if (checkpoint != context.wanted) return false;
    context.clock->now += 100; // Hook work belongs to total, not a storage stage.
    return true;
}

int main() {
    {
        Fixture f; ids::UpdateTimings t;
        assert(f.update(t).ok && t.measured && t.executed_mask == 63);
        assert(t.candidate_verify == 14 && t.erase == 5 && t.body_write == 7 && t.readback == 3);
        assert(t.readback_verify == 14 && t.commit == 10 && t.total == 53 && sum(t) == t.total);
    }
    for (auto fault : {Fault::Erase, Fault::BodyWrite, Fault::Readback, Fault::ReadbackMismatch,
                       Fault::CommitWrite, Fault::CommitRead}) {
        Fixture f; f.storage.fault = fault; ids::UpdateTimings t;
        const auto result = f.update(t);
        assert(!result.ok && !f.engine.ready() && t.measured);
        const uint32_t mask = fault == Fault::Erase ? 3 : fault == Fault::BodyWrite ? 7 :
            (fault == Fault::Readback || fault == Fault::ReadbackMismatch) ? 15 : 63;
        assert(t.executed_mask == mask && sum(t) == t.total);
    }
    for (unsigned failing_verify : {1u, 2u}) {
        Fixture f; f.crypto.fail_verify = failing_verify; ids::UpdateTimings t;
        assert(!f.update(t).ok);
        assert(t.executed_mask == (failing_verify == 1 ? 1u : 31u));
        assert(sum(t) == t.total);
        assert(f.engine.ready() == (failing_verify == 1));
    }
    {
        Fixture f; ids::UpdateTimings t;
        f.engine.fail_closed();
        assert(!f.update(t).ok && t.measured && t.executed_mask == 0 && t.total == 0);
    }
    {
        Fixture f; ids::UpdateTimings t; t.total = 999; t.executed_mask = 63;
        assert(f.engine.update(f.candidate.data(), f.candidate.size(), nullptr, nullptr, &t).ok);
        assert(!t.measured && t.total == 0 && t.executed_mask == 0 && f.clock.reads == 0);
    }
    for (auto checkpoint : {ids::Checkpoint::AfterErase, ids::Checkpoint::AfterWrite,
                            ids::Checkpoint::AfterVerify, ids::Checkpoint::AfterCommit}) {
        Fixture f; ids::UpdateTimings t; HookContext hook{&f.clock, checkpoint};
        assert(!f.engine.update(f.candidate.data(), f.candidate.size(), stop, &hook, &t, &f.clock).ok);
        const uint32_t mask = checkpoint == ids::Checkpoint::AfterErase ? 3 :
            checkpoint == ids::Checkpoint::AfterWrite ? 7 : checkpoint == ids::Checkpoint::AfterVerify ? 31 : 63;
        assert(t.executed_mask == mask && t.total == sum(t) + 100);
    }
}
