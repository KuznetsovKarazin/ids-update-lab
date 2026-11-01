#pragma once
#include "ids_core.h"
#include <cstdint>
#include <string>

namespace ids {
constexpr size_t kMaxLine = 2 * kMaxEnvelope + 32;
std::string json_quote(const char* text);
std::string digest_hex(const std::array<uint8_t, 32>& digest);
struct Platform : public Clock {
    virtual ~Platform() = default;
    virtual uint64_t microseconds() = 0;
    virtual size_t free_heap() = 0;
    virtual const char* chip() = 0;
    virtual const char* build() = 0;
    virtual const char* origin() = 0;
    virtual void output(const std::string& json) = 0;
    virtual void restart() = 0;
    // False means unavailable (e.g. native adapter); never report host zero as
    // a measured MCU key setup duration.
    virtual bool crypto_metrics(uint64_t& key_setup_us, uint64_t& first_verify_us) const {
        (void)key_setup_us; (void)first_verify_us; return false;
    }
};

class Protocol {
public:
    Protocol(Engine& engine, Platform& platform, const uint8_t* schema, unsigned features,
             bool factory_only = false);
    void status(const char* event = "status", const char* reason = "ok");
    void process(const char* line);
    void line_error(const char* reason);
private:
    static bool fail_hook(Checkpoint checkpoint, void* context);
    Engine& engine_;
    Platform& platform_;
    const uint8_t* schema_;
    unsigned features_;
    bool factory_only_;
    Checkpoint armed_ = Checkpoint::None;
};
}
