#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ids {
// Byte-oriented framing shared by firmware and native parser tests. The caller
// must reset after a non-Pending result; no malformed frame is ever processed.
class LineReader {
public:
    static constexpr size_t kLimit = 1200;
    static constexpr size_t kPrefixBytes = 64;
    enum class Result { Pending, Line, InvalidControl, TooLong };

    Result push(uint8_t byte) {
        if (byte == '\n') {
            line_[length_] = '\0';
            return overflow_ ? Result::TooLong : (invalid_ ? Result::InvalidControl : Result::Line);
        }
        if (received_ < prefix_.size()) prefix_[received_] = byte;
        const size_t offset = received_;
        if (received_ != SIZE_MAX) ++received_;
        if (byte == '\r') return Result::Pending;
        if ((byte < 32 || byte > 126) && !invalid_) {
            invalid_ = true;
            bad_byte_ = byte;
            bad_offset_ = offset;
        }
        if (length_ < kLimit) line_[length_++] = char(byte);
        else overflow_ = true;
        return Result::Pending;
    }
    void reset() {
        length_ = 0; received_ = 0; overflow_ = false; invalid_ = false;
        bad_byte_ = 0; bad_offset_ = 0;
        line_[0] = '\0';
    }
    const char* line() const { return line_.data(); }
    size_t length() const { return length_; }
    size_t received() const { return received_; }
    bool invalid() const { return invalid_; }
    unsigned bad_byte() const { return bad_byte_; }
    size_t bad_offset() const { return bad_offset_; }
    const uint8_t* prefix() const { return prefix_.data(); }
    size_t prefix_size() const { return received_ < prefix_.size() ? received_ : prefix_.size(); }
private:
    std::array<char, kLimit + 1> line_{};
    std::array<uint8_t, kPrefixBytes> prefix_{};
    size_t length_ = 0, received_ = 0, bad_offset_ = 0;
    uint8_t bad_byte_ = 0;
    bool overflow_ = false, invalid_ = false;
};
}
