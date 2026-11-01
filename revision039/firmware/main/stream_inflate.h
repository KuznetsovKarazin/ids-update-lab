// Author: Oleksandr Kuznetsov
#pragma once
#include <cstddef>
#include <cstdint>
#include "miniz_tinfl.h"

// Fixed-memory zlib decoder. Sink receives reconstructed bytes, never compressed
// bytes. Enforces one complete stream, exact signed output length, no trailers.
class StreamInflate {
public:
    using Sink = bool (*)(void*, const uint8_t*, size_t);
    void reset(size_t expected) {
        tinfl_init(&decoder_); expected_ = expected; output_ = 0;
        ring_offset_ = 0; done_ = false; failed_ = false;
    }
    bool feed(const uint8_t* input, size_t length, bool final, Sink sink, void* context) {
        if (failed_ || done_ || !input || !length || !sink) return fail();
        size_t consumed = 0;
        for (;;) {
            size_t available = length - consumed;
            size_t produced = sizeof(ring_) - ring_offset_;
            const auto status = tinfl_decompress(&decoder_, input + consumed, &available,
                ring_, ring_ + ring_offset_, &produced,
                TINFL_FLAG_PARSE_ZLIB_HEADER | (final ? 0 : TINFL_FLAG_HAS_MORE_INPUT));
            consumed += available;
            if (status < TINFL_STATUS_DONE || produced > expected_ - output_) return fail();
            if (produced && !sink(context, ring_ + ring_offset_, produced)) return fail();
            output_ += produced;
            ring_offset_ = (ring_offset_ + produced) % sizeof(ring_);
            if (status == TINFL_STATUS_DONE) {
                if (!final || consumed != length || output_ != expected_) return fail();
                done_ = true; return true;
            }
            if (status == TINFL_STATUS_NEEDS_MORE_INPUT) {
                if (final || consumed != length) return fail();
                return true;
            }
            if (status != TINFL_STATUS_HAS_MORE_OUTPUT || (!available && !produced)) return fail();
        }
    }
    bool complete() const { return done_ && !failed_ && output_ == expected_; }
    size_t output_bytes() const { return output_; }
private:
    bool fail() { failed_ = true; return false; }
    tinfl_decompressor decoder_{};
    uint8_t ring_[TINFL_LZ_DICT_SIZE]{};
    size_t expected_ = 0, output_ = 0, ring_offset_ = 0;
    bool done_ = false, failed_ = false;
};
