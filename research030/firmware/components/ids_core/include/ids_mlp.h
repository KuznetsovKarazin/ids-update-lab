#pragma once
#include <array>
#include <cstdint>
#include <cstddef>

namespace ids {
constexpr size_t kMlpWeights = 264, kMlpBiases = 25;
struct MlpData {
    std::array<float, kMlpWeights> weights{};
    std::array<float, kMlpBiases> biases{};
    std::array<int8_t, kMlpWeights> qweights{};
    std::array<int32_t, kMlpBiases> qbiases{};
    std::array<uint32_t, 3> multipliers{}, shifts{};
    std::array<float, 3> output_scales{};
    float input_scale = 1;
    int32_t qthreshold = 1;
};
// ABI4/5 fixed topology 8->16->8->1; hidden ReLU. Values are already
// log1p/standardized by Engine, whose signed feature contract binds units.
bool decode_mlp_body(const uint8_t* payload, size_t length, uint32_t abi, MlpData& model);
bool infer_mlp(const MlpData& model, uint32_t abi, const float* standardized,
               float& probability, int& quantized_label);
int32_t mlp_round_shift_away(int64_t value, uint32_t shift);
}
