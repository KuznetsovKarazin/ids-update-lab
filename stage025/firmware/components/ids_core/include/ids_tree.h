#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

namespace ids {
constexpr size_t kMaxTreeNodes = 127;
struct TreeNode {
    int16_t left = -1, right = -1, feature = -1;
    uint16_t reserved = 0;
    float split = 0, probability = 0;
};
struct TreeData {
    uint32_t node_count = 0;
    std::array<TreeNode, kMaxTreeNodes> nodes{};
};
// Decode only the ABI3 tree body. The caller verifies the signed envelope,
// common header, feature contract, release, version and decision threshold.
bool decode_tree_body(const uint8_t* payload, size_t length,
                      uint32_t feature_count, TreeData& tree);
bool infer_tree(const TreeData& tree, const float* values, size_t count,
                float& probability);
}
