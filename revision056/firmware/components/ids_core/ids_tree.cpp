#include "ids_tree.h"
#include <cmath>
#include <cstring>

namespace ids {
namespace {
uint32_t get32(const uint8_t* p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
int16_t get16(const uint8_t* p) {
    const uint16_t u = uint16_t(p[0]) | uint16_t(p[1]) << 8;
    return u < 0x8000u ? static_cast<int16_t>(u) : static_cast<int16_t>(int32_t(u) - 65536);
}
float get_float(const uint8_t* p) {
    const uint32_t u = get32(p);
    float x;
    std::memcpy(&x, &u, 4);
    return x;
}
}

bool decode_tree_body(const uint8_t* p, size_t length, uint32_t count, TreeData& tree) {
    if (!p || length < 80 || count == 0 || count > 16) return false;
    const uint32_t n = get32(p + 76);
    if (n == 0 || n > kMaxTreeNodes || length != 80 + 16 * n) return false;
    TreeData candidate{};
    candidate.node_count = n;
    std::array<unsigned, kMaxTreeNodes> parents{};
    for (uint32_t i = 0; i < n; ++i) {
        const uint8_t* q = p + 80 + 16 * i;
        auto& node = candidate.nodes[i];
        node.left = get16(q); node.right = get16(q + 2); node.feature = get16(q + 4);
        node.reserved = uint16_t(q[6]) | uint16_t(q[7]) << 8;
        node.split = get_float(q + 8); node.probability = get_float(q + 12);
        if (node.reserved || !std::isfinite(node.split) || !std::isfinite(node.probability)
            || node.probability < 0 || node.probability > 1) return false;
        if (node.left == -1 && node.right == -1) {
            if (node.feature != -1 || node.split != 0) return false;
        } else {
            if (node.left < 0 || node.right < 0 || node.left == node.right
                || uint32_t(node.left) >= n || uint32_t(node.right) >= n
                || node.feature < 0 || uint32_t(node.feature) >= count || node.split < 0) return false;
            if (++parents[node.left] != 1 || ++parents[node.right] != 1) return false;
        }
    }
    if (parents[0] != 0) return false;
    for (uint32_t i = 1; i < n; ++i) if (parents[i] != 1) return false;
    // Explicit traversal also rejects a disconnected cyclic component.
    std::array<bool, kMaxTreeNodes> seen{};
    std::array<uint32_t, kMaxTreeNodes> pending{};
    size_t top = 1, visited = 0;
    pending[0] = 0;
    while (top) {
        const uint32_t i = pending[--top];
        if (seen[i]) return false;
        seen[i] = true; ++visited;
        const auto& node = candidate.nodes[i];
        if (node.left >= 0) {
            if (top + 2 > pending.size()) return false;
            pending[top++] = uint32_t(node.left); pending[top++] = uint32_t(node.right);
        }
    }
    if (visited != n) return false;
    tree = candidate;
    return true;
}

bool infer_tree(const TreeData& tree, const float* x, size_t count, float& p) {
    if (!x || !count || count > 16 || !tree.node_count || tree.node_count > kMaxTreeNodes) return false;
    for (size_t i = 0; i < count; ++i) if (!std::isfinite(x[i]) || x[i] < 0) return false;
    uint32_t i = 0;
    for (uint32_t steps = 0; steps < tree.node_count; ++steps) {
        if (i >= tree.node_count) return false;
        const auto& node = tree.nodes[i];
        if (node.left == -1 && node.right == -1) { p = node.probability; return true; }
        if (node.feature < 0 || size_t(node.feature) >= count) return false;
        i = uint32_t(x[node.feature] <= node.split ? node.left : node.right);
    }
    return false;
}
}
