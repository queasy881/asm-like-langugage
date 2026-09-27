#pragma once
#include "support/common.h"

namespace dc::ast {

// Constants worth recognising by name: seeing FNV1A_PRIME_32 says what the
// code is doing in a way that 0x01000193 does not.
struct NamedConstant {
    u64 value;
    unsigned bits;
    const char* name;
};

inline constexpr NamedConstant kNamedConstants[] = {
    {0x811c9dc5ull, 32, "FNV1A_OFFSET_32"},
    {0x01000193ull, 32, "FNV1A_PRIME_32"},
    {0xcbf29ce484222325ull, 64, "FNV1A_OFFSET_64"},
    {0x00000100000001b3ull, 64, "FNV1A_PRIME_64"},
    {0xdeadbeefull, 32, "DEADBEEF"},
    {0xcafebabeull, 32, "CAFEBABE"},
    {0xedb88320ull, 32, "CRC32_POLY_REVERSED"},
    {0x04c11db7ull, 32, "CRC32_POLY"},
    {0xcc9e2d51ull, 32, "MURMUR3_C1"},
    {0x1b873593ull, 32, "MURMUR3_C2"},
    {0x85ebca6bull, 32, "MURMUR3_FMIX1"},
    {0xc2b2ae35ull, 32, "MURMUR3_FMIX2"},
    {0x9e3779b9ull, 32, "GOLDEN_RATIO_32"},
    {0x9e3779b97f4a7c15ull, 64, "GOLDEN_RATIO_64"},
    {0x2545f4914f6cdd1dull, 64, "XORSHIFT_MULT"},
    {0xbf58476d1ce4e5b9ull, 64, "SPLITMIX_MIX1"},
    {0x94d049bb133111ebull, 64, "SPLITMIX_MIX2"},
};

inline const char* namedConstant(u64 v, unsigned bits) {
    for (const auto& c : kNamedConstants)
        if (c.value == v && c.bits == bits) return c.name;
    return nullptr;
}

} // namespace dc::ast
