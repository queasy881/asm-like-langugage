// Common utilities shared by every layer of the decompiler.
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <stdexcept>

namespace dc {

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

// Error raised for conditions that indicate malformed input (bad PE, etc).
// Analysis code catches these per function so one bad function never takes
// down the whole run.
class DecompError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// printf-style formatting into a std::string.
std::string strfmt(const char* fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;

std::string hex(u64 v);            // "0x1a2b"
std::string hexPlain(u64 v);       // "1a2b"
std::string hexPad(u64 v, int width); // zero padded, no prefix

inline u64 maskBits(unsigned bits) {
    return bits >= 64 ? ~0ull : ((1ull << bits) - 1);
}
inline i64 signExtend(u64 v, unsigned bits) {
    if (bits == 0 || bits >= 64) return (i64)v;
    u64 m = 1ull << (bits - 1);
    v &= maskBits(bits);
    return (i64)((v ^ m) - m);
}
inline u64 truncBits(u64 v, unsigned bits) { return v & maskBits(bits); }

// FNV-1a over a byte string; used for stable content-derived identifiers.
u64 fnv1a64(const void* data, size_t len, u64 seed = 0xcbf29ce484222325ull);
inline u64 fnv1a64(std::string_view s, u64 seed = 0xcbf29ce484222325ull) {
    return fnv1a64(s.data(), s.size(), seed);
}

std::string toLower(std::string_view s);
bool startsWith(std::string_view s, std::string_view prefix);
bool endsWith(std::string_view s, std::string_view suffix);
// A symbol out of a binary may hold characters C does not allow in an
// identifier, such as the dot in "t_switch.cold".
std::string sanitizeIdentifier(const std::string& name);

std::string escapeCString(std::string_view s);

} // namespace dc
