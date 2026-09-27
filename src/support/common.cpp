#include "support/common.h"

#include <cstdarg>
#include <cstdio>
#include <cctype>

namespace dc {

std::string strfmt(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = std::vsnprintf(nullptr, 0, fmt, ap);
    va_end(ap);
    std::string out;
    if (n > 0) {
        out.resize((size_t)n + 1);
        std::vsnprintf(out.data(), out.size(), fmt, ap2);
        out.resize((size_t)n);
    }
    va_end(ap2);
    return out;
}

std::string hex(u64 v) { return strfmt("0x%llx", (unsigned long long)v); }
std::string hexPlain(u64 v) { return strfmt("%llx", (unsigned long long)v); }
std::string hexPad(u64 v, int width) { return strfmt("%0*llx", width, (unsigned long long)v); }

u64 fnv1a64(const void* data, size_t len, u64 seed) {
    const u8* p = (const u8*)data;
    u64 h = seed;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

std::string toLower(std::string_view s) {
    std::string r(s);
    for (char& c : r) c = (char)std::tolower((unsigned char)c);
    return r;
}

bool startsWith(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

bool endsWith(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

std::string escapeCString(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (unsigned char c : s) {
        switch (c) {
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\0': out += "\\0"; break;
        default:
            if (c < 0x20 || c >= 0x7f) out += strfmt("\\%03o", c); // octal: never merges with following chars
            else out += (char)c;
        }
    }
    return out;
}

} // namespace dc

namespace dc {

std::string sanitizeIdentifier(const std::string& name) {
    std::string out;
    out.reserve(name.size());
    for (char c : name) out += (std::isalnum((unsigned char)c) || c == '_') ? c : '_';
    if (out.empty() || std::isdigit((unsigned char)out[0])) out.insert(out.begin(), '_');
    return out;
}

} // namespace dc
