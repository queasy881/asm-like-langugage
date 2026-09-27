// Strings, global data and import recognition.
#pragma once

#include "analysis/program.h"

namespace dc::winapi {

enum class StringKind : u8 { Ascii, Utf16 };

struct FoundString {
    u64 address = 0;
    StringKind kind = StringKind::Ascii;
    std::string text;      // UTF-8
    size_t length = 0;     // in characters
    bool inReadOnly = false;
};

struct DataAnalysis {
    std::vector<FoundString> strings;
    std::map<u64, size_t> stringAt;  // address -> index

    const FoundString* stringAtAddress(u64 va) const {
        auto it = stringAt.find(va);
        return it == stringAt.end() ? nullptr : &strings[it->second];
    }
};

struct StringScanOptions {
    size_t minAsciiLength = 4;
    size_t minUtf16Length = 4;
    size_t maxLength = 4096;
};

DataAnalysis scanStrings(const pe::Image& img, const StringScanOptions& opt = {});

} // namespace dc::winapi
