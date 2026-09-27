#include "winapi/data_analysis.h"

#include <algorithm>

namespace dc::winapi {

namespace {

bool isPrintableAscii(u8 c) { return (c >= 0x20 && c < 0x7F) || c == '\t' || c == '\n' || c == '\r'; }

void appendUtf8(std::string& out, u32 cp) {
    if (cp < 0x80) out += (char)cp;
    else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
    else { out += (char)(0xE0 | (cp >> 12)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
}

} // namespace

DataAnalysis scanStrings(const pe::Image& img, const StringScanOptions& opt) {
    DataAnalysis out;
    for (const auto& s : img.sections()) {
        if (s.isExecutable() && !s.isReadable()) continue;
        u64 base = img.imageBase() + s.virtualAddress;
        u32 len = std::min(s.rawSize, s.mappedSize());
        if (!len) continue;
        std::vector<u8> bytes(len);
        if (!img.read(base, bytes.data(), len)) continue;
        bool readOnly = !s.isWritable();

        // ASCII runs terminated by NUL.
        for (u32 i = 0; i < len;) {
            if (!isPrintableAscii(bytes[i])) { ++i; continue; }
            u32 start = i;
            while (i < len && isPrintableAscii(bytes[i]) && i - start < opt.maxLength) ++i;
            u32 runLen = i - start;
            bool terminated = i < len && bytes[i] == 0;
            if (runLen >= opt.minAsciiLength && terminated) {
                FoundString fs;
                fs.address = base + start;
                fs.kind = StringKind::Ascii;
                fs.text.assign((const char*)bytes.data() + start, runLen);
                fs.length = runLen;
                fs.inReadOnly = readOnly;
                out.stringAt[fs.address] = out.strings.size();
                out.strings.push_back(std::move(fs));
            }
            if (i < len && bytes[i] == 0) ++i;
        }
        // UTF-16LE runs: printable code unit, zero high byte, NUL terminated.
        for (u32 i = 0; i + 1 < len;) {
            if (!(isPrintableAscii(bytes[i]) && bytes[i + 1] == 0)) { ++i; continue; }
            u32 start = i;
            std::string text;
            while (i + 1 < len && bytes[i + 1] == 0 && isPrintableAscii(bytes[i]) && text.size() < opt.maxLength) {
                appendUtf8(text, bytes[i]);
                i += 2;
            }
            bool terminated = i + 1 < len && bytes[i] == 0 && bytes[i + 1] == 0;
            if (text.size() >= opt.minUtf16Length && terminated) {
                FoundString fs;
                fs.address = base + start;
                fs.kind = StringKind::Utf16;
                fs.text = std::move(text);
                fs.length = fs.text.size();
                fs.inReadOnly = readOnly;
                if (!out.stringAt.count(fs.address)) {
                    out.stringAt[fs.address] = out.strings.size();
                    out.strings.push_back(std::move(fs));
                }
            }
            if (i + 1 < len) i += 2;
        }
    }
    std::sort(out.strings.begin(), out.strings.end(),
              [](const FoundString& a, const FoundString& b) { return a.address < b.address; });
    out.stringAt.clear();
    for (size_t i = 0; i < out.strings.size(); ++i) out.stringAt[out.strings[i].address] = i;
    return out;
}

} // namespace dc::winapi
