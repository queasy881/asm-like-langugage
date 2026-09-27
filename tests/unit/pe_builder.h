// Builds minimal but valid PE32 / PE32+ images in memory so that lifting and
// analysis can be tested on exact instruction sequences, for both x86 and x64.
#pragma once

#include "support/common.h"

#include <cstring>
#include <string>
#include <vector>

namespace dctest {

using namespace dc;

struct PeBuilder {
    bool is64 = true;
    u64 imageBase = 0x140000000ull;
    u32 codeRva = 0x1000;
    u32 dataRva = 0x2000;
    std::vector<u8> code;
    std::vector<u8> data;
    u32 entryRva = 0x1000;

    std::vector<u8> build() const {
        const u32 fileAlign = 0x200, sectAlign = 0x1000;
        const u32 optSize = is64 ? 240 : 224;
        const u32 headerSize = 0x40 + 4 + 20 + optSize + 2 * 40;
        const u32 headersRaw = (headerSize + fileAlign - 1) / fileAlign * fileAlign;
        u32 codeRaw = headersRaw;
        u32 codeRawSize = ((u32)code.size() + fileAlign - 1) / fileAlign * fileAlign;
        if (codeRawSize == 0) codeRawSize = fileAlign;
        u32 dataRaw = codeRaw + codeRawSize;
        u32 dataRawSize = ((u32)data.size() + fileAlign - 1) / fileAlign * fileAlign;
        if (dataRawSize == 0) dataRawSize = fileAlign;

        std::vector<u8> f(dataRaw + dataRawSize, 0);
        auto w16 = [&](u32 off, u16 v) { std::memcpy(f.data() + off, &v, 2); };
        auto w32 = [&](u32 off, u32 v) { std::memcpy(f.data() + off, &v, 4); };
        auto w64 = [&](u32 off, u64 v) { std::memcpy(f.data() + off, &v, 8); };

        f[0] = 'M'; f[1] = 'Z';
        w32(0x3C, 0x40);
        u32 pe = 0x40;
        w32(pe, 0x00004550);
        u32 coff = pe + 4;
        w16(coff + 0, is64 ? 0x8664 : 0x014c);
        w16(coff + 2, 2);                 // sections
        w16(coff + 16, (u16)optSize);
        w16(coff + 18, 0x0022);           // executable | large address aware
        u32 opt = coff + 20;
        w16(opt, is64 ? 0x20b : 0x10b);
        w32(opt + 16, entryRva);
        if (is64) w64(opt + 24, imageBase);
        else w32(opt + 28, (u32)imageBase);
        w32(opt + 32, sectAlign);
        w32(opt + 36, fileAlign);
        w32(opt + 56, dataRva + ((dataRawSize + sectAlign - 1) / sectAlign) * sectAlign);
        w32(opt + 60, headersRaw);
        w16(opt + 68, 3);                 // console subsystem
        w32(is64 ? opt + 108 : opt + 92, 16);

        u32 sect = opt + optSize;
        auto section = [&](u32 off, const char* name, u32 rva, u32 vsize, u32 raw, u32 rawSize, u32 chars) {
            std::memcpy(f.data() + off, name, std::min<size_t>(8, std::strlen(name)));
            w32(off + 8, vsize);
            w32(off + 12, rva);
            w32(off + 16, rawSize);
            w32(off + 20, raw);
            w32(off + 36, chars);
        };
        section(sect, ".text", codeRva, (u32)std::max<size_t>(code.size(), 1), codeRaw, codeRawSize, 0x60000020);
        section(sect + 40, ".data", dataRva, (u32)std::max<size_t>(data.size(), 1), dataRaw, dataRawSize, 0xC0000040);
        if (!code.empty()) std::memcpy(f.data() + codeRaw, code.data(), code.size());
        if (!data.empty()) std::memcpy(f.data() + dataRaw, data.data(), data.size());
        return f;
    }

    u64 codeVa() const { return imageBase + codeRva; }
    u64 dataVa() const { return imageBase + dataRva; }
};

} // namespace dctest
