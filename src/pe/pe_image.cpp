#include "pe/pe_image.h"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace dc::pe {

namespace {
constexpr u32 kMaxSections = 1024;
constexpr u32 kMaxImportDescriptors = 4096;
constexpr u32 kMaxThunksPerDll = 65536;
constexpr u32 kMaxExports = 1u << 20;
constexpr u32 kMaxRuntimeFunctions = 1u << 22;
constexpr u32 kMaxCoffSymbols = 1u << 22;

void appendUtf8(std::string& out, u32 cp) {
    if (cp < 0x80) out += (char)cp;
    else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
    else if (cp < 0x10000) {
        out += (char)(0xE0 | (cp >> 12)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F));
    } else {
        out += (char)(0xF0 | (cp >> 18)); out += (char)(0x80 | ((cp >> 12) & 0x3F));
        out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F));
    }
}
} // namespace

const char* machineName(Machine m) {
    switch (m) {
    case Machine::X86: return "x86";
    case Machine::X64: return "x64";
    default: return "unknown";
    }
}

u32 Section::mappedSize() const {
    // A virtual size of zero means "use the raw size" (old linkers).
    if (virtualSize == 0) return rawSize;
    return virtualSize;
}

std::string Import::displayName() const {
    if (!name.empty()) return name;
    return strfmt("Ordinal_%u", ordinal);
}

std::unique_ptr<Image> Image::loadFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw DecompError("cannot open file: " + path);
    f.seekg(0, std::ios::end);
    std::streamoff sz = f.tellg();
    if (sz < 0) throw DecompError("cannot determine size of: " + path);
    if (sz > (std::streamoff)(1ull << 31)) throw DecompError("file too large: " + path);
    f.seekg(0, std::ios::beg);
    std::vector<u8> data((size_t)sz);
    if (sz > 0 && !f.read((char*)data.data(), sz)) throw DecompError("cannot read file: " + path);
    return loadBuffer(std::move(data), path);
}

std::unique_ptr<Image> Image::loadBuffer(std::vector<u8> data, std::string name) {
    std::unique_ptr<Image> img(new Image());
    img->name_ = std::move(name);
    img->data_ = std::move(data);
    img->parse();
    return img;
}

bool Image::fileRead(u64 offset, void* out, size_t n) const {
    if (offset > data_.size() || n > data_.size() - offset) return false;
    if (n) std::memcpy(out, data_.data() + offset, n);
    return true;
}

void Image::parse() {
    parseHeaders();
    // Optional tables: damage here is reported but never fatal.
    auto guarded = [&](const char* what, void (Image::*fn)()) {
        try {
            (this->*fn)();
        } catch (const std::exception& e) {
            warn(std::string("failed to parse ") + what + ": " + e.what());
        }
    };
    guarded("imports", &Image::parseImports);
    guarded("delay imports", &Image::parseDelayImports);
    guarded("exports", &Image::parseExports);
    guarded("relocations", &Image::parseRelocations);
    guarded("exception directory", &Image::parseExceptionDirectory);
    guarded("COFF symbols", &Image::parseCoffSymbols);
}

void Image::parseHeaders() {
    if (data_.size() < 0x40) throw DecompError("file too small to be a PE image");
    if (fileValue<u16>(0) != 0x5A4D) throw DecompError("missing MZ signature");
    u32 peOff = fileValue<u32>(0x3C);
    if (peOff > data_.size() || peOff + 24 > data_.size()) throw DecompError("e_lfanew points outside the file");
    if (fileValue<u32>(peOff) != 0x00004550) throw DecompError("missing PE signature");

    u32 coff = peOff + 4;
    u16 machine = fileValue<u16>(coff + 0);
    u16 numSections = fileValue<u16>(coff + 2);
    timeDateStamp_ = fileValue<u32>(coff + 4);
    symbolTableOffset_ = fileValue<u32>(coff + 8);
    symbolCount_ = fileValue<u32>(coff + 12);
    u16 optSize = fileValue<u16>(coff + 16);
    fileCharacteristics_ = fileValue<u16>(coff + 18);

    switch (machine) {
    case 0x014c: machine_ = Machine::X86; break;
    case 0x8664: machine_ = Machine::X64; break;
    default:
        throw DecompError(strfmt("unsupported machine type 0x%04x (only x86/x64 are supported)", machine));
    }

    u32 opt = coff + 20;
    if (optSize < 2) throw DecompError("optional header missing");
    u16 magic = fileValue<u16>(opt);
    if (magic == 0x10b) pe32plus_ = false;
    else if (magic == 0x20b) pe32plus_ = true;
    else throw DecompError(strfmt("unknown optional header magic 0x%x", magic));

    if ((machine_ == Machine::X64) != pe32plus_)
        warn("machine type and optional header format disagree");

    u32 minOpt = pe32plus_ ? 112 : 96;
    if (optSize < minOpt) throw DecompError("optional header too small");

    entryRva_ = fileValue<u32>(opt + 16);
    if (pe32plus_) {
        imageBase_ = fileValue<u64>(opt + 24);
    } else {
        imageBase_ = fileValue<u32>(opt + 28);
    }
    sectionAlignment_ = fileValue<u32>(opt + 32);
    fileAlignment_ = fileValue<u32>(opt + 36);
    sizeOfImage_ = fileValue<u32>(opt + 56);
    sizeOfHeaders_ = fileValue<u32>(opt + 60);
    subsystem_ = fileValue<u16>(opt + 68);
    u32 numDirsOff = pe32plus_ ? opt + 108 : opt + 92;
    u32 numDirs = fileValue<u32>(numDirsOff);
    u32 dirOff = numDirsOff + 4;
    u32 maxDirsInHeader = (optSize > (dirOff - opt)) ? (optSize - (dirOff - opt)) / 8 : 0;
    numDirs = std::min<u32>({numDirs, 16u, maxDirsInHeader});
    dirs_.resize(16);
    for (u32 i = 0; i < numDirs; ++i) {
        DataDirectory d;
        if (!fileRead(dirOff + i * 8, &d.rva, 4) || !fileRead(dirOff + i * 8 + 4, &d.size, 4)) break;
        dirs_[i] = d;
    }

    u32 secTable = opt + optSize;
    if (numSections > kMaxSections) {
        warn(strfmt("section count %u clamped to %u", numSections, kMaxSections));
        numSections = (u16)kMaxSections;
    }
    parseSections(secTable, numSections);
    if (sections_.empty()) warn("image has no sections");
}

void Image::parseSections(u32 tableOffset, u16 count) {
    for (u32 i = 0; i < count; ++i) {
        u32 off = tableOffset + i * 40;
        u8 raw[40];
        if (!fileRead(off, raw, 40)) {
            warn("section table truncated");
            break;
        }
        Section s;
        char nm[9] = {};
        std::memcpy(nm, raw, 8);
        s.name = nm;
        std::memcpy(&s.virtualSize, raw + 8, 4);
        std::memcpy(&s.virtualAddress, raw + 12, 4);
        std::memcpy(&s.rawSize, raw + 16, 4);
        std::memcpy(&s.rawOffset, raw + 20, 4);
        std::memcpy(&s.characteristics, raw + 36, 4);
        // Long section names ("/4") refer to the COFF string table.
        if (s.name.size() > 1 && s.name[0] == '/' && symbolTableOffset_) {
            u32 strOff = (u32)std::strtoul(s.name.c_str() + 1, nullptr, 10);
            u64 strTable = (u64)symbolTableOffset_ + (u64)symbolCount_ * 18;
            std::string longName;
            for (u64 p = strTable + strOff; p < data_.size() && longName.size() < 256; ++p) {
                if (!data_[p]) break;
                longName += (char)data_[p];
            }
            if (!longName.empty()) s.name = longName;
        }
        // Clamp raw data to the file.
        if (s.rawOffset > data_.size()) {
            if (s.rawSize) warn("section " + s.name + " raw data outside file");
            s.rawSize = 0;
        } else if (s.rawSize > data_.size() - s.rawOffset) {
            warn("section " + s.name + " raw data truncated");
            s.rawSize = (u32)(data_.size() - s.rawOffset);
        }
        sections_.push_back(std::move(s));
    }
}

DataDirectory Image::dataDirectory(int index) const {
    if (index < 0 || index >= (int)dirs_.size()) return {};
    return dirs_[index];
}

const Section* Image::sectionForRva(u32 rva) const {
    for (const auto& s : sections_)
        if (s.containsRva(rva)) return &s;
    return nullptr;
}

const Section* Image::sectionForVa(u64 va) const {
    auto rva = vaToRva(va);
    return rva ? sectionForRva(*rva) : nullptr;
}

bool Image::isExecutableVa(u64 va) const {
    const Section* s = sectionForVa(va);
    return s && s->isExecutable();
}

bool Image::isWritableVa(u64 va) const {
    const Section* s = sectionForVa(va);
    return s && s->isWritable();
}

std::optional<u32> Image::vaToRva(u64 va) const {
    if (va < imageBase_) return std::nullopt;
    u64 rva = va - imageBase_;
    if (rva > 0xFFFFFFFFull) return std::nullopt;
    return (u32)rva;
}

bool Image::isValidVa(u64 va) const {
    auto rva = vaToRva(va);
    if (!rva) return false;
    if (*rva < sizeOfHeaders_ && *rva < data_.size()) return true;
    return sectionForRva(*rva) != nullptr;
}

std::optional<u32> Image::rvaToOffset(u32 rva) const {
    if (const Section* s = sectionForRva(rva)) {
        u32 delta = rva - s->virtualAddress;
        if (delta >= s->rawSize) return std::nullopt; // zero-filled tail
        return s->rawOffset + delta;
    }
    // Headers are mapped 1:1.
    if (rva < sizeOfHeaders_ && rva < data_.size()) return rva;
    return std::nullopt;
}

std::optional<u32> Image::offsetToRva(u32 offset) const {
    for (const auto& s : sections_) {
        if (offset >= s.rawOffset && offset - s.rawOffset < s.rawSize) {
            u32 delta = offset - s.rawOffset;
            if (delta < s.mappedSize()) return s.virtualAddress + delta;
        }
    }
    if (offset < sizeOfHeaders_ && offset < data_.size()) return offset;
    return std::nullopt;
}

bool Image::rvaRead(u32 rva, void* out, size_t n) const {
    u8* dst = (u8*)out;
    size_t done = 0;
    while (done < n) {
        u64 cur = (u64)rva + done;
        if (cur > 0xFFFFFFFFull) return false;
        u32 r = (u32)cur;
        const Section* s = sectionForRva(r);
        if (!s) {
            if (r < sizeOfHeaders_ && r < data_.size()) {
                size_t chunk = std::min<size_t>(n - done, std::min<size_t>(sizeOfHeaders_, data_.size()) - r);
                std::memcpy(dst + done, data_.data() + r, chunk);
                done += chunk;
                continue;
            }
            return false;
        }
        u32 delta = r - s->virtualAddress;
        u32 avail = s->mappedSize() - delta;
        size_t chunk = std::min<size_t>(n - done, avail);
        for (size_t i = 0; i < chunk; ++i) {
            u32 d = delta + (u32)i;
            dst[done + i] = d < s->rawSize ? data_[(size_t)s->rawOffset + d] : 0;
        }
        done += chunk;
    }
    return true;
}

bool Image::read(u64 va, void* out, size_t n) const {
    auto rva = vaToRva(va);
    if (!rva) return false;
    return rvaRead(*rva, out, n);
}

std::span<const u8> Image::fileBytesAt(u64 va) const {
    auto rva = vaToRva(va);
    if (!rva) return {};
    const Section* s = sectionForRva(*rva);
    if (!s) return {};
    u32 delta = *rva - s->virtualAddress;
    if (delta >= s->rawSize) return {};
    u32 len = std::min(s->rawSize, s->mappedSize()) - std::min(delta, std::min(s->rawSize, s->mappedSize()));
    return std::span<const u8>(data_.data() + s->rawOffset + delta, len);
}

std::optional<std::string> Image::rvaCString(u32 rva, size_t maxLen) const {
    std::string out;
    for (size_t i = 0; i < maxLen; ++i) {
        auto c = rvaValue<u8>(rva + (u32)i);
        if (!c) return std::nullopt;
        if (*c == 0) return out;
        out += (char)*c;
    }
    return out;
}

std::optional<std::string> Image::readCString(u64 va, size_t maxLen) const {
    auto rva = vaToRva(va);
    if (!rva) return std::nullopt;
    return rvaCString(*rva, maxLen);
}

std::optional<std::string> Image::readWString(u64 va, size_t maxChars) const {
    std::string out;
    for (size_t i = 0; i < maxChars; ++i) {
        auto c = readValue<u16>(va + i * 2);
        if (!c) return std::nullopt;
        if (*c == 0) return out;
        u32 cp = *c;
        if (cp >= 0xD800 && cp < 0xDC00) {
            auto lo = readValue<u16>(va + (i + 1) * 2);
            if (lo && *lo >= 0xDC00 && *lo < 0xE000) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (*lo - 0xDC00);
                ++i;
            }
        }
        appendUtf8(out, cp);
    }
    return out;
}

void Image::parseImports() {
    DataDirectory d = dataDirectory(DirImport);
    if (!d.rva) return;
    const u32 thunkSize = pe32plus_ ? 8 : 4;
    for (u32 i = 0; i < kMaxImportDescriptors; ++i) {
        u32 desc = d.rva + i * 20;
        auto origFirstThunk = rvaValue<u32>(desc + 0);
        auto nameRva = rvaValue<u32>(desc + 12);
        auto firstThunk = rvaValue<u32>(desc + 16);
        if (!origFirstThunk || !nameRva || !firstThunk) {
            warn("import directory truncated");
            return;
        }
        if (*origFirstThunk == 0 && *nameRva == 0 && *firstThunk == 0) return;
        auto dll = rvaCString(*nameRva, 512);
        if (!dll) {
            warn("bad import DLL name");
            continue;
        }
        u32 lookup = *origFirstThunk ? *origFirstThunk : *firstThunk;
        for (u32 t = 0; t < kMaxThunksPerDll; ++t) {
            u64 thunk = 0;
            if (!rvaRead(lookup + t * thunkSize, &thunk, thunkSize)) break;
            if (thunk == 0) break;
            Import imp;
            imp.dll = *dll;
            imp.iatAddress = imageBase_ + *firstThunk + (u64)t * thunkSize;
            u64 ordFlag = pe32plus_ ? (1ull << 63) : (1ull << 31);
            if (thunk & ordFlag) {
                imp.byOrdinal = true;
                imp.ordinal = (u16)(thunk & 0xFFFF);
            } else {
                u32 hintRva = (u32)(thunk & 0x7FFFFFFF);
                auto hint = rvaValue<u16>(hintRva);
                auto nm = rvaCString(hintRva + 2, 512);
                if (!hint || !nm) {
                    warn("bad import name entry in " + *dll);
                    continue;
                }
                imp.hint = *hint;
                imp.name = *nm;
            }
            importByIat_[imp.iatAddress] = imports_.size();
            imports_.push_back(std::move(imp));
        }
    }
}

void Image::parseDelayImports() {
    DataDirectory d = dataDirectory(DirDelayImport);
    if (!d.rva) return;
    const u32 thunkSize = pe32plus_ ? 8 : 4;
    for (u32 i = 0; i < kMaxImportDescriptors; ++i) {
        u32 desc = d.rva + i * 32;
        auto attrs = rvaValue<u32>(desc + 0);
        auto nameRva = rvaValue<u32>(desc + 4);
        auto iatRva = rvaValue<u32>(desc + 12);
        auto intRva = rvaValue<u32>(desc + 16);
        if (!attrs || !nameRva || !iatRva || !intRva) return;
        if (*nameRva == 0) return;
        // Old-style (attrs bit 0 clear) descriptors hold VAs instead of RVAs.
        auto fix = [&](u32 v) -> u32 { return (*attrs & 1) ? v : (u32)(v - (u32)imageBase_); };
        auto dll = rvaCString(fix(*nameRva), 512);
        if (!dll) return;
        for (u32 t = 0; t < kMaxThunksPerDll; ++t) {
            u64 thunk = 0;
            if (!rvaRead(fix(*intRva) + t * thunkSize, &thunk, thunkSize) || thunk == 0) break;
            Import imp;
            imp.dll = *dll;
            imp.delayLoad = true;
            imp.iatAddress = imageBase_ + fix(*iatRva) + (u64)t * thunkSize;
            u64 ordFlag = pe32plus_ ? (1ull << 63) : (1ull << 31);
            if (thunk & ordFlag) {
                imp.byOrdinal = true;
                imp.ordinal = (u16)(thunk & 0xFFFF);
            } else {
                u32 hintRva = fix((u32)(thunk & 0x7FFFFFFF));
                auto nm = rvaCString(hintRva + 2, 512);
                if (!nm) continue;
                imp.name = *nm;
            }
            importByIat_[imp.iatAddress] = imports_.size();
            imports_.push_back(std::move(imp));
        }
    }
}

void Image::parseExports() {
    DataDirectory d = dataDirectory(DirExport);
    if (!d.rva) return;
    auto base = rvaValue<u32>(d.rva + 16);
    auto numFuncs = rvaValue<u32>(d.rva + 20);
    auto numNames = rvaValue<u32>(d.rva + 24);
    auto funcsRva = rvaValue<u32>(d.rva + 28);
    auto namesRva = rvaValue<u32>(d.rva + 32);
    auto ordsRva = rvaValue<u32>(d.rva + 36);
    if (!base || !numFuncs || !numNames || !funcsRva || !namesRva || !ordsRva) {
        warn("export directory truncated");
        return;
    }
    u32 nf = std::min(*numFuncs, kMaxExports);
    u32 nn = std::min(*numNames, kMaxExports);
    std::vector<std::string> names(nf);
    for (u32 i = 0; i < nn; ++i) {
        auto nameRva = rvaValue<u32>(*namesRva + i * 4);
        auto ord = rvaValue<u16>(*ordsRva + i * 2);
        if (!nameRva || !ord) break;
        if (*ord >= nf) continue;
        auto nm = rvaCString(*nameRva, 1024);
        if (nm) names[*ord] = *nm;
    }
    for (u32 i = 0; i < nf; ++i) {
        auto rva = rvaValue<u32>(*funcsRva + i * 4);
        if (!rva) break;
        if (*rva == 0) continue;
        Export e;
        e.name = names[i];
        e.ordinal = *base + i;
        e.rva = *rva;
        if (*rva >= d.rva && *rva < d.rva + d.size) {
            e.forwarded = true;
            auto fwd = rvaCString(*rva, 512);
            if (fwd) e.forwarder = *fwd;
        } else {
            exportByRva_.emplace(e.rva, exports_.size());
        }
        exports_.push_back(std::move(e));
    }
}

void Image::parseRelocations() {
    DataDirectory d = dataDirectory(DirBaseReloc);
    if (!d.rva || !d.size) return;
    u32 off = 0;
    while (off + 8 <= d.size) {
        auto page = rvaValue<u32>(d.rva + off);
        auto blockSize = rvaValue<u32>(d.rva + off + 4);
        if (!page || !blockSize || *blockSize < 8 || *blockSize > d.size - off) break;
        u32 count = (*blockSize - 8) / 2;
        for (u32 i = 0; i < count; ++i) {
            auto entry = rvaValue<u16>(d.rva + off + 8 + i * 2);
            if (!entry) break;
            u16 type = *entry >> 12;
            if (type == 3 || type == 10) relocRvas_.push_back(*page + (*entry & 0xFFF));
        }
        off += *blockSize;
    }
    std::sort(relocRvas_.begin(), relocRvas_.end());
}

void Image::parseExceptionDirectory() {
    if (!pe32plus_) return;
    DataDirectory d = dataDirectory(DirException);
    if (!d.rva || !d.size) return;
    u32 n = std::min(d.size / 12, kMaxRuntimeFunctions);
    for (u32 i = 0; i < n; ++i) {
        RuntimeFunction rf;
        auto b = rvaValue<u32>(d.rva + i * 12);
        auto e = rvaValue<u32>(d.rva + i * 12 + 4);
        auto u = rvaValue<u32>(d.rva + i * 12 + 8);
        if (!b || !e || !u) break;
        if (*b == 0 && *e == 0) continue;
        if (*e <= *b) continue;
        rf.beginRva = *b;
        rf.endRva = *e;
        rf.unwindRva = *u;
        runtimeFunctions_.push_back(rf);
    }
}

void Image::parseCoffSymbols() {
    if (!symbolTableOffset_ || !symbolCount_) return;
    u64 tableEnd = (u64)symbolTableOffset_ + (u64)symbolCount_ * 18;
    if (tableEnd > data_.size()) {
        warn("COFF symbol table outside file");
        return;
    }
    u32 strTableSize = 0;
    fileRead(tableEnd, &strTableSize, 4);
    u32 n = std::min(symbolCount_, kMaxCoffSymbols);
    for (u32 i = 0; i < n; ++i) {
        u64 off = symbolTableOffset_ + (u64)i * 18;
        u8 raw[18];
        if (!fileRead(off, raw, 18)) break;
        u32 value;
        i16 sectionNumber;
        u16 type;
        u8 storageClass = raw[16];
        u8 numAux = raw[17];
        std::memcpy(&value, raw + 8, 4);
        std::memcpy(&sectionNumber, raw + 12, 2);
        std::memcpy(&type, raw + 14, 2);
        std::string name;
        u32 zeroes;
        std::memcpy(&zeroes, raw, 4);
        if (zeroes == 0) {
            u32 strOff;
            std::memcpy(&strOff, raw + 4, 4);
            if (strOff >= 4 && strOff < strTableSize) {
                for (u64 p = tableEnd + strOff; p < data_.size() && name.size() < 512; ++p) {
                    if (!data_[p]) break;
                    name += (char)data_[p];
                }
            }
        } else {
            char nm[9] = {};
            std::memcpy(nm, raw, 8);
            name = nm;
        }
        i += numAux;
        // External (2) or static (3) symbols defined in a section.
        if ((storageClass != 2 && storageClass != 3) || sectionNumber <= 0 ||
            sectionNumber > (i16)sections_.size() || name.empty())
            continue;
        const Section& s = sections_[sectionNumber - 1];
        CoffSymbol sym;
        sym.name = name;
        sym.address = imageBase_ + s.virtualAddress + value;
        sym.isFunction = ((type >> 4) & 3) == 2 || (storageClass == 2 && s.isExecutable());
        coffSymbols_.push_back(std::move(sym));
    }
}

const Import* Image::importByIat(u64 iatVa) const {
    auto it = importByIat_.find(iatVa);
    return it == importByIat_.end() ? nullptr : &imports_[it->second];
}

const Export* Image::exportByRva(u32 rva) const {
    auto it = exportByRva_.find(rva);
    return it == exportByRva_.end() ? nullptr : &exports_[it->second];
}

} // namespace dc::pe
