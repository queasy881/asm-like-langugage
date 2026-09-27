// PE32 / PE32+ image loader.
//
// Every read of the file is bounds checked; malformed images produce a
// DecompError (for fatal header problems) or are recorded as warnings (for
// damaged optional tables such as imports/exports) instead of crashing.
#pragma once

#include "support/common.h"

#include <map>
#include <memory>
#include <span>

namespace dc::pe {

enum class Machine { Unknown, X86, X64 };

const char* machineName(Machine m);

struct Section {
    std::string name;
    u32 virtualAddress = 0;
    u32 virtualSize = 0;
    u32 rawOffset = 0;
    u32 rawSize = 0;
    u32 characteristics = 0;

    bool isExecutable() const { return (characteristics & 0x20000000u) || (characteristics & 0x20u); }
    bool isReadable() const { return (characteristics & 0x40000000u) != 0; }
    bool isWritable() const { return (characteristics & 0x80000000u) != 0; }
    bool isCode() const { return (characteristics & 0x20u) != 0; }
    bool isUninitialized() const { return (characteristics & 0x80u) != 0; }
    // Size of the section once mapped (the larger of virtual and raw size).
    u32 mappedSize() const;
    bool containsRva(u32 rva) const { return rva >= virtualAddress && rva - virtualAddress < mappedSize(); }
};

struct DataDirectory {
    u32 rva = 0;
    u32 size = 0;
};

enum DirIndex : int {
    DirExport = 0, DirImport = 1, DirResource = 2, DirException = 3, DirSecurity = 4,
    DirBaseReloc = 5, DirDebug = 6, DirArchitecture = 7, DirGlobalPtr = 8, DirTLS = 9,
    DirLoadConfig = 10, DirBoundImport = 11, DirIAT = 12, DirDelayImport = 13, DirCLR = 14,
};

struct Import {
    std::string dll;        // as written in the import directory (e.g. "KERNEL32.dll")
    std::string name;       // empty when imported by ordinal
    u16 ordinal = 0;
    u16 hint = 0;
    bool byOrdinal = false;
    bool delayLoad = false;
    u64 iatAddress = 0;     // VA of the IAT slot the loader patches
    std::string displayName() const; // name, or "Ordinal_N"
};

struct Export {
    std::string name;       // may be empty for ordinal-only exports
    u32 ordinal = 0;
    u32 rva = 0;
    bool forwarded = false;
    std::string forwarder;
};

// x64 exception directory entry (.pdata RUNTIME_FUNCTION).
struct RuntimeFunction {
    u32 beginRva = 0;
    u32 endRva = 0;
    u32 unwindRva = 0;
};

struct CoffSymbol {
    std::string name;
    u64 address = 0;        // VA
    bool isFunction = false;
};

class Image {
public:
    // Loads a PE from disk / from memory. Throws DecompError on fatal errors.
    static std::unique_ptr<Image> loadFile(const std::string& path);
    static std::unique_ptr<Image> loadBuffer(std::vector<u8> data, std::string name = "<memory>");

    const std::string& name() const { return name_; }
    Machine machine() const { return machine_; }
    bool is64() const { return machine_ == Machine::X64; }
    bool isPE32Plus() const { return pe32plus_; }
    bool isDll() const { return (fileCharacteristics_ & 0x2000) != 0; }
    u64 imageBase() const { return imageBase_; }
    u32 entryPointRva() const { return entryRva_; }
    u64 entryPoint() const { return entryRva_ ? imageBase_ + entryRva_ : 0; }
    u32 sizeOfImage() const { return sizeOfImage_; }
    u32 sizeOfHeaders() const { return sizeOfHeaders_; }
    u16 subsystem() const { return subsystem_; }
    u32 timeDateStamp() const { return timeDateStamp_; }

    const std::vector<Section>& sections() const { return sections_; }
    const std::vector<Import>& imports() const { return imports_; }
    const std::vector<Export>& exports() const { return exports_; }
    const std::vector<RuntimeFunction>& runtimeFunctions() const { return runtimeFunctions_; }
    const std::vector<CoffSymbol>& coffSymbols() const { return coffSymbols_; }
    const std::vector<u32>& relocations() const { return relocRvas_; } // RVAs of patched slots
    const std::vector<std::string>& warnings() const { return warnings_; }
    DataDirectory dataDirectory(int index) const;

    // Address translation.
    std::optional<u32> rvaToOffset(u32 rva) const;
    std::optional<u32> offsetToRva(u32 offset) const;
    bool isValidVa(u64 va) const;
    std::optional<u32> vaToRva(u64 va) const;
    u64 rvaToVa(u32 rva) const { return imageBase_ + rva; }

    const Section* sectionForRva(u32 rva) const;
    const Section* sectionForVa(u64 va) const;
    bool isExecutableVa(u64 va) const;
    bool isWritableVa(u64 va) const;

    // Reads mapped image memory. Bytes that are part of a section's virtual
    // size but not backed by file data read as zero. Returns false if any
    // byte of the range is outside the mapped image.
    bool read(u64 va, void* out, size_t n) const;
    template <class T> std::optional<T> readValue(u64 va) const {
        T v{};
        if (!read(va, &v, sizeof(T))) return std::nullopt;
        return v;
    }
    // Largest contiguous file-backed byte span starting at va (possibly empty).
    std::span<const u8> fileBytesAt(u64 va) const;
    // Reads a NUL terminated ASCII string (bounded).
    std::optional<std::string> readCString(u64 va, size_t maxLen = 4096) const;
    // Reads a NUL terminated UTF-16LE string, converted to UTF-8 (bounded).
    std::optional<std::string> readWString(u64 va, size_t maxChars = 4096) const;

    // Lookups.
    const Import* importByIat(u64 iatVa) const;
    const Export* exportByRva(u32 rva) const;
    std::span<const u8> fileData() const { return data_; }

private:
    Image() = default;
    void parse();
    void parseHeaders();
    void parseSections(u32 sectionTableOffset, u16 count);
    void parseImports();
    void parseDelayImports();
    void parseExports();
    void parseRelocations();
    void parseExceptionDirectory();
    void parseCoffSymbols();
    void warn(std::string msg) { warnings_.push_back(std::move(msg)); }

    // Raw file access helpers (bounds checked).
    bool fileRead(u64 offset, void* out, size_t n) const;
    template <class T> T fileValue(u64 offset) const {
        T v{};
        if (!fileRead(offset, &v, sizeof(T))) throw DecompError("truncated PE header");
        return v;
    }
    bool rvaRead(u32 rva, void* out, size_t n) const;
    template <class T> std::optional<T> rvaValue(u32 rva) const {
        T v{};
        if (!rvaRead(rva, &v, sizeof(T))) return std::nullopt;
        return v;
    }
    std::optional<std::string> rvaCString(u32 rva, size_t maxLen = 1024) const;

    std::string name_;
    std::vector<u8> data_;
    Machine machine_ = Machine::Unknown;
    bool pe32plus_ = false;
    u16 fileCharacteristics_ = 0;
    u64 imageBase_ = 0;
    u32 entryRva_ = 0;
    u32 sizeOfImage_ = 0;
    u32 sizeOfHeaders_ = 0;
    u32 fileAlignment_ = 0;
    u32 sectionAlignment_ = 0;
    u16 subsystem_ = 0;
    u32 timeDateStamp_ = 0;
    u32 symbolTableOffset_ = 0;
    u32 symbolCount_ = 0;
    std::vector<DataDirectory> dirs_;
    std::vector<Section> sections_;
    std::vector<Import> imports_;
    std::vector<Export> exports_;
    std::vector<RuntimeFunction> runtimeFunctions_;
    std::vector<CoffSymbol> coffSymbols_;
    std::vector<u32> relocRvas_;
    std::vector<std::string> warnings_;
    std::map<u64, size_t> importByIat_;
    std::map<u32, size_t> exportByRva_;
};

} // namespace dc::pe
