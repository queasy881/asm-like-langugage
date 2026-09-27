#include "test_framework.h"

#include "pe/pe_image.h"

#include <cstring>
#include <random>

using namespace dc;

TEST(pe_corpus_headers) {
    auto img = pe::Image::loadFile(dctest::corpusPath("behemoth.dll"));
    CHECK(img->machine() == pe::Machine::X64);
    CHECK(img->isPE32Plus());
    CHECK(img->isDll());
    CHECK_EQ(img->imageBase(), 0x2D6310000ull);
    CHECK_EQ(img->entryPoint(), 0x2D6311340ull);
    CHECK(img->sections().size() >= 11);
    CHECK_EQ(img->sections()[0].name, std::string(".text"));
    CHECK(img->sections()[0].isExecutable());
    CHECK(!img->sections()[1].isExecutable());
    // Long section names resolved via the COFF string table.
    bool sawDebugInfo = false;
    for (const auto& s : img->sections()) sawDebugInfo |= s.name == ".debug_info";
    CHECK(sawDebugInfo);
}

TEST(pe_corpus_rva_offset) {
    auto img = pe::Image::loadFile(dctest::corpusPath("behemoth.dll"));
    // .text: VA 0x1000, raw 0x600
    CHECK_EQ(*img->rvaToOffset(0x1000), 0x600u);
    CHECK_EQ(*img->rvaToOffset(0x1390), 0x990u);
    CHECK_EQ(*img->offsetToRva(0x990), 0x1390u);
    CHECK(!img->rvaToOffset(0x7FFFFFFF).has_value());
    CHECK(img->isExecutableVa(0x2D6311390ull));
    CHECK(!img->isExecutableVa(0x2D6315000ull));
    u8 b[3];
    CHECK(img->read(0x2D6311390ull, b, 3));
    CHECK(b[0] == 0x48 && b[1] == 0x85 && b[2] == 0xD2); // test rdx, rdx
}

TEST(pe_corpus_imports_exports) {
    auto img = pe::Image::loadFile(dctest::corpusPath("behemoth.dll"));
    CHECK_EQ(img->exports().size(), (size_t)32);
    bool haveFnv = false, haveVm = false;
    for (const auto& e : img->exports()) {
        if (e.name == "fnv1a_hash") { haveFnv = true; CHECK_EQ(e.rva, 0x1390u); }
        if (e.name == "vm_exec") haveVm = true;
    }
    CHECK(haveFnv && haveVm);
    bool haveMemcpy = false, haveSleep = false;
    for (const auto& i : img->imports()) {
        if (i.name == "memcpy") { haveMemcpy = true; CHECK_EQ(toLower(i.dll), std::string("msvcrt.dll")); }
        if (i.name == "Sleep") haveSleep = true;
        CHECK(img->importByIat(i.iatAddress) == &i);
    }
    CHECK(haveMemcpy && haveSleep);
    CHECK(!img->runtimeFunctions().empty());
    CHECK(!img->relocations().empty());
}

TEST(pe_malformed_inputs_do_not_crash) {
    // Truncated / garbage inputs must raise DecompError, never crash.
    auto expectError = [](std::vector<u8> data) {
        bool threw = false;
        try {
            pe::Image::loadBuffer(std::move(data));
        } catch (const DecompError&) {
            threw = true;
        }
        return threw;
    };
    CHECK(expectError({}));
    CHECK(expectError({'M', 'Z'}));
    std::vector<u8> mz(0x40, 0);
    mz[0] = 'M'; mz[1] = 'Z';
    mz[0x3C] = 0xF0; // e_lfanew beyond file
    CHECK(expectError(mz));

    // Mutation fuzzing of the real corpus: every mutant either loads or
    // throws DecompError.
    auto orig = pe::Image::loadFile(dctest::corpusPath("behemoth.dll"));
    std::vector<u8> base(orig->fileData().begin(), orig->fileData().end());
    std::mt19937 rng(1234);
    int loaded = 0, rejected = 0;
    for (int iter = 0; iter < 400; ++iter) {
        std::vector<u8> m = base;
        int edits = 1 + (int)(rng() % 16);
        for (int k = 0; k < edits; ++k) {
            size_t pos = (iter % 2) ? rng() % 0x600 : rng() % m.size(); // bias towards headers
            m[pos] = (u8)rng();
        }
        if (iter % 7 == 0) m.resize(rng() % m.size());
        try {
            auto img = pe::Image::loadBuffer(std::move(m));
            // Exercise lookups on the damaged image.
            for (const auto& s : img->sections()) {
                u8 buf[16];
                img->read(img->imageBase() + s.virtualAddress, buf, sizeof buf);
                img->fileBytesAt(img->imageBase() + s.virtualAddress);
            }
            ++loaded;
        } catch (const DecompError&) {
            ++rejected;
        }
    }
    CHECK(loaded + rejected == 400);
}
