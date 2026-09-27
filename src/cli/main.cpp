// decomp: Windows x86/x64 PE decompiler command line interface.
#include "disasm/disassembler.h"
#include "pe/pe_image.h"

#include <cstdio>
#include <cstring>
#include <string>

using namespace dc;

namespace {

void usage() {
    std::printf(
        "usage: decomp <image.exe|image.dll> [options]\n"
        "\n"
        "options:\n"
        "  --disasm            linear disassembly of executable sections\n"
        "  --help              show this help\n");
}

void printHeader(const pe::Image& img) {
    std::printf("Architecture: %s\n", pe::machineName(img.machine()));
    std::printf("Image Base: 0x%llx\n", (unsigned long long)img.imageBase());
    std::printf("Entry Point: 0x%llx\n", (unsigned long long)img.entryPoint());
    for (const auto& w : img.warnings()) std::printf("warning: %s\n", w.c_str());
}

void linearDisasm(const pe::Image& img) {
    auto dis = createX86Disassembler(img.is64());
    for (const auto& s : img.sections()) {
        if (!s.isExecutable()) continue;
        std::printf("\n%s\n", s.name.c_str());
        u64 va = img.imageBase() + s.virtualAddress;
        u64 end = va + std::min(s.rawSize, s.mappedSize());
        while (va < end) {
            auto bytes = img.fileBytesAt(va);
            if (bytes.empty()) break;
            if (bytes.size() > end - va) bytes = bytes.subspan(0, end - va);
            x86::Instruction in;
            if (!dis->decode(bytes, va, in)) {
                std::printf("0x%llx: db 0x%02x\n", (unsigned long long)va, bytes[0]);
                va += 1;
                continue;
            }
            std::printf("0x%llx: %s\n", (unsigned long long)va, in.text().c_str());
            va += in.length;
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    std::string path;
    bool disasm = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") { usage(); return 0; }
        else if (a == "--disasm") disasm = true;
        else if (!a.empty() && a[0] == '-') { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); usage(); return 2; }
        else path = a;
    }
    if (path.empty()) { usage(); return 2; }
    try {
        auto img = pe::Image::loadFile(path);
        printHeader(*img);
        (void)disasm;
        linearDisasm(*img);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    return 0;
}
