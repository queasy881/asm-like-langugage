// decomp: Windows x86/x64 PE decompiler command line interface.
#include "analysis/cfg_dump.h"
#include "analysis/program.h"
#include "disasm/disassembler.h"
#include "lift/lifter.h"
#include "pe/pe_image.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace dc;

namespace {

struct Options {
    std::string path;
    bool disasm = false;
    bool functions = false;
    bool cfg = false;
    bool blocks = false;
    bool ir = false;
    bool verify = false;
    std::string function; // address or name filter
};

void usage() {
    std::printf(
        "usage: decomp <image.exe|image.dll> [options]\n"
        "\n"
        "views:\n"
        "  --disasm            linear disassembly of executable sections\n"
        "  --functions         discovered functions and their blocks\n"
        "  --blocks            basic blocks with instructions\n"
        "  --cfg               control-flow graphs (edges, dominators, loops)\n"
        "  --ir                lifted IR (pre-SSA)\n"
        "  --verify            run IR verification and report problems\n"
        "\n"
        "filters:\n"
        "  --function <addr|name>  restrict output to one function\n"
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

// Resolves --function: hex address or function name.
std::vector<Function*> selectFunctions(Program& prog, const std::string& sel, bool includeThunks) {
    std::vector<Function*> out;
    if (!sel.empty()) {
        char* end = nullptr;
        unsigned long long va = std::strtoull(sel.c_str(), &end, 16);
        if (end && *end == 0 && va) {
            if (Function* f = prog.ensureFunction(va)) out.push_back(f);
            return out;
        }
        for (const auto& [a, f] : prog.functions())
            if (f->name == sel) out.push_back(f.get());
        return out;
    }
    for (const auto& [a, f] : prog.functions())
        if (includeThunks || !f->isImportThunk) out.push_back(f.get());
    return out;
}

} // namespace

int main(int argc, char** argv) {
    Options opt;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") { usage(); return 0; }
        else if (a == "--disasm") opt.disasm = true;
        else if (a == "--functions") opt.functions = true;
        else if (a == "--cfg") opt.cfg = true;
        else if (a == "--blocks") opt.blocks = true;
        else if (a == "--ir") opt.ir = true;
        else if (a == "--verify") opt.verify = true;
        else if (a == "--function" && i + 1 < argc) opt.function = argv[++i];
        else if (!a.empty() && a[0] == '-') { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); usage(); return 2; }
        else opt.path = a;
    }
    if (opt.path.empty()) { usage(); return 2; }
    try {
        auto img = pe::Image::loadFile(opt.path);
        printHeader(*img);
        if (opt.disasm) {
            linearDisasm(*img);
            return 0;
        }
        Program prog(std::move(img));
        prog.discoverFunctions();
        auto funcs = selectFunctions(prog, opt.function, false);
        if (!opt.function.empty() && funcs.empty()) {
            std::fprintf(stderr, "error: no function matches '%s'\n", opt.function.c_str());
            return 1;
        }
        if (opt.ir || opt.verify) {
            int problems = 0;
            for (Function* f : funcs) {
                lift::LiftOptions lo;
                auto r = lift::liftFunction(prog, *f, lo);
                auto errs = r.func->verify();
                if (opt.ir) std::printf("\n%s", r.func->print(true).c_str());
                if (!errs.empty()) {
                    std::printf("\nIR verification failed for %s:\n", f->name.c_str());
                    for (const auto& e : errs) std::printf("  %s\n", e.c_str());
                    ++problems;
                }
            }
            if (opt.verify) std::printf("\n%zu functions verified, %d with problems\n", funcs.size(), problems);
            return problems ? 1 : 0;
        }
        if (opt.cfg) {
            for (Function* f : funcs) std::printf("\n%s", dumpCfg(prog, *f).c_str());
        } else if (opt.blocks) {
            for (Function* f : funcs) std::printf("\nFunction %s @ 0x%llx\n%s", f->name.c_str(), (unsigned long long)f->entry, dumpFunctionBlocks(*f, true).c_str());
        } else {
            std::printf("\n%s", dumpFunctionList(prog).c_str());
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    return 0;
}
