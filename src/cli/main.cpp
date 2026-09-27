// decomp: Windows x86/x64 PE decompiler command line interface.
#include "analysis/cfg_dump.h"
#include "analysis/program.h"
#include "disasm/disassembler.h"
#include "core/pipeline.h"
#include "cgen/cwriter.h"
#include "winapi/api_database.h"
#include "winapi/data_analysis.h"
#include "lift/lifter.h"
#include "pe/pe_image.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
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
    bool ssa = false;
    bool frame = false;
    bool opt2 = false;
    bool stats = false;
    bool sigs = false;
    bool showTypes = false;
    bool strings = false;
    bool imports = false;
    bool structs = false;
    bool noPreamble = false;
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
        "  --ssa               IR in SSA form\n"
        "  --frame             recovered stack frame layout\n"
        "  --opt               optimised SSA\n"
        "  --stats             per-function pipeline statistics\n"
        "  --signatures        recovered function signatures\n"
        "  --types             recovered variables and their types\n"
        "  --structs           recovered structure layouts\n"
        "  --strings           strings found in the image\n"
        "  --imports           imports, exports and recognised APIs\n"
        "  --no-preamble       omit the type alias header from the C output\n"
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
        else if (a == "--ssa") opt.ssa = true;
        else if (a == "--frame") opt.frame = true;
        else if (a == "--opt") opt.opt2 = true;
        else if (a == "--stats") opt.stats = true;
        else if (a == "--signatures") opt.sigs = true;
        else if (a == "--types") opt.showTypes = true;
        else if (a == "--structs") opt.structs = true;
        else if (a == "--strings") opt.strings = true;
        else if (a == "--imports") opt.imports = true;
        else if (a == "--no-preamble") opt.noPreamble = true;
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
        if (opt.strings) {
            auto data = winapi::scanStrings(prog.image());
            std::printf("\n%zu strings\n", data.strings.size());
            for (const auto& s : data.strings)
                std::printf("0x%llx  %-5s %s\"%s\"\n", (unsigned long long)s.address,
                            s.kind == winapi::StringKind::Ascii ? "ascii" : "utf16",
                            s.inReadOnly ? "" : "(writable) ", escapeCString(s.text).c_str());
            return 0;
        }
        if (opt.imports) {
            std::printf("\nimports (%zu)\n", prog.image().imports().size());
            std::string lastDll;
            for (const auto& i : prog.image().imports()) {
                if (i.dll != lastDll) {
                    std::printf("\n  %s\n", i.dll.c_str());
                    lastDll = i.dll;
                }
                const winapi::ApiSignature* api = winapi::lookup(i.name, prog.is64());
                std::printf("    0x%llx  %-32s", (unsigned long long)i.iatAddress, i.displayName().c_str());
                if (api) {
                    std::printf(" %s %s(", winapi::apiTypeName(api->ret), api->name);
                    for (size_t k = 0; k < api->params.size(); ++k)
                        std::printf("%s%s %s", k ? ", " : "", winapi::apiTypeName(api->params[k].type),
                                    api->params[k].name ? api->params[k].name : "");
                    std::printf("%s)", api->variadic ? (api->params.empty() ? "..." : ", ...") : "");
                    if (const char* d = winapi::describe(i.name)) std::printf("   /* %s */", d);
                } else {
                    std::printf(" /* signature unknown */");
                }
                if (i.delayLoad) std::printf(" [delay load]");
                std::printf("\n");
            }
            std::printf("\nexports (%zu)\n", prog.image().exports().size());
            for (const auto& e : prog.image().exports())
                std::printf("  %-4u 0x%llx  %s%s\n", e.ordinal,
                            (unsigned long long)prog.image().rvaToVa(e.rva), e.name.c_str(),
                            e.forwarded ? (" -> " + e.forwarder).c_str() : "");
            return 0;
        }
        if (opt.sigs) {
            PipelineOptions po;
            Pipeline pipe(prog, po);
            pipe.buildSignatures();
            for (Function* f : funcs) {
                const Signature* s = pipe.signatures().forFunction(f->entry);
                std::printf("0x%llx  %s\n", (unsigned long long)f->entry,
                            s ? s->str().c_str() : (f->name + "(?)").c_str());
            }
            std::printf("\n%zu signatures, %d rounds to a fixed point\n", pipe.signatures().size(),
                        pipe.signatures().rounds());
            return 0;
        }
        if (opt.showTypes || opt.structs) {
            PipelineOptions po;
            po.verifyStages = true;
            Pipeline pipe(prog, po);
            for (Function* f : funcs) {
                auto r = pipe.runToVariables(*f);
                if (opt.structs) {
                    for (const types::Type* st : r->structs) {
                        std::printf("\n#pragma pack(push, 1)\nstruct %s {\n", st->name.c_str());
                        for (const auto& fl : st->fields)
                            std::printf("    %-22s /* +0x%llx, %u bytes%s */\n",
                                        (fl.type->spell(fl.name) + ";").c_str(),
                                        (unsigned long long)fl.offset, fl.size,
                                        fl.accessed ? "" : ", not accessed");
                        std::printf("};\n#pragma pack(pop)\n");
                    }
                    continue;
                }
                std::printf("\n%s  /* confidence: %s */\n", f->name.c_str(),
                            types::confidenceName(r->confidence));
                for (const auto& why : r->confidenceReasons) std::printf("  ; %s\n", why.c_str());
                for (const auto& var : r->variables.variables) {
                    std::printf("  %-28s", (var.type ? var.type->spell(var.name) : "?? " + var.name).c_str());
                    std::printf("  %u uses, %zu values%s%s\n", var.uses, var.values.size(),
                                var.isParam ? ", parameter" : "",
                                var.singleAssignment ? ", single assignment" : "");
                }
                std::printf("  (%zu values inlined as expressions)\n", r->variables.inlined.size());
            }
            return 0;
        }
        if (opt.ssa || opt.frame || opt.opt2 || opt.stats) {
            PipelineOptions po;
            po.verifyStages = true;
            Pipeline pipe(prog, po);
            int problems = 0;
            for (Function* f : funcs) {
                auto r = (opt.opt2 || opt.stats) ? pipe.runToOptimized(*f) : pipe.runToSsa(*f);
                if (opt.frame) std::printf("\n%s @ 0x%llx\n%s", f->name.c_str(), (unsigned long long)f->entry, r->frame.print().c_str());
                if (opt.ssa || opt.opt2) {
                    std::printf("\n%s", r->ir->print(false).c_str());
                    std::printf("  ; %d phis inserted, %d pruned by liveness\n", r->ssa.phisInserted, r->ssa.phisPruned);
                }
                if (opt.stats) {
                    size_t insts = 0;
                    int phis = 0, casts = 0;
                    for (const auto& b : r->ir->blocks())
                        for (auto v : b.insts) {
                            ++insts;
                            if (r->ir->inst(v).op == ir::Op::Phi) ++phis;
                            if (ir::isCast(r->ir->inst(v).op)) ++casts;
                        }
                    std::printf("%-28s machine %4zu -> ir %4zu insts, %3d phis, %3d casts, %2zu frame slots (%u promoted)\n",
                                f->name.c_str(), f->instructionCount(), insts, phis, casts,
                                r->frame.slots.size(), r->frame.promotedCount);
                }
                if (!r->problems.empty()) {
                    ++problems;
                    std::printf("\nproblems in %s:\n", f->name.c_str());
                    for (const auto& p : r->problems) std::printf("  %s\n", p.c_str());
                }
            }
            if (problems) std::printf("\n%d functions with problems\n", problems);
            return problems ? 1 : 0;
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
            // With no view selected, decompile to C.
            PipelineOptions po;
            po.verifyStages = true;
            Pipeline pipe(prog, po);
            if (!opt.noPreamble) std::printf("%s", cgen::writePreamble().c_str());
            std::vector<const types::Type*> allStructs;
            std::vector<std::string> bodies;
            for (Function* f : funcs) {
                auto r = pipe.decompile(*f);
                for (const types::Type* st : r->structs) allStructs.push_back(st);
                bodies.push_back(r->code);
            }
            std::sort(allStructs.begin(), allStructs.end());
            allStructs.erase(std::unique(allStructs.begin(), allStructs.end()), allStructs.end());
            std::printf("%s", cgen::writeStructs(allStructs).c_str());
            for (const auto& b : bodies) std::printf("\n%s", b.c_str());
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    return 0;
}
