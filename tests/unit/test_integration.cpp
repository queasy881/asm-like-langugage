// End-to-end test: the same C compiled natively is the reference, and the
// same C compiled to a PE is decompiled and run in the IR interpreter. The
// two must agree, for x86 and x64, at -O0 and -O2.
#include "test_framework.h"

#include "core/interpreter.h"
#include "core/pipeline.h"

#include <cmath>
#include <cstring>
#include <random>

extern "C" {
#include "cases.c"
}

using namespace dc;
using namespace dc::ir;

namespace {

// Addresses must fit the target's pointer width, or the interpreter truncates
// them exactly as the program would.
constexpr u64 kScratch64 = 0x30000000ull;
constexpr u64 kStack64 = 0x7FF000000000ull;
constexpr u64 kScratch32 = 0x00300000ull;
constexpr u64 kStack32 = 0x00800000ull;
constexpr size_t kScratchSize = 256;

inline u64 scratchAddr(bool is64) { return is64 ? kScratch64 : kScratch32; }
inline u64 stackAddrFor(bool is64) { return is64 ? kStack64 : kStack32; }

struct Target {
    std::string path;
    bool is64;
    std::string label;
};

std::vector<Target> targets() {
    std::vector<Target> t;
#ifdef DECOMP_HAVE_INTEGRATION
    const std::string dir = DECOMP_INTEGRATION_DIR;
    t.push_back({dir + "/cases_x64_O2.dll", true, "x64 -O2"});
    t.push_back({dir + "/cases_x64_O0.dll", true, "x64 -O0"});
    t.push_back({dir + "/cases_x86_O2.dll", false, "x86 -O2"});
    t.push_back({dir + "/cases_x86_O0.dll", false, "x86 -O0"});
#endif
    return t;
}

// One decompiled program, with its functions kept alive for the whole test.
struct Decompiled {
    std::unique_ptr<Program> prog;
    std::unique_ptr<Pipeline> pipe;
    std::map<std::string, std::unique_ptr<FunctionResult>> byName;
    std::map<u64, std::unique_ptr<FunctionResult>> byAddr;

    FunctionResult* atAddress(u64 va) {
        auto it = byAddr.find(va);
        if (it != byAddr.end()) return it->second.get();
        const dc::Function* mf = prog->functionAt(va);
        if (!mf) return nullptr;
        byAddr[va] = nullptr; // guard against unbounded recursion while building
        auto r = pipe->runToOptimized(*mf);
        FunctionResult* raw = r.get();
        byAddr[va] = std::move(r);
        return raw;
    }

    bool load(const std::string& path) {
        prog = std::make_unique<Program>(pe::Image::loadFile(path));
        prog->discoverFunctions();
        PipelineOptions po;
        po.verifyStages = true;
        pipe = std::make_unique<Pipeline>(*prog, po);
        return true;
    }
    FunctionResult* get(const std::string& name) {
        auto it = byName.find(name);
        if (it != byName.end()) return it->second.get();
        for (const auto& [va, mf] : prog->functions()) {
            std::string n = mf->name;
            if (!n.empty() && n[0] == '_' && !prog->is64()) n = n.substr(1); // x86 decoration
            if (n != name) continue;
            auto r = pipe->runToOptimized(*mf);
            FunctionResult* raw = r.get();
            byName[name] = std::move(r);
            return raw;
        }
        return nullptr;
    }
};

// Arguments are handed over in the convention's registers; a pointer argument
// is the address of the scratch buffer.
struct CallSetup {
    std::vector<u64> intArgs;   // by position
    std::vector<double> fltArgs;
    std::vector<bool> isFloat;
    std::vector<u8> scratchIn;
};

InterpResult runIr(Decompiled& d, const ir::Function& f, const pe::Image* img, bool is64,
                   const CallSetup& cs, std::vector<u8>* scratchOut, int depth = 0);

// Calls made by the code under test: recurse into the callee's own recovered
// IR, or emulate the handful of library routines the compiler emits.
struct CallHandler {
    Decompiled* d;
    InterpMemory* mem;
    bool is64;
    int depth;
    bool operator()(const CallInfo& c, const std::vector<u64>& args, u64& ret);
};

InterpResult runIr(Decompiled& d, const ir::Function& f, const pe::Image* img, bool is64,
                   const CallSetup& cs, std::vector<u8>* scratchOut, int depth) {
    const u64 kStack = stackAddrFor(is64);
    const u64 kScratch = scratchAddr(is64);
    InterpMemory mem;
    mem.image = img;
    mem.stackLo = kStack - 0x40000;
    mem.stackHi = kStack + 0x10000;
    for (size_t i = 0; i < cs.scratchIn.size(); ++i) mem.written[kScratch + i] = cs.scratchIn[i];

    ConventionInfo ci = conventionInfo(is64 ? CallConv::Win64 : CallConv::Cdecl, is64);
    unsigned ps = is64 ? 8 : 4;
    if (is64) {
        // Arguments past the fourth live above the shadow space.
        for (size_t i = ci.intArgRegs.size(); i < cs.intArgs.size(); ++i) {
            u64 v = cs.intArgs[i];
            for (unsigned k = 0; k < ps; ++k)
                mem.written[kStack + ci.stackArgStart + (i - 0) * ps - ci.intArgRegs.size() * ps + k] =
                    (u8)(v >> (k * 8));
        }
    }
    // 32-bit conventions pass everything on the stack, above the return address.
    if (!is64) {
        u64 sp = kStack;
        for (size_t i = 0; i < cs.intArgs.size(); ++i) {
            u64 v = cs.isFloat[i] ? 0 : cs.intArgs[i];
            if (cs.isFloat[i]) {
                double d = cs.fltArgs[i];
                std::memcpy(&v, &d, 8);
                for (int k = 0; k < 8; ++k) mem.written[sp + ci.stackArgStart + i * 4 + k] = (u8)(v >> (k * 8));
                continue;
            }
            for (unsigned k = 0; k < ps; ++k) mem.written[sp + ci.stackArgStart + i * ps + k] = (u8)(v >> (k * 8));
        }
    }
    InterpOptions io;
    io.stackBase = kStack;
    io.maxSteps = 4000000;
    io.entryValue = [&](Loc l, u64& out) {
        out = 0;
        if (l.kind == LocKind::Reg && (x86::Family)l.index == x86::Family::F_RSP) out = kStack;
        return true;
    };
    // Parameters are addressed by position, whatever the convention put them in.
    io.argValue = [&](unsigned index, Type, u64& out) {
        out = index < cs.intArgs.size() ? cs.intArgs[index] : 0;
        return true;
    };
    io.onCall = CallHandler{&d, &mem, is64, depth};
    InterpResult r = interpret(f, mem, io);
    if (scratchOut) {
        scratchOut->assign(kScratchSize, 0);
        for (size_t i = 0; i < kScratchSize; ++i) {
            auto it = mem.written.find(kScratch + i);
            (*scratchOut)[i] = it == mem.written.end() ? 0 : it->second;
        }
    }
    return r;
}

bool CallHandler::operator()(const CallInfo& c, const std::vector<u64>& args, u64& ret) {
    ret = 0;
    if (c.name.rfind("__chkstk", 0) == 0 || c.name.rfind("___chkstk", 0) == 0) return true;
    // Library routines the compiler substitutes for loops.
    auto readByte = [&](u64 a) -> u8 {
        u64 v = 0;
        return mem->read(a, 1, v) ? (u8)v : 0;
    };
    std::string n = c.name;
    if (!n.empty() && n[0] == '_') n = n.substr(1);
    if (n == "strlen" && args.size() >= 1) {
        u64 i = 0;
        while (i < 1u << 20 && readByte(args[0] + i)) ++i;
        ret = i;
        return true;
    }
    if ((n == "memcpy" || n == "memmove") && args.size() >= 3) {
        std::vector<u8> tmp(args[2]);
        for (u64 i = 0; i < args[2]; ++i) tmp[i] = readByte(args[1] + i);
        for (u64 i = 0; i < args[2]; ++i) mem->write(args[0] + i, 1, tmp[i]);
        ret = args[0];
        return true;
    }
    if (n == "memset" && args.size() >= 3) {
        for (u64 i = 0; i < args[2]; ++i) mem->write(args[0] + i, 1, args[1] & 0xFF);
        ret = args[0];
        return true;
    }
    if (!c.target || depth > 24) return false;
    FunctionResult* callee = d->atAddress(c.target);
    if (!callee || !callee->ir) return false;
    // Run the callee against the same memory so its stores are visible.
    ConventionInfo ci = conventionInfo(is64 ? CallConv::Win64 : CallConv::Cdecl, is64);
    unsigned ps = is64 ? 8 : 4;
    u64 calleeStack = stackAddrFor(is64) - 0x8000 - (u64)depth * 0x1000;
    if (!is64)
        for (size_t i = 0; i < args.size(); ++i)
            for (unsigned k = 0; k < ps; ++k)
                mem->write(calleeStack + ci.stackArgStart + i * ps + k, 1, (args[i] >> (k * 8)) & 0xFF);
    else
        for (size_t i = ci.intArgRegs.size(); i < args.size(); ++i)
            for (unsigned k = 0; k < ps; ++k)
                mem->write(calleeStack + ci.stackArgStart + (i - ci.intArgRegs.size()) * ps + k, 1,
                           (args[i] >> (k * 8)) & 0xFF);
    InterpOptions io;
    io.stackBase = calleeStack;
    io.maxSteps = 2000000;
    io.entryValue = [&](Loc l, u64& out) {
        out = 0;
        if (l.kind == LocKind::Reg && (x86::Family)l.index == x86::Family::F_RSP) out = calleeStack;
        return true;
    };
    io.argValue = [&](unsigned index, Type, u64& out) {
        out = index < args.size() ? args[index] : 0;
        return true;
    };
    io.onCall = CallHandler{d, mem, is64, depth + 1};
    InterpResult r = interpret(*callee->ir, *mem, io);
    if (!r.ok) return false;
    ret = r.value;
    return true;
}

u64 bitsOfFloat(float f) {
    u32 b;
    std::memcpy(&b, &f, 4);
    return b;
}
u64 bitsOfDouble(double d) {
    u64 b;
    std::memcpy(&b, &d, 8);
    return b;
}

int g_checked = 0;
int g_failed = 0;
int g_missing = 0;
int g_unmodelled = 0;

// True when the recovered IR still contains an instruction the lifter does
// not model. Such a function must be reported, never silently believed.
bool hasUnmodelledInstruction(const ir::Function& f) {
    for (const auto& b : f.blocks())
        for (ValueId v : b.insts) {
            const Inst& in = f.inst(v);
            if (in.op == Op::Intrinsic && in.text.rfind("asm(", 0) == 0) return true;
        }
    return false;
}

// Checks one function with integer arguments against a native reference.
void checkInt(Decompiled& d, const Target& t, const char* name, const std::vector<u64>& args, u64 expect,
              unsigned resultBits, const std::vector<u8>* scratchIn = nullptr,
              const std::vector<u8>* scratchExpect = nullptr, bool expectValue = true) {
    FunctionResult* fr = d.get(name);
    if (!fr) {
        ++g_missing;
        std::printf("    %s: %s not found\n", t.label.c_str(), name);
        return;
    }
    if (!fr->problems.empty()) {
        ++g_failed;
        std::printf("    %s %s: %s\n", t.label.c_str(), name, fr->problems[0].c_str());
        return;
    }
    // Packed SIMD is not modelled yet. The contract is that such a function is
    // flagged rather than quietly producing a wrong answer.
    if (hasUnmodelledInstruction(*fr->ir)) {
        if (fr->ir->notes().empty()) {
            ++g_failed;
            std::printf("    %s %s: unmodelled instruction not reported\n", t.label.c_str(), name);
        }
        ++g_unmodelled;
        return;
    }
    CallSetup cs;
    cs.intArgs = args;
    cs.fltArgs.assign(args.size(), 0);
    cs.isFloat.assign(args.size(), false);
    if (scratchIn) cs.scratchIn = *scratchIn;
    std::vector<u8> out;
    InterpResult r = runIr(d, *fr->ir, &d.prog->image(), t.is64, cs, scratchExpect ? &out : nullptr);
    ++g_checked;
    if (!r.ok) {
        ++g_failed;
        std::printf("    %s %s: %s\n", t.label.c_str(), name, r.error.c_str());
        return;
    }
    u64 got = truncBits(r.value, resultBits);
    u64 want = truncBits(expect, resultBits);
    if (expectValue && r.hasValue && got != want) {
        ++g_failed;
        std::printf("    %s %s(", t.label.c_str(), name);
        for (size_t i = 0; i < args.size(); ++i) std::printf("%s%lld", i ? ", " : "", (long long)args[i]);
        std::printf(") = %lld, expected %lld\n", (long long)(i64)got, (long long)(i64)want);
        return;
    }
    if (scratchExpect && out != *scratchExpect) {
        ++g_failed;
        std::printf("    %s %s: memory differs\n", t.label.c_str(), name);
    }
}

} // namespace

TEST(integration_decompiled_code_matches_source) {
    auto ts = targets();
    if (ts.empty()) {
        std::printf("    integration corpus not built (no MinGW); skipped\n");
        return;
    }
    std::mt19937 rng(7);
    for (const auto& t : ts) {
        Decompiled d;
        d.load(t.path);
        int before = g_failed;

        auto rnd = [&](int lo, int hi) { return (int)(lo + (int)(rng() % (unsigned)(hi - lo + 1))); };

        for (int trial = 0; trial < 8; ++trial) {
            int a = rnd(-1000, 1000), b = rnd(-100, 100), n = rnd(0, 30);
            unsigned ua = (unsigned)rng(), ub = (unsigned)rng() % 1000 + 1;

            checkInt(d, t, "t_add", {(u64)(i64)a, (u64)(i64)b}, (u64)(i64)t_add(a, b), 32);
            checkInt(d, t, "t_branch", {(u64)(i64)a}, (u64)(i64)t_branch(a), 32);
            checkInt(d, t, "t_ifelse_chain", {(u64)(i64)a}, (u64)(i64)t_ifelse_chain(a), 32);
            checkInt(d, t, "t_for_loop", {(u64)(i64)n}, (u64)(i64)t_for_loop(n), 32);
            checkInt(d, t, "t_while_loop", {(u64)(i64)(n % 12)}, (u64)(i64)t_while_loop(n % 12), 32);
            checkInt(d, t, "t_do_while", {(u64)(i64)(a & 0xFFFF)}, (u64)(i64)t_do_while(a & 0xFFFF), 32);
            checkInt(d, t, "t_nested_loops", {(u64)(i64)(n % 12)}, (u64)(i64)t_nested_loops(n % 12), 32);
            checkInt(d, t, "t_continue_break", {(u64)(i64)n}, (u64)(i64)t_continue_break(n), 32);
            checkInt(d, t, "t_bitops", {ua}, t_bitops(ua), 32);
            checkInt(d, t, "t_udiv", {ua, ub}, t_udiv(ua, ub), 32);
            checkInt(d, t, "t_sdiv", {(u64)(i64)a, (u64)(i64)(b ? b : 1)}, (u64)(i64)t_sdiv(a, b ? b : 1), 32);
            checkInt(d, t, "t_signed_compare", {(u64)(i64)a, (u64)(i64)b}, (u64)(i64)t_signed_compare(a, b), 32);
            checkInt(d, t, "t_call_helper", {(u64)(i64)a, (u64)(i64)b}, (u64)(i64)t_call_helper(a, b), 32);
            checkInt(d, t, "t_recursion", {(u64)(i64)(n % 10)}, (u64)(i64)t_recursion(n % 10), 32);
            checkInt(d, t, "t_mutual_a", {(u64)(i64)(n % 10)}, (u64)(i64)t_mutual_a(n % 10), 32);
            checkInt(d, t, "t_many_args",
                     {(u64)(i64)a, (u64)(i64)b, (u64)(i64)n, 4, 5, 6},
                     (u64)(i64)t_many_args(a, b, n, 4, 5, 6), 32);
            checkInt(d, t, "t_local_array", {(u64)(i64)(a % 100)}, (u64)(i64)t_local_array(a % 100), 32);
            for (int op = 0; op <= 9; ++op)
                checkInt(d, t, "t_switch", {(u64)(i64)op, (u64)(i64)a, (u64)(i64)b},
                         (u64)(i64)t_switch(op, a, b), 32);
            if (t.is64) {
                int64_t wa = (int64_t)a * 1000003, wb = (int64_t)b * 7919;
                checkInt(d, t, "t_wide", {(u64)wa, (u64)wb}, (u64)t_wide(wa, wb), 64);
            }
        }

        // Pointer arguments: a scratch buffer whose contents are compared after.
        {
            const u64 kScratch = scratchAddr(t.is64);
            std::vector<u8> in(kScratchSize, 0);
            for (size_t i = 0; i < kScratchSize; ++i) in[i] = (u8)(i * 7 + 3);
            struct Point p;
            std::memcpy(&p, in.data(), sizeof p);
            checkInt(d, t, "t_struct_sum", {kScratch}, (u64)(i64)t_struct_sum(&p), 32, &in);

            std::vector<u8> expect = in;
            struct Point p2;
            std::memcpy(&p2, expect.data(), sizeof p2);
            t_struct_write(&p2, 11, 22);
            std::memcpy(expect.data(), &p2, sizeof p2);
            checkInt(d, t, "t_struct_write", {kScratch, 11, 22}, 0, 32, &in, &expect, false);

            int arr[16];
            std::memcpy(arr, in.data(), sizeof arr);
            checkInt(d, t, "t_array_sum", {kScratch, 16}, (u64)(i64)t_array_sum(arr, 16), 32, &in);
            checkInt(d, t, "t_array_max", {kScratch, 16}, (u64)(i64)t_array_max(arr, 16), 32, &in);
            checkInt(d, t, "t_hash_bytes", {kScratch, 64}, t_hash_bytes(in.data(), 64), 32, &in);
            checkInt(d, t, "t_find_byte", {kScratch, 64, in[20]},
                     (u64)(i64)t_find_byte(in.data(), 64, in[20]), 32, &in);

            std::vector<u8> revIn = in;
            std::vector<u8> revExpect = in;
            int rarr[16];
            std::memcpy(rarr, revExpect.data(), sizeof rarr);
            t_array_reverse(rarr, 16);
            std::memcpy(revExpect.data(), rarr, sizeof rarr);
            checkInt(d, t, "t_array_reverse", {kScratch, 16}, 0, 32, &revIn, &revExpect, false);

            std::vector<u8> s(kScratchSize, 0);
            const char* txt = "integration";
            std::memcpy(s.data(), txt, std::strlen(txt) + 1);
            checkInt(d, t, "t_strlen", {kScratch}, (u64)(i64)t_strlen(txt), 32, &s);
        }
        if (g_failed != before) std::printf("    -- %s had failures\n", t.label.c_str());
    }
    std::printf("    %d checks across %zu builds, %d failures, %d not found, %d skipped "
                "(unmodelled instructions, reported)\n",
                g_checked, ts.size(), g_failed, g_missing, g_unmodelled);
    CHECK(g_checked > 100);
    CHECK_EQ(g_failed, 0);
    CHECK_EQ(g_missing, 0);
}
