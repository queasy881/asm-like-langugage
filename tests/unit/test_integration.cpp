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
constexpr size_t kScratchSize = 4096;

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
    std::vector<u64> intArgs;   // by position; a float argument holds its bits
    std::vector<double> fltArgs;
    std::vector<bool> isFloat;
    std::vector<unsigned> argBytes;  // stack footprint; empty means pointer-sized
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
    bool operator()(const CallInfo& c, u64 resolvedTarget, const std::vector<u64>& args, u64& ret);
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
        u64 off = ci.stackArgStart;
        for (size_t i = 0; i < cs.intArgs.size(); ++i) {
            unsigned width = i < cs.argBytes.size() && cs.argBytes[i] ? cs.argBytes[i] : ps;
            u64 v = cs.intArgs[i];
            if (i < cs.isFloat.size() && cs.isFloat[i]) {
                double dv = cs.fltArgs[i];
                std::memcpy(&v, &dv, 8);
                width = 8;
            }
            for (unsigned k = 0; k < width; ++k) mem.written[sp + off + k] = (u8)(v >> (k * 8));
            off += width;
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

bool CallHandler::operator()(const CallInfo& c, u64 resolvedTarget, const std::vector<u64>& args, u64& ret) {
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
    u64 target = c.target ? c.target : resolvedTarget;
    if (!target || depth > 24) return false;
    FunctionResult* callee = d->atAddress(target);
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

// A call with an explicit argument description, for the large corpora where
// arguments are pointers into a shared arena and some are doubles.
struct Arg {
    u64 bits = 0;
    bool isFloat = false;
    unsigned bytes = 0;   // 0 = pointer sized
    static Arg i(i64 v) { return Arg{(u64)v, false, 0}; }
    static Arg u(u64 v) { return Arg{v, false, 0}; }
    static Arg p(u64 v) { return Arg{v, false, 0}; }
    static Arg f(double v) { u64 b; std::memcpy(&b, &v, 8); return Arg{b, true, 8}; }
};

void checkCall(Decompiled& d, const Target& t, const char* name, const std::vector<Arg>& args,
               u64 expect, unsigned resultBits, const std::vector<u8>& memIn,
               const std::vector<u8>& memExpect, bool expectValue = true) {
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
    if (hasUnmodelledInstruction(*fr->ir)) {
        ++g_unmodelled;
        return;
    }
    CallSetup cs;
    for (const Arg& a : args) {
        cs.intArgs.push_back(a.bits);
        cs.isFloat.push_back(a.isFloat);
        double dv = 0;
        if (a.isFloat) std::memcpy(&dv, &a.bits, 8);
        cs.fltArgs.push_back(dv);
        cs.argBytes.push_back(a.bytes);
    }
    cs.scratchIn = memIn;
    std::vector<u8> out;
    InterpResult r = runIr(d, *fr->ir, &d.prog->image(), t.is64, cs, &out);
    ++g_checked;
    if (!r.ok) {
        ++g_failed;
        std::printf("    %s %s: %s\n", t.label.c_str(), name, r.error.c_str());
        return;
    }
    if (expectValue && r.hasValue && truncBits(r.value, resultBits) != truncBits(expect, resultBits)) {
        ++g_failed;
        std::printf("    %s %s = %lld, expected %lld\n", t.label.c_str(), name,
                    (long long)(i64)truncBits(r.value, resultBits),
                    (long long)(i64)truncBits(expect, resultBits));
        return;
    }
    if (out != memExpect) {
        size_t at = 0;
        while (at < out.size() && at < memExpect.size() && out[at] == memExpect[at]) ++at;
        ++g_failed;
        std::printf("    %s %s: memory differs at +0x%zx (got %02x want %02x)\n",
                    t.label.c_str(), name, at, at < out.size() ? out[at] : 0,
                    at < memExpect.size() ? memExpect[at] : 0);
    }
}

// The arena both sides work in: the native reference writes through real
// pointers, the decompiled code through the interpreter's scratch address.
struct Arena {
    std::vector<double> storage;
    u64 target = 0;
    explicit Arena(bool is64) : storage(kScratchSize / sizeof(double), 0.0) {
        target = scratchAddr(is64);
    }
    void clear() { std::fill(storage.begin(), storage.end(), 0.0); }
    u8* host(size_t off) { return (u8*)storage.data() + off; }
    u64 addr(size_t off) const { return target + off; }
    std::vector<u8> bytes() const {
        const u8* p = (const u8*)storage.data();
        return std::vector<u8>(p, p + kScratchSize);
    }
    void restore(const std::vector<u8>& b) { std::memcpy(storage.data(), b.data(), kScratchSize); }
};

std::vector<Target> bigTargets(const char* stem) {
    std::vector<Target> t;
#ifdef DECOMP_HAVE_INTEGRATION
    const std::string dir = DECOMP_INTEGRATION_DIR;
    t.push_back({dir + "/" + stem + "_x64_O2.dll", true, std::string("x64 -O2 ") + stem});
    t.push_back({dir + "/" + stem + "_x64_O0.dll", true, std::string("x64 -O0 ") + stem});
    t.push_back({dir + "/" + stem + "_x86_O2.dll", false, std::string("x86 -O2 ") + stem});
    t.push_back({dir + "/" + stem + "_x86_O0.dll", false, std::string("x86 -O0 ") + stem});
#else
    (void)stem;
#endif
    return t;
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
                checkInt(d, t, "t_mul_high", {(u64)wa, (u64)wb}, (u64)t_mul_high(wa, wb), 64);
                checkInt(d, t, "t_sign_extension",
                         {(u64)(i64)a, (u64)(i64)(short)b, (u64)(i64)(signed char)n},
                         (u64)t_sign_extension(a, (short)b, (signed char)n), 64);
                checkInt(d, t, "t_zero_extension",
                         {ua, (u64)(unsigned short)b, (u64)(unsigned char)n},
                         t_zero_extension(ua, (unsigned short)b, (unsigned char)n), 64);
            }

            // Control flow
            checkInt(d, t, "t_early_returns", {(u64)(i64)a, (u64)(i64)b, (u64)(i64)n},
                     (u64)(i64)t_early_returns(a, b, n), 32);
            checkInt(d, t, "t_nested_conditions", {(u64)(i64)a, (u64)(i64)b},
                     (u64)(i64)t_nested_conditions(a, b), 32);
            checkInt(d, t, "t_do_while_complex", {(u64)(i64)(n % 25 + 1)},
                     (u64)(i64)t_do_while_complex(n % 25 + 1), 32);
            checkInt(d, t, "t_triple_nested", {(u64)(i64)(n % 8)}, (u64)(i64)t_triple_nested(n % 8), 32);
            for (int op = 0; op <= 8; ++op)
                checkInt(d, t, "t_switch_fallthrough", {(u64)(i64)op, (u64)(i64)a},
                         (u64)(i64)t_switch_fallthrough(op, a), 32);
            for (int op : {0, 1, 100, 1000, 10000, 55})
                checkInt(d, t, "t_switch_sparse", {(u64)(i64)op}, (u64)(i64)t_switch_sparse(op), 32);
            checkInt(d, t, "t_goto_like", {(u64)(i64)a, (u64)(i64)b}, (u64)(i64)t_goto_like(a, b), 32);

            // Arithmetic
            checkInt(d, t, "t_mixed_widths", {(u64)(i64)a, (u64)(i64)(short)b, (u64)(i64)(signed char)n},
                     (u64)(i64)t_mixed_widths(a, (short)b, (signed char)n), 32);
            checkInt(d, t, "t_unsigned_ops", {ua, ub}, t_unsigned_ops(ua, ub), 32);
            checkInt(d, t, "t_div_by_constants", {(u64)(i64)a}, (u64)(i64)t_div_by_constants(a), 32);
            checkInt(d, t, "t_udiv_by_constants", {ua}, t_udiv_by_constants(ua), 32);
            checkInt(d, t, "t_abs_and_min_max", {(u64)(i64)a, (u64)(i64)b},
                     (u64)(i64)t_abs_and_min_max(a, b), 32);
            checkInt(d, t, "t_bool_logic", {(u64)(i64)a, (u64)(i64)b, (u64)(i64)n},
                     (u64)(i64)t_bool_logic(a, b, n), 32);

            // Calls
            checkInt(d, t, "t_call_chain", {(u64)(i64)a}, (u64)(i64)t_call_chain(a), 32);
            checkInt(d, t, "t_call_in_loop", {(u64)(i64)(n % 15)}, (u64)(i64)t_call_in_loop(n % 15), 32);
            checkInt(d, t, "t_call_in_condition", {(u64)(i64)a}, (u64)(i64)t_call_in_condition(a), 32);
            checkInt(d, t, "t_function_pointer", {(u64)(i64)(a & 1), (u64)(i64)b},
                     (u64)(i64)t_function_pointer(a & 1, b), 32);
            checkInt(d, t, "t_call_with_many",
                     {(u64)(i64)a, (u64)(i64)b, (u64)(i64)n, 4, 5, 6, 7, 8},
                     (u64)(i64)t_call_with_many(a, b, n, 4, 5, 6, 7, 8), 32);
            checkInt(d, t, "t_deep_recursion", {(u64)(i64)(n % 14)},
                     (u64)(i64)t_deep_recursion(n % 14), 32);
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

            // Structures of mixed widths, read and written.
            {
                std::vector<u8> win(kScratchSize, 0);
                for (size_t i = 0; i < kScratchSize; ++i) win[i] = (u8)(i * 13 + 5);
                struct Wide w;
                std::memcpy(&w, win.data(), sizeof w);
                // Keep the floating members finite so both runs agree.
                w.e = 1.5f;
                w.f = 2.25;
                std::memcpy(win.data(), &w, sizeof w);
                checkInt(d, t, "t_wide_struct", {kScratch}, (u64)(i64)t_wide_struct(&w), 32, &win);

                std::vector<u8> wexpect = win;
                struct Wide w2;
                std::memcpy(&w2, wexpect.data(), sizeof w2);
                t_wide_struct_write(&w2, 21);
                std::memcpy(wexpect.data(), &w2, sizeof w2);
                checkInt(d, t, "t_wide_struct_write", {kScratch, 21}, 0, 32, &win, &wexpect, false);

                struct Point pts[8];
                std::memcpy(pts, in.data(), sizeof pts);
                checkInt(d, t, "t_array_of_structs", {kScratch, 8},
                         (u64)(i64)t_array_of_structs(pts, 8), 32, &in);

                int m[12];
                std::memcpy(m, in.data(), sizeof m);
                checkInt(d, t, "t_two_dim", {kScratch, 3, 4}, (u64)(i64)t_two_dim(m, 3, 4), 32, &in);

                int arr2[16];
                std::memcpy(arr2, in.data(), sizeof arr2);
                checkInt(d, t, "t_loop_two_exits", {kScratch, 16, (u64)(i64)arr2[5]},
                         (u64)(i64)t_loop_two_exits(arr2, 16, arr2[5]), 32, &in);
                checkInt(d, t, "t_pointer_compare", {kScratch, kScratch + 16},
                         (u64)(i64)t_pointer_compare((const int*)1, (const int*)2), 32, &in);

                // A linked list built inside the scratch buffer.
                std::vector<u8> listMem(kScratchSize, 0);
                const u64 base = scratchAddr(t.is64);
                unsigned nodeSize = t.is64 ? 16u : 12u;
                for (int i = 0; i < 4; ++i) {
                    u64 off = (u64)i * nodeSize;
                    int value = 100 + i;
                    std::memcpy(listMem.data() + off, &value, 4);
                    // value, 4 bytes of padding, then the pointer.
                    u64 next = i == 3 ? 0 : base + off + nodeSize;
                    std::memcpy(listMem.data() + off + 8, &next, t.is64 ? 8 : 4);
                }
                checkInt(d, t, "t_walk_list", {base, 10}, (u64)(i64)(100 + 101 + 102 + 103), 32, &listMem);
            }
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

// ---------------------------------------------------------------------------
// The large corpora. Each function is driven with the same inputs natively and
// through the recovered IR, and both the return value and every byte the call
// touched in the shared arena have to agree.

namespace bigcorpus {
#define API
#include "big.c"
#undef API
}

namespace hugecorpus {
#define API
#include "huge.c"
#undef API
}

namespace {

void runBigCorpus(Decompiled& d, const Target& t) {
    using namespace bigcorpus;
    Arena ar(t.is64);
    std::mt19937 rng(0x5eed);

    auto snap = [&](auto&& fill, auto&& native, const char* name,
                    auto&& argsOf, unsigned bits = 32) {
        ar.clear();
        fill();
        std::vector<Arg> args = argsOf();
        std::vector<u8> before = ar.bytes();
        u64 expect = (u64)(i64)native();
        std::vector<u8> after = ar.bytes();
        ar.restore(before);
        checkCall(d, t, name, args, expect, bits, before, after);
    };

    // bignum_mul: a at 0, b at 64, out at 192
    snap([&] {
        auto* a = (uint32_t*)ar.host(0);
        auto* b = (uint32_t*)ar.host(64);
        for (int i = 0; i < 6; i++) a[i] = 0x80000000u + (uint32_t)rng();
        for (int i = 0; i < 5; i++) b[i] = (uint32_t)rng();
    }, [&] {
        return bignum_mul((const uint32_t*)ar.host(0), 6, (const uint32_t*)ar.host(64), 5,
                          (uint32_t*)ar.host(192), 16);
    }, "bignum_mul",
       [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i(6), Arg::p(ar.addr(64)), Arg::i(5), Arg::p(ar.addr(192)), Arg::i(16)}; });

    // tokenize: text at 0, tokens at 128
    snap([&] {
        const char* txt = "let x1 = 42 + foo*(bar - 7);\n\"str\" 0x1F end";
        std::memcpy(ar.host(0), txt, std::strlen(txt) + 1);
    }, [&] {
        return tokenize((const char*)ar.host(0), (int)std::strlen((char*)ar.host(0)),
                        (struct Token*)ar.host(128), 24);
    }, "tokenize", [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i((i64)std::strlen((char*)ar.host(0))), Arg::p(ar.addr(128)), Arg::i(24)}; });

    // crc32_with_table: data at 0, table at 512
    snap([&] {
        for (int i = 0; i < 64; i++) ar.host(0)[i] = (u8)(rng() & 0xFF);
    }, [&] {
        return (int)crc32_with_table((const uint8_t*)ar.host(0), 64, (uint32_t*)ar.host(512), 256);
    }, "crc32_with_table", [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i(64), Arg::p(ar.addr(512)), Arg::i(256)}; });

    // lu_decompose: 5x5 doubles at 0, perm at 256
    snap([&] {
        auto* m = (double*)ar.host(0);
        for (int i = 0; i < 25; i++) m[i] = (double)((int)(rng() % 19) - 9) + 0.5 * (i % 3);
        for (int i = 0; i < 5; i++) m[i * 5 + i] += 20.0;
    }, [&] {
        return lu_decompose((double*)ar.host(0), 5, (int*)ar.host(256), 5);
    }, "lu_decompose", [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i(5), Arg::p(ar.addr(256)), Arg::i(5)}; });

    // heap_sort_search
    int needle = 0;
    snap([&] {
        auto* a = (int*)ar.host(0);
        for (int i = 0; i < 24; i++) a[i] = (int)(rng() % 500) - 250;
        needle = a[7];
    }, [&] {
        return heap_sort_search((int*)ar.host(0), 24, needle);
    }, "heap_sort_search",
       [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i(24), Arg::i(needle)}; });

    // route_lookup: table at 0, outputs at 512
    {
        ar.clear();
        auto* rt = (struct Route*)ar.host(0);
        for (int i = 0; i < 8; i++) {
            rt[i].prefix = 0x0A000000u + (uint32_t)(i << 16);
            rt[i].mask = 0xFFFF0000u >> (i & 3);
            rt[i].metric = (uint16_t)(10 + i);
            rt[i].flags = (uint16_t)((i % 3) ? 1 : 3);
            rt[i].nextHop = 100 + i;
            rt[i].iface = i;
        }
        std::vector<u8> before = ar.bytes();
        u64 expect = (u64)(i64)route_lookup(rt, 8, 0x0A020030u, (int32_t*)ar.host(512),
                                            (int32_t*)ar.host(520));
        std::vector<u8> after = ar.bytes();
        ar.restore(before);
        checkCall(d, t, "route_lookup",
                  {Arg::p(ar.addr(0)), Arg::i(8), Arg::u(0x0A020030u), Arg::p(ar.addr(512)),
                   Arg::p(ar.addr(520))}, expect, 32, before, after);
    }

    // utf8_decode
    snap([&] {
        static const u8 seq[] = {'A', 0xC3, 0xA9, 0xE2, 0x82, 0xAC, 0xF0, 0x9F, 0x98, 0x80,
                                 'z', 0xFF, 0xC3, 0x28, 'q'};
        std::memcpy(ar.host(0), seq, sizeof(seq));
    }, [&] {
        return utf8_decode((const uint8_t*)ar.host(0), 15, (uint32_t*)ar.host(64), 16);
    }, "utf8_decode", [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i(15), Arg::p(ar.addr(64)), Arg::i(16)}; });

    // pool_init / pool_alloc / pool_free share the arena
    snap([] {}, [&] { return pool_init(ar.host(0), 512, 32); }, "pool_init",
         [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i(512), Arg::i(32)}; });
    {
        ar.clear();
        pool_init(ar.host(0), 512, 32);
        std::vector<u8> before = ar.bytes();
        u64 expect = (u64)(i64)pool_alloc(ar.host(0));
        std::vector<u8> after = ar.bytes();
        ar.restore(before);
        checkCall(d, t, "pool_alloc", {Arg::p(ar.addr(0))}, expect, 32, before, after);

        ar.restore(before);
        pool_alloc(ar.host(0));
        std::vector<u8> b2 = ar.bytes();
        u64 e2 = (u64)(i64)pool_free(ar.host(0), 0);
        std::vector<u8> a2 = ar.bytes();
        ar.restore(b2);
        checkCall(d, t, "pool_free", {Arg::p(ar.addr(0)), Arg::i(0)}, e2, 32, b2, a2);
    }

    // vm_run: state at 0, code at 512
    snap([&] {
        static const u8 prog[] = {1, 5, 1, 7, 3, 12, 0, 1, 9, 4, 13, 1, 2, 0};
        std::memcpy(ar.host(512), prog, sizeof(prog));
    }, [&] {
        return vm_run((struct VmState*)ar.host(0), (const uint8_t*)ar.host(512), 14, 200);
    }, "vm_run", [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::p(ar.addr(512)), Arg::i(14), Arg::i(200)}; });

    // text_wrap
    snap([&] {
        const char* txt = "the quick brown fox jumps over the lazy dog and keeps running along";
        std::memcpy(ar.host(0), txt, std::strlen(txt) + 1);
    }, [&] {
        return text_wrap((const char*)ar.host(0), (int)std::strlen((char*)ar.host(0)), 16,
                         (int*)ar.host(256), 16);
    }, "text_wrap", [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i((i64)std::strlen((char*)ar.host(0))), Arg::i(16), Arg::p(ar.addr(256)), Arg::i(16)}; });
}

void runHugeCorpus(Decompiled& d, const Target& t) {
    using namespace hugecorpus;
    Arena ar(t.is64);
    std::mt19937 rng(0xc0ffee);

    auto snap = [&](auto&& fill, auto&& native, const char* name,
                    auto&& argsOf, unsigned bits = 32, bool value = true) {
        ar.clear();
        fill();
        std::vector<Arg> args = argsOf();
        std::vector<u8> before = ar.bytes();
        u64 expect = (u64)(i64)native();
        std::vector<u8> after = ar.bytes();
        ar.restore(before);
        checkCall(d, t, name, args, expect, bits, before, after, value);
    };

    // json_scan
    snap([&] {
        const char* txt = "{\"a\":[1,-2.5e3,true,false,null],\"b\":{\"c\":\"x\\\"y\"}}";
        std::memcpy(ar.host(0), txt, std::strlen(txt) + 1);
    }, [&] {
        return json_scan((const char*)ar.host(0), (int)std::strlen((char*)ar.host(0)),
                         (struct JsonToken*)ar.host(128), 40);
    }, "json_scan", [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i((i64)std::strlen((char*)ar.host(0))), Arg::p(ar.addr(128)), Arg::i(40)}; });

    // matrix_solve: a 4x4 at 0, b at 256, x at 320
    snap([&] {
        auto* a = (double*)ar.host(0);
        auto* b = (double*)ar.host(256);
        for (int i = 0; i < 16; i++) a[i] = (double)((int)(rng() % 11) - 5);
        for (int i = 0; i < 4; i++) { a[i * 4 + i] += 12.0; b[i] = (double)(i + 1); }
    }, [&] {
        return matrix_solve((double*)ar.host(0), (double*)ar.host(256), 4, (double*)ar.host(320));
    }, "matrix_solve", [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::p(ar.addr(256)), Arg::i(4), Arg::p(ar.addr(320))}; });

    // huffman_lengths: freq at 0, lengths at 128, pool at 256
    snap([&] {
        auto* f = (int32_t*)ar.host(0);
        for (int i = 0; i < 12; i++) f[i] = (int32_t)(rng() % 40);
        f[3] = 0;
    }, [&] {
        return huffman_lengths((const int32_t*)ar.host(0), 12, (uint8_t*)ar.host(128),
                               (struct HuffNode*)ar.host(256), 32);
    }, "huffman_lengths",
       [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i(12), Arg::p(ar.addr(128)), Arg::p(ar.addr(256)), Arg::i(32)}; });

    // rle_codec both directions
    snap([&] {
        u8* in = ar.host(0);
        for (int i = 0; i < 60; i++) in[i] = (u8)((i / 7) % 4 == 0 ? 0xAA : (rng() & 0xFF));
    }, [&] {
        return rle_codec((const uint8_t*)ar.host(0), 60, (uint8_t*)ar.host(256), 256, 0);
    }, "rle_codec", [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i(60), Arg::p(ar.addr(256)), Arg::i(256), Arg::i(0)}; });

    snap([&] {
        static const u8 enc[] = {0x85, 0x11, 0x02, 1, 2, 3, 0x83, 0x77, 0x00, 9};
        std::memcpy(ar.host(0), enc, sizeof(enc));
    }, [&] {
        return rle_codec((const uint8_t*)ar.host(0), 10, (uint8_t*)ar.host(256), 256, 1);
    }, "rle_codec", [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i(10), Arg::p(ar.addr(256)), Arg::i(256), Arg::i(1)}; });

    // bitset_ops
    for (int op = 0; op <= 6; ++op) {
        snap([&] {
            auto* dst = (uint64_t*)ar.host(0);
            auto* src = (uint64_t*)ar.host(64);
            for (int i = 0; i < 6; i++) { dst[i] = ((u64)rng() << 32) | rng(); src[i] = (u64)rng(); }
        }, [&] {
            return bitset_ops((uint64_t*)ar.host(0), (const uint64_t*)ar.host(64), 6, op,
                              (int32_t*)ar.host(256));
        }, "bitset_ops",
           [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::p(ar.addr(64)), Arg::i(6), Arg::i(op), Arg::p(ar.addr(256))}; });
    }

    // sha256_block: state at 0, block at 64, scratch at 256
    snap([&] {
        auto* st = (uint32_t*)ar.host(0);
        static const uint32_t iv[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                       0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        std::memcpy(st, iv, sizeof(iv));
        for (int i = 0; i < 64; i++) ar.host(64)[i] = (u8)(i * 7 + 3);
    }, [&] {
        sha256_block((uint32_t*)ar.host(0), (const uint8_t*)ar.host(64), (uint32_t*)ar.host(256));
        return 0;
    }, "sha256_block", [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::p(ar.addr(64)), Arg::p(ar.addr(256))}; }, 32, false);

    // interp_eval: code at 0, stack at 256, slots at 1024, trace at 1536
    snap([&] {
        static const int32_t code[] = {
            OP_PUSHI, 7, OP_PUSHI, 5, OP_ADD, OP_DUP, OP_STORE, 0, OP_PUSHF, 2500,
            OP_MUL, OP_PRINT, OP_LOAD, 0, OP_PUSHI, 3, OP_CMP, OP_JZ, 22, OP_PUSHI,
            99, OP_PRINT, OP_PUSHI, 1, OP_NEG, OP_TOFLOAT, OP_TOINT, OP_HALT};
        std::memcpy(ar.host(0), code, sizeof(code));
    }, [&] {
        return interp_eval((const int32_t*)ar.host(0), 28, (struct Value*)ar.host(256), 16,
                           (struct Value*)ar.host(1024), 4, (int32_t*)ar.host(1536));
    }, "interp_eval",
       [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i(28), Arg::p(ar.addr(256)), Arg::i(16), Arg::p(ar.addr(1024)),
        Arg::i(4), Arg::p(ar.addr(1536))}; });

    // skiplist_ops: arena at 0, header at 3200, ops at 3264, results at 3600
    snap([&] {
        auto* hdr = (int32_t*)ar.host(3200);
        hdr[2] = 0x1234567;
        auto* ops = (int32_t*)ar.host(3264);
        int n = 0;
        for (int i = 0; i < 10; i++) { ops[n++] = 1; ops[n++] = (int)(rng() % 50); ops[n++] = i * 3; }
        for (int i = 0; i < 5; i++) { ops[n++] = 0; ops[n++] = (int)(rng() % 50); ops[n++] = 0; }
        ops[n++] = 2; ops[n++] = 7; ops[n++] = 0;
    }, [&] {
        return skiplist_ops((struct SkipNode*)ar.host(0), (int32_t*)ar.host(3200), 60,
                            (const int32_t*)ar.host(3264), 16, (int32_t*)ar.host(3600));
    }, "skiplist_ops",
       [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::p(ar.addr(3200)), Arg::i(60), Arg::p(ar.addr(3264)), Arg::i(16),
        Arg::p(ar.addr(3600))}; });

    // csv_parse
    snap([&] {
        const char* txt = "name, 42 ,\"quoted, field\"\nsecond,-7,+13\nx,,3\n";
        std::memcpy(ar.host(0), txt, std::strlen(txt) + 1);
    }, [&] {
        return csv_parse((const char*)ar.host(0), (int)std::strlen((char*)ar.host(0)),
                         (struct CsvField*)ar.host(128), 24, (int32_t*)ar.host(1024));
    }, "csv_parse",
       [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i((i64)std::strlen((char*)ar.host(0))), Arg::p(ar.addr(128)), Arg::i(24), Arg::p(ar.addr(1024))}; });

    // physics_step: bodies at 0, energy at 1024
    snap([&] {
        auto* b = (struct Body*)ar.host(0);
        for (int i = 0; i < 4; i++) {
            b[i].x = (double)(i * 3) - 4.0;
            b[i].y = (double)(i % 2) * 2.5;
            b[i].vx = 0.1 * i;
            b[i].vy = -0.05 * i;
            b[i].mass = 1.0 + i;
        }
    }, [&] {
        return physics_step((struct Body*)ar.host(0), 4, 0.125, 3, (double*)ar.host(1024));
    }, "physics_step",
       [&] { return std::vector<Arg>{Arg::p(ar.addr(0)), Arg::i(4), Arg::f(0.125), Arg::i(3), Arg::p(ar.addr(1024))}; });
}

} // namespace

TEST(integration_big_corpus) {
    auto ts = bigTargets("big");
    if (ts.empty()) { std::printf("    big corpus not built; skipped\n"); return; }
    int before = g_failed;
    for (const auto& t : ts) {
        Decompiled d;
        if (!d.load(t.path)) { std::printf("    %s: cannot load\n", t.label.c_str()); continue; }
        int mark = g_failed;
        runBigCorpus(d, t);
        if (g_failed != mark) std::printf("    -- %s had failures\n", t.label.c_str());
    }
    CHECK(g_failed == before);
}

TEST(integration_huge_corpus) {
    auto ts = bigTargets("huge");
    if (ts.empty()) { std::printf("    huge corpus not built; skipped\n"); return; }
    int before = g_failed;
    for (const auto& t : ts) {
        Decompiled d;
        if (!d.load(t.path)) { std::printf("    %s: cannot load\n", t.label.c_str()); continue; }
        int mark = g_failed;
        runHugeCorpus(d, t);
        if (g_failed != mark) std::printf("    -- %s had failures\n", t.label.c_str());
    }
    CHECK(g_failed == before);
}
