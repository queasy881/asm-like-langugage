#include "test_framework.h"
#include "pe_builder.h"

#include "core/interpreter.h"
#include "core/pipeline.h"

#include <random>

using namespace dc;
using namespace dc::ir;

namespace {

// Runs a function with the given integer arguments in the Win64 registers and
// a scratch stack, returning the result.
InterpResult runFunction(const ir::Function& f, const pe::Image* img, const std::vector<u64>& args,
                         std::vector<std::pair<u64, u64>>* writes, bool is64 = true) {
    InterpMemory mem;
    mem.image = img;
    InterpOptions io;
    io.stackBase = 0x7FF000000000ull;
    mem.stackLo = io.stackBase - 0x20000;
    mem.stackHi = io.stackBase + 0x10000;
    io.maxSteps = 400000;
    ConventionInfo ci = conventionInfo(is64 ? CallConv::Win64 : CallConv::Cdecl, is64);
    io.entryValue = [&](Loc l, u64& out) {
        out = 0;
        if (l.kind == LocKind::Reg) {
            x86::Family fam = (x86::Family)l.index;
            if (fam == x86::Family::F_RSP) {
                out = io.stackBase;
                return true;
            }
            for (size_t i = 0; i < ci.intArgRegs.size(); ++i)
                if (ci.intArgRegs[i] == fam && i < args.size()) {
                    out = args[i];
                    return true;
                }
            if (x86::isXmmFamily(fam)) {
                int xi = x86::xmmIndex(fam);
                if (xi >= 0 && (size_t)xi < args.size()) out = args[xi];
                return true;
            }
            // Callee-saved and scratch registers start from a fixed pattern so
            // the two runs see the same inputs.
            out = 0x1111111111111111ull * (u64)((int)fam + 1);
            return true;
        }
        return true;
    };
    // Calls return a value derived from their arguments, deterministically.
    io.onCall = [](const CallInfo& ci2, const std::vector<u64>& a, u64& ret) {
        u64 h = fnv1a64(ci2.name.data(), ci2.name.size());
        for (u64 x : a) h = (h ^ x) * 0x100000001b3ull;
        ret = h;
        return true;
    };
    InterpResult r = interpret(f, mem, io);
    if (writes) *writes = mem.writeLog;
    return r;
}

} // namespace

TEST(opt_constant_folding_and_algebra) {
    ir::Function f("t");
    int b0 = f.addBlock();
    ValueId a = f.constInt(b0, kI32, 6);
    ValueId b = f.constInt(b0, kI32, 7);
    ValueId m = f.binary(b0, Op::Mul, kI32, a, b);
    Inst ret;
    ret.op = Op::Return;
    ret.args = {m};
    f.add(b0, std::move(ret));
    opt::optimize(f);
    ValueId r = f.block(b0).insts.back();
    CHECK(f.inst(f.inst(r).args[0]).op == Op::Const);
    CHECK_EQ(f.inst(f.inst(r).args[0]).imm, (u64)42);
}

TEST(opt_identity_chain_collapses) {
    // t1 = a + 0 ; t2 = t1 * 1 ; return t2   ->   return a
    ir::Function f("t");
    int b0 = f.addBlock();
    Inst ev;
    ev.op = Op::EntryValue;
    ev.type = kI32;
    ev.loc = Loc{LocKind::Reg, 1, 4};
    ValueId a = f.add(b0, std::move(ev));
    ValueId zero = f.constInt(b0, kI32, 0);
    ValueId one = f.constInt(b0, kI32, 1);
    ValueId t1 = f.binary(b0, Op::Add, kI32, a, zero);
    ValueId t2 = f.binary(b0, Op::Mul, kI32, t1, one);
    Inst ret;
    ret.op = Op::Return;
    ret.args = {t2};
    f.add(b0, std::move(ret));
    opt::optimize(f);
    ValueId r = f.block(b0).insts.back();
    CHECK_EQ(f.inst(r).args[0], a);
    CHECK_EQ(f.block(b0).insts.size(), (size_t)2); // the entry value and the return
}

TEST(opt_does_not_merge_distinct_entry_values) {
    // Two different incoming registers must never be treated as one value.
    ir::Function f("t");
    int b0 = f.addBlock();
    Inst e1;
    e1.op = Op::EntryValue;
    e1.type = kI64;
    e1.loc = Loc{LocKind::Reg, 2, 8};
    ValueId a = f.add(b0, std::move(e1));
    Inst e2;
    e2.op = Op::EntryValue;
    e2.type = kI64;
    e2.loc = Loc{LocKind::Reg, 3, 8};
    ValueId b = f.add(b0, std::move(e2));
    ValueId s = f.binary(b0, Op::Add, kI64, a, b);
    Inst ret;
    ret.op = Op::Return;
    ret.args = {s};
    f.add(b0, std::move(ret));
    opt::optimize(f);
    ValueId r = f.block(b0).insts.back();
    const Inst& add = f.inst(f.inst(r).args[0]);
    REQUIRE(add.op == Op::Add);
    CHECK(add.args[0] != add.args[1]);
}

TEST(opt_dead_store_of_unused_value) {
    ir::Function f("t");
    int b0 = f.addBlock();
    ValueId a = f.constInt(b0, kI32, 5);
    f.binary(b0, Op::Add, kI32, a, a); // never used
    Inst ret;
    ret.op = Op::Return;
    f.add(b0, std::move(ret));
    opt::optimize(f);
    CHECK_EQ(f.block(b0).insts.size(), (size_t)1);
}

TEST(opt_branch_on_constant_is_folded) {
    ir::Function f("t");
    int b0 = f.addBlock(), b1 = f.addBlock(), b2 = f.addBlock();
    ValueId c = f.constInt(b0, kI1, 1);
    Inst br;
    br.op = Op::Branch;
    br.args = {c};
    f.add(b0, std::move(br));
    f.block(b0).succs = {b1, b2};
    for (int b : {b1, b2}) {
        ValueId k = f.constInt(b, kI32, b == b1 ? 10 : 20);
        Inst ret;
        ret.op = Op::Return;
        ret.args = {k};
        f.add(b, std::move(ret));
    }
    f.recomputePreds();
    opt::optimize(f);
    CHECK_EQ(f.blockCount(), 2); // the untaken arm is gone
}

// --- differential testing against the corpus -------------------------------

TEST(opt_preserves_behaviour_on_corpus) {
    auto prog = std::make_unique<Program>(pe::Image::loadFile(dctest::corpusPath("behemoth.dll")));
    prog->discoverFunctions();
    PipelineOptions po;
    po.verifyStages = true;

    std::mt19937_64 rng(99);
    int compared = 0, mismatches = 0, skipped = 0;
    for (const auto& [va, mf] : prog->functions()) {
        if (mf->isImportThunk || mf->hasUnresolvedIndirect || mf->hasDecodeErrors) continue;
        Pipeline pipe(prog ? *prog : *prog, po);
        auto plain = pipe.runToSsa(*mf);
        auto tuned = pipe.runToOptimized(*mf);
        if (!plain->problems.empty() || !tuned->problems.empty()) {
            ++mismatches;
            std::printf("    %s: %s\n", mf->name.c_str(),
                        plain->problems.empty() ? tuned->problems[0].c_str() : plain->problems[0].c_str());
            continue;
        }
        bool any = false;
        for (int trial = 0; trial < 6; ++trial) {
            // Arguments are small integers so pointer arguments mostly land in
            // unmapped memory and both runs fail identically.
            std::vector<u64> args;
            for (int i = 0; i < 6; ++i) args.push_back(trial == 0 ? 0 : (rng() & 0xFF));
            std::vector<std::pair<u64, u64>> w1, w2;
            InterpResult r1 = runFunction(*plain->ir, &prog->image(), args, &w1);
            InterpResult r2 = runFunction(*tuned->ir, &prog->image(), args, &w2);
            if (!r1.ok && !r2.ok) continue; // both trapped the same way
            any = true;
            if (r1.ok != r2.ok || r1.hasValue != r2.hasValue || (r1.hasValue && r1.value != r2.value) || w1 != w2) {
                ++mismatches;
                std::printf("    %s trial %d: %s(%llu) vs %s(%llu)\n", mf->name.c_str(), trial,
                            r1.ok ? "ok" : r1.error.c_str(), (unsigned long long)r1.value,
                            r2.ok ? "ok" : r2.error.c_str(), (unsigned long long)r2.value);
                break;
            }
        }
        if (any) ++compared;
        else ++skipped;
    }
    std::printf("    compared %d functions (%d skipped, no reachable behaviour)\n", compared, skipped);
    CHECK(compared > 20);
    CHECK_EQ(mismatches, 0);
}

TEST(interp_matches_known_algorithms) {
    auto prog = std::make_unique<Program>(pe::Image::loadFile(dctest::corpusPath("behemoth.dll")));
    prog->discoverFunctions();
    PipelineOptions po;
    Pipeline pipe(*prog, po);

    auto byName = [&](const char* n) -> const dc::Function* {
        for (const auto& [va, f] : prog->functions())
            if (f->name == n) return f.get();
        return nullptr;
    };

    // Place a test string in scratch memory and hash it, then compare against
    // the reference implementations of the same algorithms.
    const char* text = "hello world";
    size_t len = std::strlen(text);
    const u64 strAddr = 0x7FE000000000ull;

    auto runWith = [&](const dc::Function* mf, std::vector<u64> args) {
        auto r = pipe.runToOptimized(*mf);
        InterpMemory mem;
        mem.image = &prog->image();
        for (size_t i = 0; i <= len; ++i) mem.written[strAddr + i] = (u8)text[i];
        InterpOptions io;
        io.maxSteps = 200000;
        mem.stackLo = io.stackBase - 0x20000;
        mem.stackHi = io.stackBase + 0x10000;
        ConventionInfo ci = conventionInfo(CallConv::Win64, true);
        io.entryValue = [&](Loc l, u64& out) {
            out = 0;
            if (l.kind != LocKind::Reg) return true;
            x86::Family fam = (x86::Family)l.index;
            if (fam == x86::Family::F_RSP) { out = io.stackBase; return true; }
            for (size_t i = 0; i < ci.intArgRegs.size(); ++i)
                if (ci.intArgRegs[i] == fam && i < args.size()) { out = args[i]; return true; }
            return true;
        };
        return interpret(*r->ir, mem, io);
    };

    // fnv1a_hash(data, len)
    if (const dc::Function* mf = byName("fnv1a_hash")) {
        u32 expect = 0x811c9dc5u;
        for (size_t i = 0; i < len; ++i) { expect ^= (u8)text[i]; expect *= 0x01000193u; }
        InterpResult r = runWith(mf, {strAddr, len});
        CHECK(r.ok);
        if (r.ok) CHECK_EQ((u32)r.value, expect);
    }
    // fnv1a_hash64(data, len)
    if (const dc::Function* mf = byName("fnv1a_hash64")) {
        u64 expect = 0xcbf29ce484222325ull;
        for (size_t i = 0; i < len; ++i) { expect ^= (u8)text[i]; expect *= 0x100000001b3ull; }
        InterpResult r = runWith(mf, {strAddr, len});
        CHECK(r.ok);
        if (r.ok) CHECK_EQ(r.value, expect);
    }
    // djb2(str)
    if (const dc::Function* mf = byName("djb2")) {
        u32 expect = 5381;
        for (size_t i = 0; i < len; ++i) expect = expect * 33 + (u8)text[i];
        InterpResult r = runWith(mf, {strAddr});
        CHECK(r.ok);
        if (r.ok) CHECK_EQ((u32)r.value, expect);
    }
    // is_prime(n)
    if (const dc::Function* mf = byName("is_prime")) {
        for (u64 n : {0ull, 1ull, 2ull, 3ull, 4ull, 17ull, 25ull, 97ull, 1000003ull}) {
            bool expect = n >= 2;
            for (u64 d = 2; d * d <= n && expect; ++d)
                if (n % d == 0) expect = false;
            InterpResult r = runWith(mf, {n});
            CHECK(r.ok);
            if (r.ok) CHECK_EQ((int)(r.value & 1), (int)expect);
        }
    }
    // gcd(a, b)
    if (const dc::Function* mf = byName("gcd")) {
        auto ref = [](u64 a, u64 b) {
            while (b) { u64 t = a % b; a = b; b = t; }
            return a;
        };
        for (auto [a, b] : std::vector<std::pair<u64, u64>>{{12, 18}, {17, 5}, {100, 75}, {0, 9}, {36, 0}}) {
            InterpResult r = runWith(mf, {a, b});
            CHECK(r.ok);
            if (r.ok) CHECK_EQ(r.value, ref(a, b));
        }
    }
    // reverse_bits(x) and next_power_of_2(x)
    if (const dc::Function* mf = byName("reverse_bits")) {
        for (u32 x : {0u, 1u, 0x80000000u, 0x12345678u}) {
            u32 expect = 0;
            for (int i = 0; i < 32; ++i)
                if (x & (1u << i)) expect |= 1u << (31 - i);
            InterpResult r = runWith(mf, {x});
            CHECK(r.ok);
            if (r.ok) CHECK_EQ((u32)r.value, expect);
        }
    }
    if (const dc::Function* mf = byName("next_power_of_2")) {
        for (u32 x : {0u, 1u, 2u, 3u, 5u, 1000u, 65536u}) {
            u32 expect = 1;
            while (expect < x) expect <<= 1;
            InterpResult r = runWith(mf, {x});
            CHECK(r.ok);
            if (r.ok) CHECK_EQ((u32)r.value, expect);
        }
    }
    if (const dc::Function* mf = byName("count_leading_zeros")) {
        for (u32 x : {0u, 1u, 0xFFu, 0x80000000u, 0x12345678u}) {
            u32 expect = x ? (u32)__builtin_clz(x) : 32u;
            InterpResult r = runWith(mf, {x});
            CHECK(r.ok);
            if (r.ok) CHECK_EQ((u32)r.value, expect);
        }
    }
    // vm_exec exercises the recovered jump table.
    if (const dc::Function* mf = byName("vm_exec")) {
        // PUSH 5, PUSH 3, ADD, HALT  -- opcode numbering unknown, so just
        // check that every opcode byte runs without the interpreter trapping.
        const u64 vmAddr = 0x7FD000000000ull, codeAddr = 0x7FD000001000ull;
        auto r = pipe.runToOptimized(*mf);
        for (int opcode = 0; opcode < 16; ++opcode) {
            InterpMemory mem;
            mem.image = &prog->image();
            mem.written[codeAddr] = (u8)opcode;
            mem.written[codeAddr + 1] = 1;
            InterpOptions io;
            io.maxSteps = 100000;
            mem.stackLo = io.stackBase - 0x20000;
            mem.stackHi = io.stackBase + 0x10000;
            mem.stackLo = std::min(mem.stackLo, vmAddr);
            mem.stackHi = std::max(mem.stackHi, vmAddr + 0x200);
            std::vector<u64> args{vmAddr, codeAddr, 2, 4};
            ConventionInfo ci = conventionInfo(CallConv::Win64, true);
            io.entryValue = [&](Loc l, u64& out) {
                out = 0;
                if (l.kind != LocKind::Reg) return true;
                x86::Family fam = (x86::Family)l.index;
                if (fam == x86::Family::F_RSP) { out = io.stackBase; return true; }
                for (size_t i = 0; i < ci.intArgRegs.size(); ++i)
                    if (ci.intArgRegs[i] == fam && i < args.size()) { out = args[i]; return true; }
                return true;
            };
            InterpResult ir2 = interpret(*r->ir, mem, io);
            CHECK(ir2.ok);
            if (!ir2.ok) {
                std::printf("    vm_exec opcode %d: %s\n", opcode, ir2.error.c_str());
                break;
            }
        }
    }
}
