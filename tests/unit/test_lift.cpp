#include "test_framework.h"
#include "pe_builder.h"

#include "lift/lifter.h"

#include <algorithm>

using namespace dc;
using namespace dc::ir;

namespace {

struct Lifted {
    std::unique_ptr<Program> prog;
    lift::LiftResult result;
    dc::Function* mf = nullptr;
    ir::Function* f = nullptr;
};

// Assembles the given bytes at the entry point and lifts the function there.
Lifted liftBytes(bool is64, std::vector<u8> code, lift::LiftOptions opt = {}) {
    dctest::PeBuilder pb;
    pb.is64 = is64;
    pb.imageBase = is64 ? 0x140000000ull : 0x400000ull;
    pb.code = std::move(code);
    Lifted out;
    out.prog = std::make_unique<Program>(pe::Image::loadBuffer(pb.build(), "<test>"));
    out.prog->discoverFunctions();
    out.mf = out.prog->functionAt(pb.codeVa());
    if (!out.mf) return out;
    out.result = lift::liftFunction(*out.prog, *out.mf, opt);
    out.f = out.result.func.get();
    return out;
}

int countOp(const ir::Function& f, Op op) {
    int n = 0;
    for (const auto& b : f.blocks())
        for (ValueId v : b.insts)
            if (f.inst(v).op == op) ++n;
    return n;
}

int countCasts(const ir::Function& f) {
    int n = 0;
    for (const auto& b : f.blocks())
        for (ValueId v : b.insts)
            if (isCast(f.inst(v).op)) ++n;
    return n;
}

bool hasOp(const ir::Function& f, Op op) { return countOp(f, op) > 0; }

} // namespace

TEST(lift_x64_load_add_return) {
    // mov eax, [rcx+8] ; add eax, 1 ; ret
    auto L = liftBytes(true, {0x8B, 0x41, 0x08, 0x83, 0xC0, 0x01, 0xC3});
    REQUIRE(L.f);
    CHECK(L.f->verify().empty());
    CHECK_EQ(countOp(*L.f, Op::Load), 1);
    CHECK_EQ(countOp(*L.f, Op::Add), 2); // address computation + the increment
    // Everything is 32-bit wide; no cast should be needed anywhere.
    CHECK_EQ(countCasts(*L.f), 0);
    CHECK(L.result.unsupported.empty());
}

TEST(lift_x86_load_add_return) {
    // mov eax, [ebp-8] ; add eax, 1 ; ret   (32-bit)
    auto L = liftBytes(false, {0x8B, 0x45, 0xF8, 0x83, 0xC0, 0x01, 0xC3});
    REQUIRE(L.f);
    CHECK(L.f->verify().empty());
    CHECK_EQ(countOp(*L.f, Op::Load), 1);
    CHECK_EQ(countCasts(*L.f), 0);
}

TEST(lift_flags_are_lazy) {
    // cmp ecx, edx ; jl .L ; ret ; .L: ret
    auto L = liftBytes(true, {0x39, 0xD1, 0x7C, 0x01, 0xC3, 0xC3});
    REQUIRE(L.f);
    CHECK(L.f->verify().empty());
    // A signed comparison, and nothing else: no flag bits materialised.
    CHECK_EQ(countOp(*L.f, Op::CmpSlt), 1);
    CHECK_EQ(countOp(*L.f, Op::CmpSge), 0);
    CHECK_EQ(countOp(*L.f, Op::Xor), 0); // SF^OF never computed
    for (const auto& b : L.f->blocks())
        for (ValueId v : b.insts)
            CHECK(L.f->inst(v).loc.kind != LocKind::Flag);
}

TEST(lift_test_self_becomes_compare_with_zero) {
    // test eax, eax ; je .L ; ret ; .L: ret
    auto L = liftBytes(true, {0x85, 0xC0, 0x74, 0x01, 0xC3, 0xC3});
    REQUIRE(L.f);
    CHECK_EQ(countOp(*L.f, Op::CmpEq), 1);
    CHECK_EQ(countOp(*L.f, Op::And), 0); // the AND of a value with itself is elided
}

TEST(lift_xor_self_is_zero) {
    // xor eax, eax ; ret
    auto L = liftBytes(true, {0x31, 0xC0, 0xC3});
    REQUIRE(L.f);
    CHECK_EQ(countOp(*L.f, Op::Xor), 0);
    bool sawZero = false;
    for (const auto& b : L.f->blocks())
        for (ValueId v : b.insts)
            if (L.f->inst(v).op == Op::Const && L.f->inst(v).imm == 0) sawZero = true;
    CHECK(sawZero);
}

TEST(lift_sub_register_write_preserves_upper) {
    // mov al, 5 ; mov edx, eax ; ret
    // Writing AL keeps the upper 24 bits of EAX, so reading EAX afterwards
    // must compose the two.
    auto L = liftBytes(true, {0xB0, 0x05, 0x89, 0xC2, 0xC3});
    REQUIRE(L.f);
    CHECK(L.f->verify().empty());
    CHECK(hasOp(*L.f, Op::And));  // old bits masked
    CHECK(hasOp(*L.f, Op::Or));   // new byte deposited

    // When AL is the only way the register is touched, no composition is
    // needed at all: the variable is simply one byte wide.
    auto L2 = liftBytes(true, {0xB0, 0x05, 0xC3});
    REQUIRE(L2.f);
    CHECK_EQ(countCasts(*L2.f), 0);
    CHECK(!hasOp(*L2.f, Op::Or));
}

TEST(lift_32bit_write_zero_extends) {
    // mov eax, ecx ; ret    -- in x64 this clears the upper half of RAX
    auto L = liftBytes(true, {0x89, 0xC8, 0xC3});
    REQUIRE(L.f);
    CHECK(L.f->verify().empty());
    CHECK_EQ(countCasts(*L.f), 0); // both sides are 32-bit: no zext is observable
}

TEST(lift_width_election) {
    // A function that only touches ecx at 32 bits elects a 32-bit variable.
    auto L = liftBytes(true, {0x83, 0xC1, 0x01, 0x89, 0xC8, 0xC3}); // add ecx,1 ; mov eax,ecx ; ret
    REQUIRE(L.mf);
    auto widths = lift::electRegisterWidths(*L.mf, true);
    CHECK_EQ((int)widths[(size_t)x86::Family::F_RCX], 4);
    CHECK_EQ((int)widths[(size_t)x86::Family::F_RAX], 4);
    // Pushing rbx uses it at full width.
    auto L2 = liftBytes(true, {0x53, 0x89, 0xCB, 0x5B, 0xC3}); // push rbx; mov ebx,ecx; pop rbx; ret
    REQUIRE(L2.mf);
    auto w2 = lift::electRegisterWidths(*L2.mf, true);
    CHECK_EQ((int)w2[(size_t)x86::Family::F_RBX], 8);
}

TEST(lift_stack_slots_become_frame_references) {
    // sub rsp,0x18 ; mov dword [rsp+8], ecx ; mov eax,[rsp+8] ; add rsp,0x18 ; ret
    auto L = liftBytes(true, {0x48, 0x83, 0xEC, 0x18, 0x89, 0x4C, 0x24, 0x08,
                              0x8B, 0x44, 0x24, 0x08, 0x48, 0x83, 0xC4, 0x18, 0xC3});
    REQUIRE(L.f);
    CHECK(L.f->verify().empty());
    int frames = countOp(*L.f, Op::FrameAddr);
    CHECK(frames >= 2);
    // Both references resolve to the same frame offset.
    std::vector<i64> offs;
    for (const auto& b : L.f->blocks())
        for (ValueId v : b.insts)
            if (L.f->inst(v).op == Op::FrameAddr) offs.push_back((i64)L.f->inst(v).imm);
    REQUIRE(offs.size() >= 2);
    CHECK_EQ(offs[0], offs[1]);
    CHECK_EQ(offs[0], (i64)-0x10); // rsp-0x18+8 relative to entry
}

TEST(lift_float_ops_have_float_types) {
    // movss xmm0,[rcx] ; addss xmm0,[rdx] ; movss [r8],xmm0 ; ret
    auto L = liftBytes(true, {0xF3, 0x0F, 0x10, 0x01, 0xF3, 0x0F, 0x58, 0x02,
                              0xF3, 0x41, 0x0F, 0x11, 0x00, 0xC3});
    REQUIRE(L.f);
    CHECK(L.f->verify().empty());
    CHECK_EQ(countOp(*L.f, Op::FAdd), 1);
    // The value stays f32 throughout, so no bitcasts are needed.
    CHECK_EQ(countOp(*L.f, Op::Bitcast), 0);
    for (const auto& b : L.f->blocks())
        for (ValueId v : b.insts)
            if (L.f->inst(v).op == Op::FAdd) CHECK(L.f->inst(v).type == kF32);
}

TEST(lift_double_conversion) {
    // cvtsi2sd xmm0, ecx ; ret
    auto L = liftBytes(true, {0xF2, 0x0F, 0x2A, 0xC1, 0xC3});
    REQUIRE(L.f);
    CHECK_EQ(countOp(*L.f, Op::SIToFP), 1);
}

TEST(lift_division_narrows_when_dividend_is_extended) {
    // cdq ; idiv ecx ; ret   -- RDX is just the sign of EAX, so it is a 32-bit divide
    auto L = liftBytes(true, {0x99, 0xF7, 0xF9, 0xC3});
    REQUIRE(L.f);
    CHECK(L.f->verify().empty());
    CHECK_EQ(countOp(*L.f, Op::SDiv), 1);
    for (const auto& b : L.f->blocks())
        for (ValueId v : b.insts)
            if (L.f->inst(v).op == Op::SDiv) CHECK_EQ((int)L.f->inst(v).type.bits, 32);
}

TEST(lift_unsupported_is_reported_not_dropped) {
    // f2 0f 70 = an SSE shuffle we do not model; must be recorded explicitly.
    auto L = liftBytes(true, {0xF2, 0x0F, 0x70, 0xC1, 0x00, 0xC3});
    REQUIRE(L.f);
    CHECK(!L.result.unsupported.empty());
    CHECK(!L.f->notes().empty());
    bool sawIntrinsic = false;
    for (const auto& b : L.f->blocks())
        for (ValueId v : b.insts)
            if (L.f->inst(v).op == Op::Intrinsic) sawIntrinsic = true;
    CHECK(sawIntrinsic);
}

TEST(lift_corpus_verifies) {
    auto prog = std::make_unique<Program>(pe::Image::loadFile(dctest::corpusPath("behemoth.dll")));
    prog->discoverFunctions();
    int problems = 0, lifted = 0;
    std::vector<std::string> unsupported;
    for (const auto& [va, mf] : prog->functions()) {
        if (mf->isImportThunk) continue;
        auto r = lift::liftFunction(*prog, *mf);
        ++lifted;
        auto errs = r.func->verify();
        if (!errs.empty()) {
            ++problems;
            std::printf("    %s: %s\n", mf->name.c_str(), errs[0].c_str());
        }
        for (const auto& u : r.unsupported)
            if (std::find(unsupported.begin(), unsupported.end(), u) == unsupported.end()) unsupported.push_back(u);
    }
    CHECK(lifted > 60);
    CHECK_EQ(problems, 0);
    if (!unsupported.empty()) {
        std::printf("    unsupported mnemonics:");
        for (const auto& u : unsupported) std::printf(" %s", u.c_str());
        std::printf("\n");
    }
}
