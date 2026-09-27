#include "test_framework.h"

#include "disasm/disassembler.h"

using namespace dc;
using namespace dc::x86;

static Instruction dec(bool is64, std::vector<u8> bytes, u64 addr = 0x1000) {
    auto d = createX86Disassembler(is64);
    Instruction in;
    bool ok = d->decode(bytes, addr, in);
    CHECK(ok);
    return in;
}

TEST(disasm_x64_basic) {
    Instruction in = dec(true, {0x8B, 0x41, 0x08}); // mov eax, [rcx+8]
    CHECK(in.mnem == Mnem::Mov);
    CHECK_EQ((int)in.numOps, 2);
    CHECK(in.ops[0].isReg(Reg::EAX));
    CHECK(in.ops[1].isMem());
    CHECK(in.ops[1].mem.base == Reg::RCX);
    CHECK_EQ(in.ops[1].mem.disp, (i64)8);
    CHECK_EQ((int)in.ops[1].size, 4);
    CHECK(in.flow == Flow::Normal);
    CHECK_EQ((int)in.length, 3);
}

TEST(disasm_x64_control_flow) {
    Instruction j = dec(true, {0x74, 0x10}, 0x2000); // je +0x10
    CHECK(j.mnem == Mnem::Je);
    CHECK(j.flow == Flow::CondJump);
    CHECK_EQ(j.target, 0x2012ull);
    CHECK(j.condition() == Cond::E);
    Instruction c = dec(true, {0xE8, 0x00, 0x01, 0x00, 0x00}, 0x2000);
    CHECK(c.flow == Flow::Call);
    CHECK_EQ(c.target, 0x2105ull);
    Instruction r = dec(true, {0xC3});
    CHECK(r.flow == Flow::Return);
    Instruction ij = dec(true, {0xFF, 0xE0}); // jmp rax
    CHECK(ij.flow == Flow::IndirectJump);
    Instruction ip = dec(true, {0xFF, 0x25, 0x10, 0x00, 0x00, 0x00}, 0x3000); // jmp [rip+0x10]
    CHECK(ip.flow == Flow::IndirectJump);
    CHECK_EQ(*ip.ripTarget(0), 0x3016ull);
}

TEST(disasm_register_aliasing) {
    CHECK(regFamily(Reg::AL) == regFamily(Reg::RAX));
    CHECK(regFamily(Reg::AH) == Family::F_RAX);
    CHECK_EQ((int)regInfo(Reg::AH).offset, 1);
    CHECK_EQ(regSize(Reg::EAX), 4u);
    CHECK_EQ(regSize(Reg::R9W), 2u);
    CHECK(gprOfSize(Family::F_R9, 4) == Reg::R9D);
    CHECK(fullReg(Family::F_RSP, false) == Reg::ESP);
}

TEST(disasm_x86_mode) {
    Instruction in = dec(false, {0x8B, 0x45, 0xF8}); // mov eax, [ebp-8]
    CHECK(in.ops[1].mem.base == Reg::EBP);
    CHECK_EQ(in.ops[1].mem.disp, (i64)-8);
    Instruction p = dec(false, {0x55}); // push ebp
    CHECK(p.mnem == Mnem::Push);
    CHECK(p.ops[0].isReg(Reg::EBP));
}

TEST(disasm_movsd_disambiguation) {
    Instruction sse = dec(true, {0xF2, 0x0F, 0x10, 0x01}); // movsd xmm0, [rcx]
    CHECK(sse.mnem == Mnem::Movsd);
    Instruction str = dec(true, {0xA5}); // movsd (string)
    CHECK(str.mnem == Mnem::MovsdStr);
    Instruction rep = dec(true, {0xF3, 0xAA}); // rep stosb
    CHECK(rep.mnem == Mnem::Stosb);
    CHECK(rep.prefixes & PrefixRep);
}

TEST(disasm_invalid_bytes) {
    auto d = createX86Disassembler(true);
    Instruction in;
    std::vector<u8> bad = {0x0F, 0xFF};
    d->decode(bad, 0, in); // must not crash, result irrelevant
    std::vector<u8> empty;
    CHECK(!d->decode(empty, 0, in));
}
