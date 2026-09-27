#include "test_framework.h"

#include "ir/ir.h"

using namespace dc;
using namespace dc::ir;

TEST(ir_build_and_verify) {
    Function f("test");
    int b0 = f.addBlock(0x1000);
    int b1 = f.addBlock(0x1010);
    int b2 = f.addBlock(0x1020);
    ValueId a = f.constInt(b0, kI32, 10);
    ValueId b = f.constInt(b0, kI32, 20);
    ValueId c = f.binary(b0, Op::CmpSlt, kI1, a, b);
    Inst br;
    br.op = Op::Branch;
    br.args = {c};
    f.add(b0, std::move(br));
    f.block(b0).succs = {b1, b2};

    ValueId x1 = f.constInt(b1, kI32, 1);
    Inst j;
    j.op = Op::Jump;
    f.add(b1, std::move(j));
    f.block(b1).succs = {b2};

    f.recomputePreds();
    Inst phi;
    phi.op = Op::Phi;
    phi.type = kI32;
    phi.args = {a, x1}; // preds of b2 are b0, b1 in that order
    ValueId p = f.add(b2, std::move(phi));
    Inst ret;
    ret.op = Op::Return;
    ret.args = {p};
    f.add(b2, std::move(ret));

    auto errs = f.verify();
    for (const auto& e : errs) std::printf("    %s\n", e.c_str());
    CHECK(errs.empty());
    CHECK_EQ(f.block(b2).preds.size(), (size_t)2);
}

TEST(ir_verify_catches_problems) {
    Function f("bad");
    int b0 = f.addBlock();
    ValueId a = f.constInt(b0, kI32, 1);
    ValueId b = f.constInt(b0, kI16, 1);
    f.binary(b0, Op::Add, kI32, a, b); // width mismatch
    Inst ret;
    ret.op = Op::Return;
    f.add(b0, std::move(ret));
    auto errs = f.verify();
    CHECK(!errs.empty());

    Function g("noterm");
    int g0 = g.addBlock();
    g.constInt(g0, kI32, 1);
    CHECK(!g.verify().empty());
}

TEST(ir_op_tables) {
    CHECK(isTerminator(Op::Return));
    CHECK(!isTerminator(Op::Add));
    CHECK(isCommutative(Op::Add));
    CHECK(!isCommutative(Op::Sub));
    CHECK(isComparison(Op::CmpSlt));
    CHECK(invertComparison(Op::CmpSlt) == Op::CmpSge);
    CHECK(swapComparisonOperands(Op::CmpSlt) == Op::CmpSgt);
    CHECK(invertComparison(invertComparison(Op::CmpUle)) == Op::CmpUle);
    CHECK(isFloatOp(Op::FAdd));
    CHECK(isCast(Op::ZExt));
    CHECK(hasSideEffects(Op::Store));
    CHECK(!hasSideEffects(Op::Load));
    // Every op must have a name.
    for (int i = 0; i < (int)Op::Count; ++i) CHECK(opName((Op)i)[0] != 0);
}

TEST(ir_replace_uses) {
    Function f("r");
    int b0 = f.addBlock();
    ValueId a = f.constInt(b0, kI32, 1);
    ValueId b = f.constInt(b0, kI32, 2);
    ValueId s = f.binary(b0, Op::Add, kI32, a, a);
    f.replaceAllUses(a, b);
    CHECK_EQ(f.inst(s).args[0], b);
    CHECK_EQ(f.inst(s).args[1], b);
    auto uses = f.buildUses();
    CHECK_EQ(uses[b].size(), (size_t)2);
}
