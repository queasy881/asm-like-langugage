// Internal declaration of the lifter, shared with the machine-state model.
#pragma once

#include "lift/lifter.h"
#include "lift/machine_state.h"

#include <map>

namespace dc::lift {

class Lifter {
public:
    Lifter(Program& prog, const Function& mf, const LiftOptions& opt);

    LiftResult run();

    // --- services used by RegFile ---
    bool is64() const { return is64_; }
    unsigned pointerBytes() const { return is64_ ? 8 : 4; }
    ir::Type ptrType() const { return ir::Type::ptr((u16)(pointerBytes() * 8)); }
    unsigned familyWidth(x86::Family f) const { return widths_[(size_t)f]; }

    ValueId emitReadReg(x86::Family fam, unsigned bytes);
    void emitWriteReg(x86::Family fam, unsigned bytes, ValueId v);
    ValueId emitTruncTo(ValueId v, unsigned bytes);
    ValueId emitZExtTo(ValueId v, unsigned bytes);
    ValueId emitSExtTo(ValueId v, unsigned bytes);
    ValueId emitDeposit(ValueId base, ValueId narrow, unsigned offset, unsigned size, unsigned fullBytes);
    ValueId emitShiftRightConst(ValueId v, unsigned bits);
    ValueId emitFrameAddress(i64 offset, unsigned bytes);
    ValueId toIntBits(ValueId v);

private:
    // --- emission helpers ---
    ValueId konst(ir::Type t, u64 v) { return fn_->constInt(cur_, t, v, addr_); }
    ValueId konstLike(ValueId like, u64 v) { return konst(typeOf(like), v); }
    ValueId bin(ir::Op op, ValueId a, ValueId b) { return fn_->binary(cur_, op, typeOf(a), a, b, addr_); }
    ValueId un(ir::Op op, ValueId a) { return fn_->unary(cur_, op, typeOf(a), a, addr_); }
    ValueId cmp(ir::Op op, ValueId a, ValueId b) { return fn_->binary(cur_, op, ir::kI1, a, b, addr_); }
    ValueId undef(ir::Type t) { return fn_->undef(cur_, t); }
    ir::Type typeOf(ValueId v) const { return fn_->inst(v).type; }
    unsigned bytesOf(ValueId v) const { return typeOf(v).bytes(); }
    ValueId intrinsic(const char* name, ir::Type t, std::vector<ValueId> args, bool sideEffects = false);
    ValueId select(ValueId cond, ValueId a, ValueId b);
    ValueId boolConst(bool b) { return konst(ir::kI1, b ? 1 : 0); }
    ValueId zeroExtendBool(ValueId cond, ir::Type t);

    // --- operands ---
    ValueId readOperand(const x86::Instruction& in, unsigned i);
    ValueId readOperandAs(const x86::Instruction& in, unsigned i, ir::Type t);
    void writeOperand(const x86::Instruction& in, unsigned i, ValueId v);
    ValueId memAddress(const x86::Instruction& in, const x86::Operand& op, bool& isFrame, i64& frameOff);
    ValueId effectiveAddress(const x86::Instruction& in, const x86::Operand& op);
    ir::Type intTypeForBytes(unsigned bytes) const { return ir::Type::i((u16)(bytes * 8)); }

    // --- stack ---
    void adjustStack(i64 delta);
    ValueId stackAddr(i64 offset);
    void pushValue(ValueId v);
    ValueId popValue(ir::Type t);
    bool stackDeltaKnown() const { return spKnown_; }

    // --- flags ---
    void setFlagsSub(ValueId lhs, ValueId rhs, ValueId result);
    void setFlagsAdd(ValueId lhs, ValueId rhs, ValueId result);
    void setFlagsLogic(ValueId lhs, ValueId rhs, ValueId result);
    void setFlagsIncDec(ValueId lhs, ValueId result, bool inc);
    void setFlagsNeg(ValueId lhs, ValueId result);
    void setFlagsShift(ValueId result, ValueId carry, ValueId overflow);
    void setFlagsUnknown(FlagMask mask);
    void setFlagBit(ir::FlagBit f, ValueId v);
    ValueId flagBitValue(ir::FlagBit f);
    ValueId materializeCond(x86::Cond c);
    void flushFlags(FlagMask liveOut);

    // --- instruction semantics ---
    void liftInstruction(const x86::Instruction& in);
    bool liftDataMovement(const x86::Instruction& in);
    bool liftArithmetic(const x86::Instruction& in);
    bool liftLogic(const x86::Instruction& in);
    bool liftShift(const x86::Instruction& in);
    bool liftStack(const x86::Instruction& in);
    bool liftCompareAndSet(const x86::Instruction& in);
    bool liftMulDiv(const x86::Instruction& in);
    bool liftBits(const x86::Instruction& in);
    bool liftSse(const x86::Instruction& in);
    bool liftX87(const x86::Instruction& in);
    ValueId readFloat(const x86::Instruction& in, unsigned i, ir::Type ft);
    void writeFloat(const x86::Instruction& in, unsigned i, ValueId v);
    bool liftStringOp(const x86::Instruction& in);
    bool liftMisc(const x86::Instruction& in);
    void liftCall(const x86::Instruction& in, const CallSite* cs);
    void computeStackDeltas();
    // Registers definitely written before each block, used to tell how many
    // arguments a call whose signature is unknown actually receives.
    void computeDefinedRegs();
    // Argument registers set up before `call`, as a count of the convention's
    // leading argument registers.
    unsigned guessArgumentCount(const x86::Instruction& call, const ConventionInfo& ci,
                                std::vector<bool>& isFloat, std::vector<unsigned>& widths) const;
    void unsupported(const x86::Instruction& in);
    void clobberCallRegisters();

    // --- block plumbing ---
    void liftBlock(int machineBlock);
    // Propagates the symbolic flag record into blocks whose predecessors all
    // leave the same one, so a cmp in one block still folds with a jcc or
    // cmov in the next.
    void computeFlagEntryStates();
    void emitTerminator(const BasicBlock& mb);

    Program& prog_;
    const Function& mf_;
    LiftOptions opt_;
    bool is64_;
    std::unique_ptr<ir::Function> fn_;
    std::array<u8, (size_t)x86::Family::Count> widths_{};
    std::unique_ptr<RegFile> regs_;
    FlagLiveness flagLive_;
    FlagState flags_;
    std::vector<int> blockMap_;
    std::vector<std::string> unsupported_;
    int cur_ = 0;             // current IR block
    int curMachine_ = 0;      // current machine block
    u64 addr_ = 0;            // address of the instruction being lifted
    bool spKnown_ = true;     // the stack delta is statically known
    i64 spDelta_ = 0;         // current SP relative to function entry
    ValueId switchIndex_ = kNoValue;
    int fpuTop_ = 0;
    std::vector<i64> blockEntrySp_;
    std::vector<char> blockSpKnown_;
    // Registers holding a frame address on entry to each block, and by how
    // much they differ from the stack pointer at function entry.
    std::vector<std::map<x86::Family, i64>> blockFrameRegs_;
    std::vector<u32> blockDefinedGpr_;
    // The function computes its result in xmm0 and never touches the integer
    // return register, so what it returns is a floating point value.
    bool floatReturn_ = false;
    void computeFloatReturn();
    std::vector<u32> blockDefinedXmm_;
    ValueId callResult_ = kNoValue;
    std::array<ValueId, ir::FlagCount> flagLoc_{}; // cached ReadLoc per flag
    // Machine block -> the instruction whose flags reach its entry, or null.
    std::vector<const x86::Instruction*> flagDefIn_;
    std::vector<const x86::Instruction*> flagDefOut_;
};

} // namespace dc::lift
