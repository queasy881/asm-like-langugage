// Lifting-time model of the machine: the register cache, the symbolic stack
// pointer and the lazy flag model.
//
// Three mechanisms keep the produced IR free of noise:
//
//  1. Narrow-value shadowing. A write of `eax` records the 32-bit value, so a
//     later 32-bit read returns it directly. A cast appears only when the
//     program really does mix widths.
//
//  2. Width election. Before lifting, every access to a register family is
//     scanned. If a family is only ever touched at one width, its SSA
//     variable has that width and no cast is ever needed for it.
//
//  3. Lazy flags. Flag-setting instructions record what they computed instead
//     of writing flag bits. A condition is materialised from that record at
//     the point of use, so `cmp`/`jl` becomes a single signed comparison.
//     Flag bits are written to real locations only where the flag liveness
//     analysis says they escape the block.
#pragma once

#include "analysis/program.h"
#include "arch/x86/x86.h"
#include "ir/ir.h"

#include <array>

namespace dc::lift {

using ir::ValueId;
using ir::kNoValue;

// --- flag effects ----------------------------------------------------------

using FlagMask = u8;
constexpr FlagMask flagBit(ir::FlagBit f) { return (FlagMask)(1u << f); }
constexpr FlagMask kFlagsArith = flagBit(ir::FlagCF) | flagBit(ir::FlagPF) | flagBit(ir::FlagAF) |
                                 flagBit(ir::FlagZF) | flagBit(ir::FlagSF) | flagBit(ir::FlagOF);
constexpr FlagMask kFlagsLogic = kFlagsArith;
constexpr FlagMask kFlagsNoCF = flagBit(ir::FlagPF) | flagBit(ir::FlagAF) | flagBit(ir::FlagZF) |
                                flagBit(ir::FlagSF) | flagBit(ir::FlagOF);

// Flags read and written by an instruction.
void flagEffects(const x86::Instruction& in, FlagMask& reads, FlagMask& writes);
// Flag bits a condition depends on.
FlagMask condFlags(x86::Cond c);

// Per-block flag liveness over the machine CFG.
struct FlagLiveness {
    std::vector<FlagMask> liveIn, liveOut;
    static FlagLiveness compute(const Function& f);
};

// --- lazy flag record ------------------------------------------------------

enum class FlagOp : u8 {
    None,       // unknown: flags come from locations
    Sub,        // result = lhs - rhs   (cmp, sub, dec via SubConst)
    Add,        // result = lhs + rhs
    Logic,      // result = lhs & rhs / | / ^  (CF = OF = 0)
    Inc,        // result = lhs + 1, CF preserved
    Dec,        // result = lhs - 1, CF preserved
    Neg,        // result = -lhs, CF = (lhs != 0)
    Shift,      // result of a shift; CF/OF modelled explicitly
    BitTest,    // CF = tested bit
    Mul,        // CF = OF = (high half significant)
    Explicit,   // every bit was computed into `bits`
};

struct FlagState {
    FlagOp op = FlagOp::None;
    ValueId lhs = kNoValue;
    ValueId rhs = kNoValue;
    ValueId result = kNoValue;
    ir::Type type;                                   // width of the operation
    std::array<ValueId, ir::FlagCount> bits{};       // Explicit / partially known bits
    FlagMask known = 0;                              // which entries of `bits` are valid
    FlagMask undefined = 0;                          // architecturally undefined bits
    u64 addr = 0;

    void clear() {
        *this = FlagState{};
        bits.fill(kNoValue);
    }
    FlagState() { bits.fill(kNoValue); }
};

// --- register cache --------------------------------------------------------

struct FamilyState {
    // Contents = base, with `narrow` deposited at `narrowOffset` when narrowSize != 0.
    ValueId base = kNoValue;   // full-width value; kNoValue means "not read yet"
    bool baseZero = false;     // the bits outside `narrow` are known zero
    ValueId narrow = kNoValue;
    u8 narrowSize = 0;
    u8 narrowOffset = 0;
    bool dirty = false;        // written in this block
    // Symbolic stack tracking: value == entrySP + spDelta.
    bool spRelative = false;
    i64 spDelta = 0;
    // 128-bit registers are held as two 64-bit lanes. The low lane is `base`
    // and friends above; this is the upper one. Keeping them apart means every
    // value the IR carries fits in 64 bits, which is what the rest of the
    // pipeline (and the interpreter) can reason about.
    ValueId high = kNoValue;
    bool highDirty = false;
};

class Lifter;

// Register file for one basic block being lifted.
class RegFile {
public:
    RegFile(Lifter& lifter, unsigned fullBytes) : lifter_(lifter), fullBytes_(fullBytes) {}

    void reset();
    // Reads `reg` producing a value of exactly its width.
    ValueId read(x86::Reg reg);
    ValueId readFamily(x86::Family fam, unsigned bytes, unsigned offset = 0);
    void write(x86::Reg reg, ValueId value);
    void writeFamily(x86::Family fam, unsigned bytes, unsigned offset, ValueId value);
    // The upper 64 bits of a 128-bit register.
    ValueId readXmmHigh(x86::Family fam);
    void writeXmmHigh(x86::Family fam, ValueId value);
    // Marks the family as holding entrySP + delta.
    void setStackRelative(x86::Family fam, i64 delta);
    bool stackRelative(x86::Family fam, i64& delta) const;
    void clearStackRelative(x86::Family fam);
    // Emits WriteLoc for every family written in this block.
    void flush();
    FamilyState& state(x86::Family f) { return states_[(size_t)f]; }

private:
    ValueId materializeFull(x86::Family fam);
    unsigned familyBytes(x86::Family fam) const;

    Lifter& lifter_;
    unsigned fullBytes_;
    std::array<FamilyState, (size_t)x86::Family::Count> states_;
};

} // namespace dc::lift
