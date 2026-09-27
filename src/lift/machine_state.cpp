#include "lift/machine_state.h"

#include "lift/lifter_impl.h"

namespace dc::lift {

using namespace x86;

void flagEffects(const Instruction& in, FlagMask& reads, FlagMask& writes) {
    reads = 0;
    writes = 0;
    const FlagMask CF = flagBit(ir::FlagCF), ZF = flagBit(ir::FlagZF), SF = flagBit(ir::FlagSF);
    const FlagMask OF = flagBit(ir::FlagOF), PF = flagBit(ir::FlagPF), AF = flagBit(ir::FlagAF);
    const FlagMask DF = flagBit(ir::FlagDF);
    switch (in.mnem) {
    case Mnem::Add: case Mnem::Sub: case Mnem::Cmp: case Mnem::Neg: case Mnem::Xadd:
        writes = kFlagsArith;
        break;
    case Mnem::Adc: case Mnem::Sbb:
        reads = CF;
        writes = kFlagsArith;
        break;
    case Mnem::Cmpxchg:
        writes = kFlagsArith;
        break;
    case Mnem::And: case Mnem::Or: case Mnem::Xor: case Mnem::Test: case Mnem::Andn:
        writes = kFlagsLogic;
        break;
    case Mnem::Inc: case Mnem::Dec:
        writes = kFlagsNoCF;
        break;
    case Mnem::Shl: case Mnem::Shr: case Mnem::Sar: case Mnem::Shld: case Mnem::Shrd:
        writes = kFlagsArith;
        break;
    case Mnem::Rol: case Mnem::Ror:
        writes = CF | OF;
        break;
    case Mnem::Rcl: case Mnem::Rcr:
        reads = CF;
        writes = CF | OF;
        break;
    case Mnem::Imul: case Mnem::Mul:
        writes = kFlagsArith;
        break;
    case Mnem::Idiv: case Mnem::Div:
        writes = kFlagsArith; // architecturally undefined
        break;
    case Mnem::Bt: case Mnem::Bts: case Mnem::Btr: case Mnem::Btc:
        writes = CF | OF | SF | AF | PF;
        break;
    case Mnem::Bsf: case Mnem::Bsr: case Mnem::Tzcnt: case Mnem::Lzcnt: case Mnem::Popcnt:
        writes = kFlagsArith;
        break;
    case Mnem::Clc: writes = CF; break;
    case Mnem::Stc: writes = CF; break;
    case Mnem::Cmc: reads = CF; writes = CF; break;
    case Mnem::Cld: writes = DF; break;
    case Mnem::Std: writes = DF; break;
    case Mnem::Sahf: writes = CF | PF | AF | ZF | SF; break;
    case Mnem::Lahf: reads = CF | PF | AF | ZF | SF; break;
    case Mnem::Popfd: case Mnem::Popfq: writes = kFlagsArith | DF; break;
    case Mnem::Pushfd: case Mnem::Pushfq: reads = kFlagsArith | DF; break;
    case Mnem::Comiss: case Mnem::Comisd: case Mnem::Ucomiss: case Mnem::Ucomisd:
    case Mnem::Vcomiss: case Mnem::Vcomisd: case Mnem::Vucomiss: case Mnem::Vucomisd:
        writes = ZF | PF | CF | OF | SF | AF;
        break;
    case Mnem::Fcomi: case Mnem::Fcomip: case Mnem::Fucomi: case Mnem::Fucomip:
        writes = ZF | PF | CF;
        break;
    case Mnem::Movsb: case Mnem::Movsw: case Mnem::MovsdStr: case Mnem::Movsq:
    case Mnem::Stosb: case Mnem::Stosw: case Mnem::Stosd: case Mnem::Stosq:
    case Mnem::Lodsb: case Mnem::Lodsw: case Mnem::Lodsd: case Mnem::Lodsq:
        reads = DF;
        break;
    case Mnem::Scasb: case Mnem::Scasw: case Mnem::Scasd: case Mnem::Scasq:
    case Mnem::Cmpsb: case Mnem::Cmpsw: case Mnem::CmpsdStr: case Mnem::Cmpsq:
        reads = DF;
        writes = kFlagsArith;
        break;
    default:
        break;
    }
    if (in.mnem >= Mnem::Jo && in.mnem <= Mnem::Jg) reads = condFlags(in.condition());
    if (in.mnem >= Mnem::Seto && in.mnem <= Mnem::Setg) reads = condFlags(in.condition());
    if (in.mnem >= Mnem::Cmovo && in.mnem <= Mnem::Cmovg) reads = condFlags(in.condition());
    // A call may observe flags only through undefined behaviour; treat calls
    // as clobbering nothing but also as not reading. Returns end flag lifetimes.
}

FlagMask condFlags(Cond c) {
    const FlagMask CF = flagBit(ir::FlagCF), ZF = flagBit(ir::FlagZF), SF = flagBit(ir::FlagSF);
    const FlagMask OF = flagBit(ir::FlagOF), PF = flagBit(ir::FlagPF);
    switch (c) {
    case Cond::O: case Cond::NO: return OF;
    case Cond::B: case Cond::AE: return CF;
    case Cond::E: case Cond::NE: return ZF;
    case Cond::BE: case Cond::A: return CF | ZF;
    case Cond::S: case Cond::NS: return SF;
    case Cond::P: case Cond::NP: return PF;
    case Cond::L: case Cond::GE: return SF | OF;
    case Cond::LE: case Cond::G: return ZF | SF | OF;
    default: return 0;
    }
}

FlagLiveness FlagLiveness::compute(const Function& f) {
    FlagLiveness fl;
    size_t n = f.blocks.size();
    fl.liveIn.assign(n, 0);
    fl.liveOut.assign(n, 0);
    // Per-block gen/kill.
    std::vector<FlagMask> gen(n, 0), kill(n, 0);
    for (size_t i = 0; i < n; ++i) {
        FlagMask g = 0, k = 0;
        for (const auto& in : f.blocks[i].insns) {
            FlagMask r, w;
            flagEffects(in, r, w);
            g |= (FlagMask)(r & ~k);
            k |= w;
            // A call clobbers flags in every Windows calling convention.
            if (in.isCall()) k = 0xFF;
        }
        gen[i] = g;
        kill[i] = k;
    }
    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t i = n; i-- > 0;) {
            FlagMask out = 0;
            for (const auto& e : f.blocks[i].succs)
                if (e.target >= 0) out |= fl.liveIn[e.target];
            FlagMask in = (FlagMask)(gen[i] | (out & ~kill[i]));
            if (out != fl.liveOut[i] || in != fl.liveIn[i]) {
                fl.liveOut[i] = out;
                fl.liveIn[i] = in;
                changed = true;
            }
        }
    }
    return fl;
}

// --- RegFile ---------------------------------------------------------------

unsigned RegFile::familyBytes(Family fam) const {
    // The elected width, so a register only ever used narrowly never needs a
    // cast to reach its architectural width.
    unsigned w = lifter_.familyWidth(fam);
    return w ? w : (isXmmFamily(fam) ? 16 : fullBytes_);
}

void RegFile::reset() {
    for (auto& s : states_) s = FamilyState{};
}

ValueId RegFile::read(Reg reg) {
    const RegInfo& ri = regInfo(reg);
    return readFamily(ri.family, ri.size, ri.offset);
}

ValueId RegFile::readFamily(Family fam, unsigned bytes, unsigned offset) {
    FamilyState& st = state(fam);
    // A register tracked as holding a frame address is read as that address.
    // Its architectural value was never materialised, so reading the location
    // would hand back a stale one.
    if (st.spRelative && offset == 0 && bytes == lifter_.pointerBytes())
        return lifter_.emitFrameAddress(st.spDelta, bytes);
    if (st.narrowSize == bytes && st.narrowOffset == offset && st.narrow != kNoValue) return st.narrow;
    unsigned full = familyBytes(fam);
    ValueId v = materializeFull(fam);
    if (bytes == full && offset == 0) return v;
    if (offset) {
        v = lifter_.emitShiftRightConst(v, offset * 8);
    }
    return lifter_.emitTruncTo(v, bytes);
}

ValueId RegFile::materializeFull(Family fam) {
    FamilyState& st = state(fam);
    unsigned full = familyBytes(fam);
    if (st.narrowSize == 0) {
        if (st.base == kNoValue) st.base = lifter_.emitReadReg(fam, full);
        return st.base;
    }
    if (st.narrowSize == full && st.narrowOffset == 0) {
        st.base = st.narrow;
        st.narrowSize = 0;
        st.narrow = kNoValue;
        return st.base;
    }
    ValueId composed;
    if (st.baseZero && st.narrowOffset == 0) {
        composed = lifter_.emitZExtTo(st.narrow, full);
    } else {
        if (st.base == kNoValue) st.base = lifter_.emitReadReg(fam, full);
        composed = lifter_.emitDeposit(st.base, st.narrow, st.narrowOffset, st.narrowSize, full);
    }
    st.base = composed;
    st.baseZero = false;
    st.narrow = kNoValue;
    st.narrowSize = 0;
    st.narrowOffset = 0;
    return composed;
}

void RegFile::write(Reg reg, ValueId value) {
    const RegInfo& ri = regInfo(reg);
    writeFamily(ri.family, ri.size, ri.offset, value);
}

void RegFile::writeFamily(Family fam, unsigned bytes, unsigned offset, ValueId value) {
    FamilyState& st = state(fam);
    unsigned full = familyBytes(fam);
    st.dirty = true;
    st.spRelative = false;
    if (bytes >= full && offset == 0) {
        st.base = value;
        st.baseZero = false;
        st.narrow = kNoValue;
        st.narrowSize = 0;
        st.narrowOffset = 0;
        return;
    }
    // A 32-bit write in 64-bit mode clears the upper half.
    bool zeroUpper = lifter_.is64() && bytes == 4 && offset == 0 && isGprFamily(fam);
    if (st.narrowSize && !(st.narrowSize == bytes && st.narrowOffset == offset)) materializeFull(fam);
    if (zeroUpper) {
        st.base = kNoValue;
        st.baseZero = true;
    } else if (!st.baseZero || offset != 0 || bytes != st.narrowSize) {
        if (st.base == kNoValue && !st.baseZero) st.base = lifter_.emitReadReg(fam, full);
        st.baseZero = false;
    }
    st.narrow = value;
    st.narrowSize = (u8)bytes;
    st.narrowOffset = (u8)offset;
}

void RegFile::setStackRelative(Family fam, i64 delta) {
    FamilyState& st = state(fam);
    st.spRelative = true;
    st.spDelta = delta;
}

bool RegFile::stackRelative(Family fam, i64& delta) const {
    const FamilyState& st = states_[(size_t)fam];
    if (!st.spRelative) return false;
    delta = st.spDelta;
    return true;
}

void RegFile::clearStackRelative(Family fam) { state(fam).spRelative = false; }

void RegFile::flush() {
    for (size_t i = 0; i < states_.size(); ++i) {
        FamilyState& st = states_[i];
        if (!st.dirty) continue;
        Family fam = (Family)i;
        ValueId v = materializeFull(fam);
        lifter_.emitWriteReg(fam, familyBytes(fam), v);
    }
}

} // namespace dc::lift
