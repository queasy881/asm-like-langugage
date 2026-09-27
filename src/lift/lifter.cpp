#include "lift/lifter_impl.h"

#include <algorithm>
#include <cstring>
#include <set>

namespace dc::lift {

using namespace x86;
using ir::Op;
using ir::Type;

namespace {

// Registers clobbered by a call under every Windows convention we support.
bool isVolatileFamily(Family f, bool is64) {
    if (isXmmFamily(f)) return !is64 || xmmIndex(f) <= 5;
    switch (f) {
    case Family::F_RAX: case Family::F_RCX: case Family::F_RDX:
        return true;
    case Family::F_R8: case Family::F_R9: case Family::F_R10: case Family::F_R11:
        return is64;
    default:
        return false;
    }
}

// Width an SSE instruction actually touches in an XMM register. The register
// name does not encode it, so it comes from the mnemonic. 0 means "the whole
// register".
unsigned sseAccessBytes(Mnem m) {
    switch (m) {
    case Mnem::Movss: case Mnem::Vmovss: case Mnem::Addss: case Mnem::Vaddss:
    case Mnem::Subss: case Mnem::Vsubss: case Mnem::Mulss: case Mnem::Vmulss:
    case Mnem::Divss: case Mnem::Vdivss: case Mnem::Minss: case Mnem::Maxss:
    case Mnem::Sqrtss: case Mnem::Comiss: case Mnem::Ucomiss: case Mnem::Vcomiss:
    case Mnem::Vucomiss: case Mnem::Cvtsi2ss: case Mnem::Vcvtsi2ss:
    case Mnem::Cvttss2si: case Mnem::Cvtss2si: case Mnem::Vcvttss2si:
    case Mnem::Movd: case Mnem::Vmovd: case Mnem::Roundss:
    case Mnem::Pinsrd: case Mnem::Pextrd:
        return 4;
    case Mnem::Movsd: case Mnem::Vmovsd: case Mnem::Addsd: case Mnem::Vaddsd:
    case Mnem::Subsd: case Mnem::Vsubsd: case Mnem::Mulsd: case Mnem::Vmulsd:
    case Mnem::Divsd: case Mnem::Vdivsd: case Mnem::Minsd: case Mnem::Maxsd:
    case Mnem::Sqrtsd: case Mnem::Comisd: case Mnem::Ucomisd: case Mnem::Vcomisd:
    case Mnem::Vucomisd: case Mnem::Cvtsi2sd: case Mnem::Vcvtsi2sd:
    case Mnem::Cvttsd2si: case Mnem::Cvtsd2si: case Mnem::Vcvttsd2si:
    case Mnem::Movq: case Mnem::Vmovq: case Mnem::Roundsd:
    case Mnem::Movlps: case Mnem::Movhps: case Mnem::Movlpd: case Mnem::Movhpd:
    case Mnem::Pinsrq: case Mnem::Pextrq:
        return 8;
    // Mixed-width conversions touch both operands at their own width.
    case Mnem::Cvtss2sd: case Mnem::Vcvtss2sd: case Mnem::Cvtsd2ss: case Mnem::Vcvtsd2ss:
        return 8;
    default:
        return 0;
    }
}

unsigned roundUpAccess(unsigned bytes) {
    if (bytes <= 1) return 1;
    if (bytes <= 2) return 2;
    if (bytes <= 4) return 4;
    if (bytes <= 8) return 8;
    return 16;
}

} // namespace

// ---------------------------------------------------------------------------
// Width election
// ---------------------------------------------------------------------------

std::array<u8, (size_t)Family::Count> electRegisterWidths(const Function& f, bool is64) {
    const unsigned fullGpr = is64 ? 8 : 4;
    std::array<u8, (size_t)Family::Count> widths{};
    // The widest access to each family; a narrower variable is never enough,
    // and a wider one would only add casts.
    std::array<u8, (size_t)Family::Count> maxAccess{};
    std::array<bool, (size_t)Family::Count> subByte{};
    auto note = [&](Family fam, unsigned bytes, unsigned offset) {
        if (fam == Family::None) return;
        if (offset) subByte[(size_t)fam] = true;
        unsigned w = roundUpAccess(bytes + offset);
        if (w > maxAccess[(size_t)fam]) maxAccess[(size_t)fam] = (u8)w;
    };
    for (const auto& b : f.blocks) {
        for (const auto& in : b.insns) {
            // Multi-byte padding nops carry a memory operand that names a
            // register the instruction never actually uses.
            if (in.mnem == Mnem::Nop) continue;
            for (unsigned i = 0; i < in.numOps; ++i) {
                const Operand& op = in.ops[i];
                if (op.isReg()) {
                    const RegInfo& ri = regInfo(op.reg);
                    unsigned sz = ri.size;
                    if (isXmmFamily(ri.family)) {
                        unsigned sse = sseAccessBytes(in.mnem);
                        sz = sse ? sse : 16;
                    }
                    note(ri.family, sz, ri.offset);
                } else if (op.isMem()) {
                    // A real address is computed at full width, but lea is
                    // arithmetic: "lea eax, [rcx+rdx]" only uses 32 bits.
                    unsigned w = in.mnem == Mnem::Lea && in.numOps >= 1 && in.ops[0].isReg()
                                     ? regSize(in.ops[0].reg)
                                     : fullGpr;
                    if (op.mem.base != Reg::None) note(regFamily(op.mem.base), w, 0);
                    if (op.mem.index != Reg::None) note(regFamily(op.mem.index), w, 0);
                }
            }
            // Implicit operands.
            switch (in.mnem) {
            case Mnem::Mul: case Mnem::Imul: case Mnem::Div: case Mnem::Idiv: {
                unsigned w = in.numOps >= 1 ? in.ops[0].size : fullGpr;
                if (in.mnem == Mnem::Imul && in.numOps != 1) break;
                note(Family::F_RAX, w, 0);
                if (w > 1) note(Family::F_RDX, w, 0);
                break;
            }
            case Mnem::Cdq: note(Family::F_RAX, 4, 0); note(Family::F_RDX, 4, 0); break;
            case Mnem::Cqo: note(Family::F_RAX, 8, 0); note(Family::F_RDX, 8, 0); break;
            case Mnem::Cwd: note(Family::F_RAX, 2, 0); note(Family::F_RDX, 2, 0); break;
            case Mnem::Cdqe: note(Family::F_RAX, 8, 0); note(Family::F_RAX, 4, 0); break;
            case Mnem::Cwde: note(Family::F_RAX, 4, 0); note(Family::F_RAX, 2, 0); break;
            case Mnem::Cbw: note(Family::F_RAX, 2, 0); note(Family::F_RAX, 1, 0); break;
            case Mnem::Push: case Mnem::Pop: case Mnem::Call: case Mnem::Ret: case Mnem::Leave:
                note(Family::F_RSP, fullGpr, 0);
                if (in.mnem == Mnem::Leave) note(Family::F_RBP, fullGpr, 0);
                break;
            case Mnem::Shl: case Mnem::Shr: case Mnem::Sar: case Mnem::Rol: case Mnem::Ror:
            case Mnem::Rcl: case Mnem::Rcr: case Mnem::Shld: case Mnem::Shrd:
                if (in.numOps >= 2 && in.ops[in.numOps - 1].isReg()) note(Family::F_RCX, 1, 0);
                break;
            case Mnem::Movsb: case Mnem::Movsw: case Mnem::MovsdStr: case Mnem::Movsq:
            case Mnem::Stosb: case Mnem::Stosw: case Mnem::Stosd: case Mnem::Stosq:
            case Mnem::Lodsb: case Mnem::Lodsw: case Mnem::Lodsd: case Mnem::Lodsq:
            case Mnem::Scasb: case Mnem::Scasw: case Mnem::Scasd: case Mnem::Scasq:
            case Mnem::Cmpsb: case Mnem::Cmpsw: case Mnem::CmpsdStr: case Mnem::Cmpsq:
                note(Family::F_RSI, fullGpr, 0);
                note(Family::F_RDI, fullGpr, 0);
                if (in.prefixes & (PrefixRep | PrefixRepne)) note(Family::F_RCX, fullGpr, 0);
                break;
            default:
                break;
            }
            // Calls read and write the convention registers at full width.
            if (in.isCall()) {
                for (size_t i = 0; i < (size_t)Family::Count; ++i)
                    if (isGprFamily((Family)i)) note((Family)i, fullGpr, 0);
            }
        }
    }
    for (size_t i = 0; i < (size_t)Family::Count; ++i) {
        Family fam = (Family)i;
        unsigned full = 8;
        // A 128-bit register is held as two 64-bit lanes, so its location is
        // never wider than a machine word.
        if (isXmmFamily(fam)) full = 8;
        else if (isGprFamily(fam) || fam == Family::F_RIP) full = fullGpr;
        else if (fam >= Family::F_ES && fam <= Family::F_GS) full = 2;
        else if (fam == Family::F_FPSW) full = 2;
        unsigned w = maxAccess[i];
        if (w == 0) w = full;
        if (subByte[i] && w < 2) w = 2;
        widths[i] = (u8)std::min<unsigned>(w, full);
    }
    return widths;
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

Lifter::Lifter(Program& prog, const Function& mf, const LiftOptions& opt)
    : prog_(prog), mf_(mf), opt_(opt), is64_(prog.is64()) {
    fn_ = std::make_unique<ir::Function>(mf.name);
    fn_->setEntryAddr(mf.entry);
    widths_ = electRegisterWidths(mf, is64_);
    regs_ = std::make_unique<RegFile>(*this, is64_ ? 8 : 4);
    flagLive_ = FlagLiveness::compute(mf);
    flagLoc_.fill(kNoValue);
}

// ---------------------------------------------------------------------------
// Emission helpers
// ---------------------------------------------------------------------------

ValueId Lifter::emitReadReg(Family fam, unsigned bytes) {
    ir::Loc l{ir::LocKind::Reg, (u16)fam, (u16)bytes};
    Type t = isXmmFamily(fam) ? Type::i((u16)(bytes * 8)) : intTypeForBytes(bytes);
    return fn_->readLoc(cur_, l, t, addr_);
}

void Lifter::emitWriteReg(Family fam, unsigned bytes, ValueId v) {
    ir::Loc l{ir::LocKind::Reg, (u16)fam, (u16)bytes};
    fn_->writeLoc(cur_, l, v, addr_);
}

ValueId Lifter::emitReadRegHigh(Family fam) {
    ir::Loc l{ir::LocKind::RegHigh, (u16)fam, 8};
    return fn_->readLoc(cur_, l, ir::kI64, addr_);
}

bool Lifter::readLanes(const Instruction& in, unsigned opIndex, ValueId& lo, ValueId& hi) {
    if (opIndex >= in.numOps) return false;
    const Operand& op = in.ops[opIndex];
    if (op.isReg()) {
        Family fam = regFamily(op.reg);
        if (!isXmmFamily(fam)) return false;
        lo = emitTruncTo(regs_->readFamily(fam, 8), 8);
        hi = regs_->readXmmHigh(fam);
        return true;
    }
    if (op.isMem()) {
        ValueId base = effectiveAddress(in, op);
        lo = fn_->load(cur_, ir::kI64, base, addr_);
        hi = fn_->load(cur_, ir::kI64, bin(Op::Add, base, konstLike(base, 8)), addr_);
        return true;
    }
    return false;
}

void Lifter::writeLanes(const Instruction& in, unsigned opIndex, ValueId lo, ValueId hi) {
    const Operand& op = in.ops[opIndex];
    if (op.isReg()) {
        Family fam = regFamily(op.reg);
        regs_->writeFamily(fam, 8, 0, emitTruncTo(lo, 8));
        regs_->writeXmmHigh(fam, hi);
        return;
    }
    ValueId base = effectiveAddress(in, op);
    fn_->store(cur_, base, emitTruncTo(lo, 8), addr_);
    fn_->store(cur_, bin(Op::Add, base, konstLike(base, 8)), emitTruncTo(hi, 8), addr_);
}

// Packed SSE, modelled exactly over the two 64-bit lanes. Anything that needs
// a value wider than a machine word, or a lane layout this cannot express, is
// left to the honest "unsupported instruction" path.
bool Lifter::liftPacked(const Instruction& in) {
    auto k64 = [&](u64 v) { return konst(ir::kI64, v); };
    // dst is operand 0; the VEX forms put the two sources after it.
    unsigned sa = in.numOps == 3 ? 1 : 0;
    unsigned sb = in.numOps == 3 ? 2 : 1;
    ValueId al = kNoValue, ah = kNoValue, bl = kNoValue, bh = kNoValue;

    auto binaryLanes = [&](Op op) -> bool {
        if (!readLanes(in, sa, al, ah) || !readLanes(in, sb, bl, bh)) return false;
        writeLanes(in, 0, bin(op, al, bl), bin(op, ah, bh));
        return true;
    };
    // Adds or subtracts within each 32-bit half of a lane, without letting a
    // carry cross the boundary.
    auto dwordLanes = [&](bool sub) -> bool {
        if (!readLanes(in, sa, al, ah) || !readLanes(in, sb, bl, bh)) return false;
        auto halves = [&](ValueId x, ValueId y) {
            ValueId mask = k64(0xFFFFFFFFull);
            ValueId lowPart = bin(Op::And, bin(sub ? Op::Sub : Op::Add,
                                               bin(Op::And, x, mask), bin(Op::And, y, mask)), mask);
            ValueId highPart = bin(Op::Shl,
                                   bin(Op::And, bin(sub ? Op::Sub : Op::Add,
                                                    bin(Op::LShr, x, k64(32)), bin(Op::LShr, y, k64(32))),
                                       mask),
                                   k64(32));
            return bin(Op::Or, lowPart, highPart);
        };
        writeLanes(in, 0, halves(al, bl), halves(ah, bh));
        return true;
    };

    switch (in.mnem) {
    case Mnem::Pxor: case Mnem::Xorps: case Mnem::Xorpd:
    case Mnem::Vpxor: case Mnem::Vxorps: case Mnem::Vxorpd:
        return binaryLanes(Op::Xor);
    case Mnem::Pand: case Mnem::Andps: case Mnem::Andpd:
        return binaryLanes(Op::And);
    case Mnem::Por: case Mnem::Orps: case Mnem::Orpd:
        return binaryLanes(Op::Or);
    case Mnem::Paddq:
        return binaryLanes(Op::Add);
    case Mnem::Psubq:
        return binaryLanes(Op::Sub);
    case Mnem::Paddd:
        return dwordLanes(false);
    case Mnem::Psubd:
        return dwordLanes(true);
    case Mnem::Pandn: case Mnem::Andnps: case Mnem::Andnpd: {
        if (!readLanes(in, sa, al, ah) || !readLanes(in, sb, bl, bh)) return false;
        writeLanes(in, 0, bin(Op::And, fn_->unary(cur_, Op::Not, ir::kI64, al, addr_), bl),
                   bin(Op::And, fn_->unary(cur_, Op::Not, ir::kI64, ah, addr_), bh));
        return true;
    }
    case Mnem::Pmuludq: {
        if (!readLanes(in, sa, al, ah) || !readLanes(in, sb, bl, bh)) return false;
        ValueId mask = k64(0xFFFFFFFFull);
        writeLanes(in, 0, bin(Op::Mul, bin(Op::And, al, mask), bin(Op::And, bl, mask)),
                   bin(Op::Mul, bin(Op::And, ah, mask), bin(Op::And, bh, mask)));
        return true;
    }
    case Mnem::Psrlq: case Mnem::Psllq: {
        if (in.numOps < 2 || !in.ops[in.numOps - 1].isImm()) return false;
        if (!readLanes(in, sa, al, ah)) return false;
        u64 n = (u64)in.ops[in.numOps - 1].imm;
        if (n >= 64) { writeLanes(in, 0, k64(0), k64(0)); return true; }
        Op op = in.mnem == Mnem::Psrlq ? Op::LShr : Op::Shl;
        writeLanes(in, 0, bin(op, al, k64(n)), bin(op, ah, k64(n)));
        return true;
    }
    case Mnem::Psrldq: case Mnem::Pslldq: {
        // A byte shift of the whole 128-bit value.
        if (in.numOps < 2 || !in.ops[in.numOps - 1].isImm()) return false;
        if (!readLanes(in, 0, al, ah)) return false;
        u64 n = (u64)in.ops[in.numOps - 1].imm;
        if (n >= 16) { writeLanes(in, 0, k64(0), k64(0)); return true; }
        unsigned bits = (unsigned)(n * 8);
        ValueId lo, hi;
        if (in.mnem == Mnem::Psrldq) {
            if (bits == 0) { lo = al; hi = ah; }
            else if (bits < 64)
                lo = bin(Op::Or, bin(Op::LShr, al, k64(bits)), bin(Op::Shl, ah, k64(64 - bits))),
                hi = bin(Op::LShr, ah, k64(bits));
            else if (bits == 64) { lo = ah; hi = k64(0); }
            else { lo = bin(Op::LShr, ah, k64(bits - 64)); hi = k64(0); }
        } else {
            if (bits == 0) { lo = al; hi = ah; }
            else if (bits < 64)
                hi = bin(Op::Or, bin(Op::Shl, ah, k64(bits)), bin(Op::LShr, al, k64(64 - bits))),
                lo = bin(Op::Shl, al, k64(bits));
            else if (bits == 64) { hi = al; lo = k64(0); }
            else { hi = bin(Op::Shl, al, k64(bits - 64)); lo = k64(0); }
        }
        writeLanes(in, 0, lo, hi);
        return true;
    }
    case Mnem::Punpckldq: case Mnem::Unpcklps: {
        // Interleaves the low four dwords of the two operands.
        if (!readLanes(in, sa, al, ah) || !readLanes(in, sb, bl, bh)) return false;
        ValueId mask = k64(0xFFFFFFFFull);
        ValueId outLo = bin(Op::Or, bin(Op::And, al, mask),
                            bin(Op::Shl, bin(Op::And, bl, mask), k64(32)));
        ValueId outHi = bin(Op::Or, bin(Op::LShr, al, k64(32)),
                            bin(Op::Shl, bin(Op::LShr, bl, k64(32)), k64(32)));
        writeLanes(in, 0, outLo, outHi);
        return true;
    }
    case Mnem::Pcmpeqd: case Mnem::Pcmpeqb: {
        if (!readLanes(in, sa, al, ah) || !readLanes(in, sb, bl, bh)) return false;
        unsigned esz = in.mnem == Mnem::Pcmpeqd ? 32 : 8;
        u64 unit = esz == 32 ? 0xFFFFFFFFull : 0xFFull;
        auto lane = [&](ValueId x, ValueId y) {
            ValueId acc = k64(0);
            for (unsigned sh = 0; sh < 64; sh += esz) {
                ValueId xe = bin(Op::And, bin(Op::LShr, x, k64(sh)), k64(unit));
                ValueId ye = bin(Op::And, bin(Op::LShr, y, k64(sh)), k64(unit));
                ValueId eq = zeroExtendBool(cmp(Op::CmpEq, xe, ye), ir::kI64);
                acc = bin(Op::Or, acc, bin(Op::Shl, bin(Op::Mul, eq, k64(unit)), k64(sh)));
            }
            return acc;
        };
        writeLanes(in, 0, lane(al, bl), lane(ah, bh));
        return true;
    }
    case Mnem::Movhlps: {
        if (!readLanes(in, 1, bl, bh) || !in.ops[0].isReg()) return false;
        regs_->writeFamily(regFamily(in.ops[0].reg), 8, 0, bh);
        return true;
    }
    case Mnem::Movlhps: {
        if (!readLanes(in, 1, bl, bh) || !in.ops[0].isReg()) return false;
        regs_->writeXmmHigh(regFamily(in.ops[0].reg), bl);
        return true;
    }
    case Mnem::Punpckhqdq: case Mnem::Unpckhpd: {
        if (!readLanes(in, sa, al, ah) || !readLanes(in, sb, bl, bh)) return false;
        writeLanes(in, 0, ah, bh);
        return true;
    }
    case Mnem::Shufpd: {
        // Non-VEX is dst, src, imm: the destination is also the first source.
        if (in.numOps < 3 || !in.ops[in.numOps - 1].isImm()) return false;
        sa = in.numOps == 4 ? 1 : 0;
        sb = in.numOps == 4 ? 2 : 1;
        if (!readLanes(in, sa, al, ah) || !readLanes(in, sb, bl, bh)) return false;
        u64 sel = (u64)in.ops[in.numOps - 1].imm;
        writeLanes(in, 0, (sel & 1) ? ah : al, (sel & 2) ? bh : bl);
        return true;
    }
    case Mnem::Pshufd: {
        if (in.numOps != 3 || !in.ops[2].isImm() || !in.ops[0].isReg()) return false;
        if (!readLanes(in, 1, bl, bh)) return false;
        u64 sel = (u64)in.ops[2].imm;
        auto dword = [&](unsigned i) {
            ValueId src = (i & 2) ? bh : bl;
            ValueId v = (i & 1) ? bin(Op::LShr, src, k64(32)) : src;
            return bin(Op::And, v, k64(0xFFFFFFFFull));
        };
        auto lane = [&](unsigned d0, unsigned d1) {
            return bin(Op::Or, dword(d0), bin(Op::Shl, dword(d1), k64(32)));
        };
        writeLanes(in, 0, lane((unsigned)(sel & 3), (unsigned)((sel >> 2) & 3)),
                   lane((unsigned)((sel >> 4) & 3), (unsigned)((sel >> 6) & 3)));
        return true;
    }
    case Mnem::Shufps: {
        // The low lane comes from the destination, the high lane from the
        // source; each selector picks one of that operand's four dwords.
        if (in.numOps < 3 || !in.ops[in.numOps - 1].isImm()) return false;
        sa = in.numOps == 4 ? 1 : 0;
        sb = in.numOps == 4 ? 2 : 1;
        if (!readLanes(in, sa, al, ah) || !readLanes(in, sb, bl, bh)) return false;
        u64 sel = (u64)in.ops[in.numOps - 1].imm;
        auto dword = [&](ValueId lo2, ValueId hi2, unsigned i) {
            ValueId src = (i & 2) ? hi2 : lo2;
            ValueId v = (i & 1) ? bin(Op::LShr, src, k64(32)) : src;
            return bin(Op::And, v, k64(0xFFFFFFFFull));
        };
        ValueId outLo = bin(Op::Or, dword(al, ah, (unsigned)(sel & 3)),
                            bin(Op::Shl, dword(al, ah, (unsigned)((sel >> 2) & 3)), k64(32)));
        ValueId outHi = bin(Op::Or, dword(bl, bh, (unsigned)((sel >> 4) & 3)),
                            bin(Op::Shl, dword(bl, bh, (unsigned)((sel >> 6) & 3)), k64(32)));
        writeLanes(in, 0, outLo, outHi);
        return true;
    }
    default:
        return false;
    }
}

void Lifter::emitWriteRegHigh(Family fam, ValueId v) {
    ir::Loc l{ir::LocKind::RegHigh, (u16)fam, 8};
    fn_->writeLoc(cur_, l, emitTruncTo(v, 8), addr_);
}

// Reinterprets a float value as the integer of the same width. Integer values
// pass through untouched, so no cast appears unless one is really needed.
ValueId Lifter::toIntBits(ValueId v) {
    Type t = typeOf(v);
    if (!t.isFloat()) return v;
    const ir::Inst& in = fn_->inst(v);
    if (in.op == Op::Bitcast && typeOf(in.args[0]).isInt() && typeOf(in.args[0]).bits == t.bits) return in.args[0];
    return fn_->cast(cur_, Op::Bitcast, Type::i(t.bits), v, addr_);
}

ValueId Lifter::emitTruncTo(ValueId v, unsigned bytes) {
    v = toIntBits(v);
    Type t = typeOf(v);
    unsigned want = bytes * 8;
    if (t.bits == want) return v;
    if (t.bits < want) return emitZExtTo(v, bytes);
    // trunc(zext/sext x) with x already the target width is just x.
    const ir::Inst& in = fn_->inst(v);
    if ((in.op == Op::ZExt || in.op == Op::SExt) && typeOf(in.args[0]).bits == want) return in.args[0];
    if (in.op == Op::Const) return konst(Type::i((u16)want), in.imm);
    return fn_->cast(cur_, Op::Trunc, Type::i((u16)want), v, addr_);
}

ValueId Lifter::emitZExtTo(ValueId v, unsigned bytes) {
    v = toIntBits(v);
    Type t = typeOf(v);
    unsigned want = bytes * 8;
    if (t.bits == want) return v;
    if (t.bits > want) return emitTruncTo(v, bytes);
    const ir::Inst& in = fn_->inst(v);
    if (in.op == Op::Const) return konst(Type::i((u16)want), truncBits(in.imm, t.bits));
    if (in.op == Op::ZExt) return fn_->cast(cur_, Op::ZExt, Type::i((u16)want), in.args[0], addr_);
    return fn_->cast(cur_, Op::ZExt, Type::i((u16)want), v, addr_);
}

ValueId Lifter::emitSExtTo(ValueId v, unsigned bytes) {
    v = toIntBits(v);
    Type t = typeOf(v);
    unsigned want = bytes * 8;
    if (t.bits == want) return v;
    if (t.bits > want) return emitTruncTo(v, bytes);
    const ir::Inst& in = fn_->inst(v);
    if (in.op == Op::Const) return konst(Type::i((u16)want), (u64)signExtend(in.imm, t.bits));
    if (in.op == Op::SExt) return fn_->cast(cur_, Op::SExt, Type::i((u16)want), in.args[0], addr_);
    return fn_->cast(cur_, Op::SExt, Type::i((u16)want), v, addr_);
}

ValueId Lifter::emitFrameAddress(i64 offset, unsigned bytes) {
    ir::Inst fa;
    fa.op = Op::FrameAddr;
    fa.type = Type::ptr((u16)(bytes * 8));
    fa.imm = (u64)offset;
    fa.addr = addr_;
    return fn_->add(cur_, std::move(fa));
}

ValueId Lifter::emitShiftRightConst(ValueId v, unsigned bits) {
    v = toIntBits(v);
    if (bits == 0) return v;
    return bin(Op::LShr, v, konstLike(v, bits));
}

ValueId Lifter::emitDeposit(ValueId base, ValueId narrow, unsigned offset, unsigned size, unsigned fullBytes) {
    base = toIntBits(base);
    narrow = toIntBits(narrow);
    Type ft = Type::i((u16)(fullBytes * 8));
    u64 mask = maskBits(size * 8) << (offset * 8);
    ValueId wide = emitZExtTo(narrow, fullBytes);
    if (offset) wide = bin(Op::Shl, wide, konst(ft, offset * 8));
    ValueId cleared = bin(Op::And, base, konst(ft, ~mask & maskBits(fullBytes * 8)));
    return bin(Op::Or, cleared, wide);
}

ValueId Lifter::intrinsic(const char* name, Type t, std::vector<ValueId> args, bool sideEffects) {
    ir::Inst in;
    in.op = Op::Intrinsic;
    in.type = t;
    in.args = std::move(args);
    in.text = name;
    in.addr = addr_;
    in.aux = sideEffects ? 1 : 0;
    return fn_->add(cur_, std::move(in));
}

ValueId Lifter::select(ValueId cond, ValueId a, ValueId b) {
    ir::Inst in;
    in.op = Op::Select;
    in.type = typeOf(a);
    in.args = {cond, a, b};
    in.addr = addr_;
    return fn_->add(cur_, std::move(in));
}

ValueId Lifter::zeroExtendBool(ValueId cond, Type t) {
    if (t.bits == 1) return cond;
    return fn_->cast(cur_, Op::ZExt, t, cond, addr_);
}

// ---------------------------------------------------------------------------
// Operands
// ---------------------------------------------------------------------------

ValueId Lifter::memAddress(const Instruction& in, const Operand& op, bool& isFrame, i64& frameOff) {
    const MemOperand& m = op.mem;
    isFrame = false;
    frameOff = 0;
    unsigned ps = pointerBytes();
    Type pt = Type::i((u16)(ps * 8));

    if (m.segment == Reg::FS || m.segment == Reg::GS) {
        ValueId base = intrinsic(m.segment == Reg::FS ? "read_fs_base" : "read_gs_base", pt, {});
        ValueId off = konst(pt, (u64)m.disp);
        ValueId a = bin(Op::Add, base, off);
        if (m.base != Reg::None) a = bin(Op::Add, a, emitZExtTo(regs_->read(m.base), ps));
        if (m.index != Reg::None) {
            ValueId idx = emitZExtTo(regs_->read(m.index), ps);
            if (m.scale > 1) idx = bin(Op::Mul, idx, konst(pt, m.scale));
            a = bin(Op::Add, a, idx);
        }
        return a;
    }
    // RIP-relative: an absolute address.
    if (m.base == Reg::RIP || m.base == Reg::EIP) {
        u64 target = in.next() + (u64)m.disp;
        ir::Inst g;
        g.op = Op::GlobalAddr;
        g.type = ptrType();
        g.imm = target;
        g.addr = addr_;
        return fn_->add(cur_, std::move(g));
    }
    // Absolute [disp].
    if (m.base == Reg::None && m.index == Reg::None) {
        u64 target = (u64)m.disp;
        if (!is64_) target &= 0xFFFFFFFFull;
        ir::Inst g;
        g.op = Op::GlobalAddr;
        g.type = ptrType();
        g.imm = target;
        g.addr = addr_;
        return fn_->add(cur_, std::move(g));
    }
    // Stack-relative with a known displacement becomes a frame reference.
    if (m.index == Reg::None && m.base != Reg::None) {
        i64 delta;
        if (regs_->stackRelative(regFamily(m.base), delta)) {
            isFrame = true;
            frameOff = delta + m.disp;
            ir::Inst fa;
            fa.op = Op::FrameAddr;
            fa.type = ptrType();
            fa.imm = (u64)frameOff;
            fa.addr = addr_;
            return fn_->add(cur_, std::move(fa));
        }
    }
    ValueId a = kNoValue;
    if (m.base != Reg::None) a = emitZExtTo(regs_->read(m.base), ps);
    if (m.index != Reg::None) {
        ValueId idx = emitZExtTo(regs_->read(m.index), ps);
        if (m.scale > 1) idx = bin(Op::Mul, idx, konst(pt, m.scale));
        a = a == kNoValue ? idx : bin(Op::Add, a, idx);
    }
    if (m.disp || a == kNoValue) {
        ValueId d = konst(pt, (u64)m.disp);
        a = a == kNoValue ? d : bin(Op::Add, a, d);
    }
    return a;
}

ValueId Lifter::effectiveAddress(const Instruction& in, const Operand& op) {
    bool isFrame;
    i64 off;
    return memAddress(in, op, isFrame, off);
}

ValueId Lifter::readOperand(const Instruction& in, unsigned i) {
    const Operand& op = in.ops[i];
    switch (op.kind) {
    case OpKind::Reg:
        return regs_->read(op.reg);
    case OpKind::Imm:
        return konst(intTypeForBytes(op.size ? op.size : pointerBytes()), (u64)op.imm);
    case OpKind::Mem: {
        ValueId a = effectiveAddress(in, op);
        unsigned bytes = op.size ? op.size : pointerBytes();
        return fn_->load(cur_, intTypeForBytes(bytes), a, addr_);
    }
    default:
        return undef(intTypeForBytes(pointerBytes()));
    }
}

ValueId Lifter::readOperandAs(const Instruction& in, unsigned i, Type t) {
    const Operand& op = in.ops[i];
    if (op.isMem()) {
        ValueId a = effectiveAddress(in, op);
        return fn_->load(cur_, t, a, addr_);
    }
    ValueId v = readOperand(in, i);
    if (typeOf(v).bits == t.bits) {
        if (typeOf(v) == t) return v;
        return fn_->cast(cur_, Op::Bitcast, t, v, addr_);
    }
    return t.isFloat() ? fn_->cast(cur_, Op::Bitcast, t, emitTruncTo(v, t.bytes()), addr_) : emitTruncTo(v, t.bytes());
}

void Lifter::writeOperand(const Instruction& in, unsigned i, ValueId v) {
    const Operand& op = in.ops[i];
    switch (op.kind) {
    case OpKind::Reg:
        regs_->write(op.reg, v);
        break;
    case OpKind::Mem: {
        ValueId a = effectiveAddress(in, op);
        fn_->store(cur_, a, v, addr_);
        break;
    }
    default:
        break;
    }
}

// ---------------------------------------------------------------------------
// Stack
// ---------------------------------------------------------------------------

void Lifter::adjustStack(i64 delta) {
    spDelta_ += delta;
    if (spKnown_) regs_->setStackRelative(Family::F_RSP, spDelta_);
}

ValueId Lifter::stackAddr(i64 offset) {
    ir::Inst fa;
    fa.op = Op::FrameAddr;
    fa.type = ptrType();
    fa.imm = (u64)offset;
    fa.addr = addr_;
    return fn_->add(cur_, std::move(fa));
}

void Lifter::pushValue(ValueId v) {
    unsigned ps = pointerBytes();
    adjustStack(-(i64)ps);
    ValueId a = spKnown_ ? stackAddr(spDelta_) : emitZExtTo(regs_->readFamily(Family::F_RSP, ps), ps);
    fn_->store(cur_, a, emitZExtTo(v, ps), addr_);
}

ValueId Lifter::popValue(Type t) {
    unsigned ps = pointerBytes();
    ValueId a = spKnown_ ? stackAddr(spDelta_) : emitZExtTo(regs_->readFamily(Family::F_RSP, ps), ps);
    ValueId v = fn_->load(cur_, t, a, addr_);
    adjustStack((i64)ps);
    return v;
}

// ---------------------------------------------------------------------------
// Flags
//
// Nothing is written to a flag location unless the flag escapes the block.
// Conditions are rebuilt from the recorded defining operation, which turns the
// usual cmp/jcc pair into one comparison rather than six flag computations.
// ---------------------------------------------------------------------------

void Lifter::setFlagsSub(ValueId lhs, ValueId rhs, ValueId result) {
    flags_.clear();
    flags_.op = FlagOp::Sub;
    flags_.lhs = lhs;
    flags_.rhs = rhs;
    flags_.result = result;
    flags_.type = typeOf(result);
    flags_.addr = addr_;
}

void Lifter::setFlagsAdd(ValueId lhs, ValueId rhs, ValueId result) {
    flags_.clear();
    flags_.op = FlagOp::Add;
    flags_.lhs = lhs;
    flags_.rhs = rhs;
    flags_.result = result;
    flags_.type = typeOf(result);
    flags_.addr = addr_;
}

void Lifter::setFlagsLogic(ValueId lhs, ValueId rhs, ValueId result) {
    flags_.clear();
    flags_.op = FlagOp::Logic;
    flags_.lhs = lhs;
    flags_.rhs = rhs;
    flags_.result = result;
    flags_.type = typeOf(result);
    flags_.addr = addr_;
}

void Lifter::setFlagsIncDec(ValueId lhs, ValueId result, bool inc) {
    // CF survives inc/dec, so keep whatever is currently known about it.
    ValueId cf = flagBitValue(ir::FlagCF);
    flags_.clear();
    flags_.op = inc ? FlagOp::Inc : FlagOp::Dec;
    flags_.lhs = lhs;
    flags_.result = result;
    flags_.type = typeOf(result);
    flags_.addr = addr_;
    flags_.bits[ir::FlagCF] = cf;
    flags_.known = flagBit(ir::FlagCF);
}

void Lifter::setFlagsNeg(ValueId lhs, ValueId result) {
    flags_.clear();
    flags_.op = FlagOp::Neg;
    flags_.lhs = lhs;
    flags_.result = result;
    flags_.type = typeOf(result);
    flags_.addr = addr_;
}

void Lifter::setFlagsShift(ValueId result, ValueId carry, ValueId overflow) {
    flags_.clear();
    flags_.op = FlagOp::Shift;
    flags_.result = result;
    flags_.type = typeOf(result);
    flags_.addr = addr_;
    flags_.bits[ir::FlagCF] = carry;
    flags_.bits[ir::FlagOF] = overflow;
    flags_.known = (FlagMask)((carry != kNoValue ? flagBit(ir::FlagCF) : 0) |
                              (overflow != kNoValue ? flagBit(ir::FlagOF) : 0));
}

void Lifter::setFlagsUnknown(FlagMask mask) {
    // Undefined bits are recorded, not materialised: an undef value is only
    // created if something actually reads the flag.
    if (mask == 0) return;
    if ((mask & kFlagsArith) == kFlagsArith) {
        flags_.clear();
        flags_.op = FlagOp::Explicit;
        flags_.undefined = mask;
        return;
    }
    flags_.undefined |= mask;
    flags_.known = (FlagMask)(flags_.known & ~mask);
}

void Lifter::setFlagBit(ir::FlagBit f, ValueId v) {
    flags_.bits[f] = v;
    flags_.known |= flagBit(f);
    flags_.undefined = (FlagMask)(flags_.undefined & ~flagBit(f));
}

// Computes one flag bit as an i1 value.
ValueId Lifter::flagBitValue(ir::FlagBit f) {
    if (flags_.undefined & flagBit(f)) return undef(ir::kI1);
    if (flags_.known & flagBit(f)) {
        ValueId v = flags_.bits[f];
        if (v != kNoValue) return v;
    }
    Type t = flags_.type;
    ValueId zero = flags_.result != kNoValue ? konstLike(flags_.result, 0) : kNoValue;
    auto signBitSet = [&](ValueId v) { return cmp(Op::CmpSlt, v, konstLike(v, 0)); };
    switch (flags_.op) {
    case FlagOp::Sub:
        switch (f) {
        case ir::FlagZF: return cmp(Op::CmpEq, flags_.lhs, flags_.rhs);
        case ir::FlagCF: return cmp(Op::CmpUlt, flags_.lhs, flags_.rhs);
        case ir::FlagSF: return signBitSet(flags_.result);
        case ir::FlagOF: {
            // (lhs ^ rhs) & (lhs ^ result) is negative on signed overflow.
            ValueId a = bin(Op::Xor, flags_.lhs, flags_.rhs);
            ValueId b = bin(Op::Xor, flags_.lhs, flags_.result);
            return signBitSet(bin(Op::And, a, b));
        }
        case ir::FlagPF: return intrinsic("_parity8", ir::kI1, {emitTruncTo(flags_.result, 1)});
        case ir::FlagAF: return intrinsic("aux_carry_sub", ir::kI1, {flags_.lhs, flags_.rhs});
        default: break;
        }
        break;
    case FlagOp::Add:
        switch (f) {
        case ir::FlagZF: return cmp(Op::CmpEq, flags_.result, zero);
        case ir::FlagCF: return cmp(Op::CmpUlt, flags_.result, flags_.lhs);
        case ir::FlagSF: return signBitSet(flags_.result);
        case ir::FlagOF: {
            ValueId a = bin(Op::Xor, flags_.lhs, flags_.result);
            ValueId b = bin(Op::Xor, flags_.rhs, flags_.result);
            return signBitSet(bin(Op::And, a, b));
        }
        case ir::FlagPF: return intrinsic("_parity8", ir::kI1, {emitTruncTo(flags_.result, 1)});
        case ir::FlagAF: return intrinsic("aux_carry_add", ir::kI1, {flags_.lhs, flags_.rhs});
        default: break;
        }
        break;
    case FlagOp::Logic:
        switch (f) {
        case ir::FlagZF: return cmp(Op::CmpEq, flags_.result, zero);
        case ir::FlagSF: return signBitSet(flags_.result);
        case ir::FlagCF: case ir::FlagOF: return boolConst(false);
        case ir::FlagPF: return intrinsic("_parity8", ir::kI1, {emitTruncTo(flags_.result, 1)});
        case ir::FlagAF: return undef(ir::kI1);
        default: break;
        }
        break;
    case FlagOp::Inc:
    case FlagOp::Dec:
        switch (f) {
        case ir::FlagZF: return cmp(Op::CmpEq, flags_.result, zero);
        case ir::FlagSF: return signBitSet(flags_.result);
        case ir::FlagOF:
            // Overflow exactly when the result is the signed extreme.
            return cmp(Op::CmpEq, flags_.result,
                       konstLike(flags_.result, flags_.op == FlagOp::Inc ? (1ull << (t.bits - 1))
                                                                         : maskBits(t.bits - 1)));
        case ir::FlagPF: return intrinsic("_parity8", ir::kI1, {emitTruncTo(flags_.result, 1)});
        case ir::FlagAF: return undef(ir::kI1);
        default: break;
        }
        break;
    case FlagOp::Neg:
        switch (f) {
        case ir::FlagZF: return cmp(Op::CmpEq, flags_.lhs, konstLike(flags_.lhs, 0));
        case ir::FlagCF: return cmp(Op::CmpNe, flags_.lhs, konstLike(flags_.lhs, 0));
        case ir::FlagSF: return signBitSet(flags_.result);
        case ir::FlagOF: return cmp(Op::CmpEq, flags_.lhs, konstLike(flags_.lhs, 1ull << (t.bits - 1)));
        case ir::FlagPF: return intrinsic("_parity8", ir::kI1, {emitTruncTo(flags_.result, 1)});
        default: break;
        }
        break;
    case FlagOp::Shift:
        switch (f) {
        case ir::FlagZF: return cmp(Op::CmpEq, flags_.result, zero);
        case ir::FlagSF: return signBitSet(flags_.result);
        case ir::FlagPF: return intrinsic("_parity8", ir::kI1, {emitTruncTo(flags_.result, 1)});
        default: break;
        }
        break;
    default:
        break;
    }
    // Fall back to the architectural flag location.
    ir::Loc l{ir::LocKind::Flag, (u16)f, 1};
    return fn_->readLoc(cur_, l, ir::kI1, addr_);
}

ValueId Lifter::materializeCond(Cond c) {
    // A condition whose flags were clobbered has no meaningful value.
    if (flags_.undefined & condFlags(c)) {
        bool anyKnown = (flags_.known & condFlags(c)) == condFlags(c);
        if (!anyKnown) return undef(ir::kI1);
    }
    // Fast paths that avoid computing flag bits at all.
    if (flags_.op == FlagOp::Sub) {
        ValueId a = flags_.lhs, b = flags_.rhs;
        switch (c) {
        case Cond::E: return cmp(Op::CmpEq, a, b);
        case Cond::NE: return cmp(Op::CmpNe, a, b);
        case Cond::B: return cmp(Op::CmpUlt, a, b);
        case Cond::AE: return cmp(Op::CmpUge, a, b);
        case Cond::BE: return cmp(Op::CmpUle, a, b);
        case Cond::A: return cmp(Op::CmpUgt, a, b);
        case Cond::L: return cmp(Op::CmpSlt, a, b);
        case Cond::GE: return cmp(Op::CmpSge, a, b);
        case Cond::LE: return cmp(Op::CmpSle, a, b);
        case Cond::G: return cmp(Op::CmpSgt, a, b);
        default: break;
        }
    } else if (flags_.op == FlagOp::Logic || flags_.op == FlagOp::Shift) {
        ValueId r = flags_.result;
        ValueId z = konstLike(r, 0);
        bool logic = flags_.op == FlagOp::Logic;
        switch (c) {
        case Cond::E: return cmp(Op::CmpEq, r, z);
        case Cond::NE: return cmp(Op::CmpNe, r, z);
        case Cond::S: return cmp(Op::CmpSlt, r, z);
        case Cond::NS: return cmp(Op::CmpSge, r, z);
        case Cond::L: if (logic) return cmp(Op::CmpSlt, r, z); break;   // SF ^ OF, OF = 0
        case Cond::GE: if (logic) return cmp(Op::CmpSge, r, z); break;
        case Cond::LE: if (logic) return cmp(Op::CmpSle, r, z); break;  // ZF | SF
        case Cond::G: if (logic) return cmp(Op::CmpSgt, r, z); break;
        case Cond::B: if (logic) return boolConst(false); break;
        case Cond::AE: if (logic) return boolConst(true); break;
        case Cond::BE: if (logic) return cmp(Op::CmpEq, r, z); break;   // CF | ZF, CF = 0
        case Cond::A: if (logic) return cmp(Op::CmpNe, r, z); break;
        case Cond::O: if (logic) return boolConst(false); break;
        case Cond::NO: if (logic) return boolConst(true); break;
        default: break;
        }
    } else if ((flags_.op == FlagOp::Add || flags_.op == FlagOp::Inc || flags_.op == FlagOp::Dec) &&
               flags_.result != kNoValue) {
        ValueId r = flags_.result;
        ValueId z = konstLike(r, 0);
        switch (c) {
        case Cond::E: return cmp(Op::CmpEq, r, z);
        case Cond::NE: return cmp(Op::CmpNe, r, z);
        case Cond::S: return cmp(Op::CmpSlt, r, z);
        case Cond::NS: return cmp(Op::CmpSge, r, z);
        default: break;
        }
    }
    // General case: compose from the individual bits.
    auto bit = [&](ir::FlagBit f) { return flagBitValue(f); };
    auto notOf = [&](ValueId v) { return bin(Op::Xor, v, boolConst(true)); };
    switch (c) {
    case Cond::O: return bit(ir::FlagOF);
    case Cond::NO: return notOf(bit(ir::FlagOF));
    case Cond::B: return bit(ir::FlagCF);
    case Cond::AE: return notOf(bit(ir::FlagCF));
    case Cond::E: return bit(ir::FlagZF);
    case Cond::NE: return notOf(bit(ir::FlagZF));
    case Cond::BE: return bin(Op::Or, bit(ir::FlagCF), bit(ir::FlagZF));
    case Cond::A: return notOf(bin(Op::Or, bit(ir::FlagCF), bit(ir::FlagZF)));
    case Cond::S: return bit(ir::FlagSF);
    case Cond::NS: return notOf(bit(ir::FlagSF));
    case Cond::P: return bit(ir::FlagPF);
    case Cond::NP: return notOf(bit(ir::FlagPF));
    case Cond::L: return bin(Op::Xor, bit(ir::FlagSF), bit(ir::FlagOF));
    case Cond::GE: return notOf(bin(Op::Xor, bit(ir::FlagSF), bit(ir::FlagOF)));
    case Cond::LE: return bin(Op::Or, bit(ir::FlagZF), bin(Op::Xor, bit(ir::FlagSF), bit(ir::FlagOF)));
    case Cond::G: return notOf(bin(Op::Or, bit(ir::FlagZF), bin(Op::Xor, bit(ir::FlagSF), bit(ir::FlagOF))));
    default: return boolConst(false);
    }
}

void Lifter::flushFlags(FlagMask liveOut) {
    for (int i = 0; i < ir::FlagCount; ++i) {
        ir::FlagBit f = (ir::FlagBit)i;
        if (!(liveOut & flagBit(f))) continue;
        ValueId v = flagBitValue(f);
        ir::Loc l{ir::LocKind::Flag, (u16)f, 1};
        fn_->writeLoc(cur_, l, v, addr_);
    }
}
// ---------------------------------------------------------------------------
// Instruction semantics
// ---------------------------------------------------------------------------

namespace {
// Number of bits of the shift-count operand that x86 actually uses.
unsigned shiftMask(unsigned operandBytes) { return operandBytes == 8 ? 63 : 31; }
} // namespace

void Lifter::unsupported(const Instruction& in) {
    std::string name = mnemName(in.mnem);
    if (in.mnem == Mnem::Unknown) name = in.mnemonicText;
    if (std::find(unsupported_.begin(), unsupported_.end(), name) == unsupported_.end())
        unsupported_.push_back(name);
    fn_->notes().push_back(strfmt("unsupported instruction at %s: %s", hex(in.address).c_str(), in.text().c_str()));

    // Model it honestly: an opaque operation over the source operands whose
    // result clobbers the destination, plus full flag invalidation.
    std::vector<ValueId> args;
    for (unsigned i = 0; i < in.numOps; ++i) {
        const Operand& op = in.ops[i];
        if (op.isReg()) args.push_back(regs_->read(op.reg));
        else if (op.isMem()) args.push_back(effectiveAddress(in, op));
        else if (op.isImm()) args.push_back(konst(intTypeForBytes(op.size ? op.size : pointerBytes()), (u64)op.imm));
    }
    std::string label = "asm(\"" + in.text() + "\")";
    if (in.numOps >= 1 && (in.ops[0].isReg() || in.ops[0].isMem())) {
        unsigned bytes = in.ops[0].size ? in.ops[0].size : pointerBytes();
        ValueId r = intrinsic(label.c_str(), intTypeForBytes(bytes), std::move(args), true);
        writeOperand(in, 0, r);
    } else {
        intrinsic(label.c_str(), Type::voidTy(), std::move(args), true);
    }
    FlagMask reads, writes;
    flagEffects(in, reads, writes);
    setFlagsUnknown(writes ? writes : kFlagsArith);
}

bool Lifter::liftDataMovement(const Instruction& in) {
    switch (in.mnem) {
    case Mnem::Mov: {
        ValueId v = readOperand(in, 1);
        // A pointer-width register copy carries the frame relationship over.
        i64 srcDelta = 0;
        bool srcFrame = in.ops[0].isReg() && in.ops[1].isReg() &&
                        regSize(in.ops[0].reg) == pointerBytes() &&
                        regs_->stackRelative(regFamily(in.ops[1].reg), srcDelta);
        unsigned dstBytes = in.ops[0].size ? in.ops[0].size : bytesOf(v);
        writeOperand(in, 0, emitTruncTo(v, dstBytes));
        if (srcFrame) {
            Family dst = regFamily(in.ops[0].reg);
            if (dst == Family::F_RSP) { spDelta_ = srcDelta; spKnown_ = true; }
            regs_->setStackRelative(dst, srcDelta);
        }
        return true;
    }
    case Mnem::Movzx: {
        ValueId v = readOperand(in, 1);
        writeOperand(in, 0, emitZExtTo(v, in.ops[0].size));
        return true;
    }
    case Mnem::Movsx:
    case Mnem::Movsxd: {
        ValueId v = readOperand(in, 1);
        writeOperand(in, 0, emitSExtTo(v, in.ops[0].size));
        return true;
    }
    case Mnem::Lea: {
        if (!in.ops[1].isMem()) return false;
        ValueId a = effectiveAddress(in, in.ops[1]);
        // lea of a frame address keeps its stack-relative meaning.
        const ir::Inst& ai = fn_->inst(a);
        if (in.ops[0].isReg() && ai.op == Op::FrameAddr && regSize(in.ops[0].reg) == pointerBytes()) {
            writeOperand(in, 0, emitTruncTo(a, in.ops[0].size));
            regs_->setStackRelative(regFamily(in.ops[0].reg), (i64)ai.imm);
            return true;
        }
        writeOperand(in, 0, emitTruncTo(a, in.ops[0].size));
        return true;
    }
    case Mnem::Xchg: {
        ValueId a = readOperand(in, 0);
        ValueId b = readOperand(in, 1);
        writeOperand(in, 0, b);
        writeOperand(in, 1, a);
        return true;
    }
    case Mnem::Xadd: {
        ValueId a = readOperand(in, 0);
        ValueId b = readOperand(in, 1);
        ValueId sum = bin(Op::Add, a, b);
        writeOperand(in, 1, a);
        writeOperand(in, 0, sum);
        setFlagsAdd(a, b, sum);
        return true;
    }
    case Mnem::Cmpxchg: {
        unsigned bytes = in.ops[0].size;
        ValueId acc = regs_->readFamily(Family::F_RAX, bytes);
        ValueId dst = readOperand(in, 0);
        ValueId src = readOperand(in, 1);
        ValueId eq = cmp(Op::CmpEq, acc, dst);
        writeOperand(in, 0, select(eq, src, dst));
        regs_->writeFamily(Family::F_RAX, bytes, 0, select(eq, acc, dst));
        setFlagsSub(acc, dst, bin(Op::Sub, acc, dst));
        return true;
    }
    default:
        break;
    }
    if (in.mnem >= Mnem::Cmovo && in.mnem <= Mnem::Cmovg) {
        ValueId c = materializeCond(in.condition());
        ValueId a = readOperand(in, 1);
        ValueId b = readOperand(in, 0);
        writeOperand(in, 0, select(c, a, b));
        return true;
    }
    if (in.mnem >= Mnem::Seto && in.mnem <= Mnem::Setg) {
        ValueId c = materializeCond(in.condition());
        writeOperand(in, 0, zeroExtendBool(c, ir::kI8));
        return true;
    }
    return false;
}

bool Lifter::liftArithmetic(const Instruction& in) {
    switch (in.mnem) {
    case Mnem::Add: {
        ValueId a = readOperand(in, 0);
        ValueId b = emitTruncTo(readOperand(in, 1), bytesOf(a));
        // Capture the frame relationship before the write clears it.
        i64 d = 0;
        bool wasFrame = in.ops[0].isReg() && in.ops[1].isImm() &&
                        regSize(in.ops[0].reg) == pointerBytes() &&
                        regs_->stackRelative(regFamily(in.ops[0].reg), d);
        ValueId r = bin(Op::Add, a, b);
        writeOperand(in, 0, r);
        setFlagsAdd(a, b, r);
        if (wasFrame) {
            Family fam = regFamily(in.ops[0].reg);
            if (fam == Family::F_RSP) adjustStack(in.ops[1].imm);
            else regs_->setStackRelative(fam, d + in.ops[1].imm);
        }
        return true;
    }
    case Mnem::Sub: {
        if (in.ops[0].isReg() && in.ops[1].isReg() && in.ops[0].reg == in.ops[1].reg) {
            ValueId z = konst(intTypeForBytes(in.ops[0].size ? in.ops[0].size : pointerBytes()), 0);
            writeOperand(in, 0, z);
            setFlagsSub(z, z, z);
            return true;
        }
        ValueId a = readOperand(in, 0);
        ValueId b = emitTruncTo(readOperand(in, 1), bytesOf(a));
        i64 d = 0;
        bool wasFrame = in.ops[0].isReg() && in.ops[1].isImm() &&
                        regSize(in.ops[0].reg) == pointerBytes() &&
                        regs_->stackRelative(regFamily(in.ops[0].reg), d);
        ValueId r = bin(Op::Sub, a, b);
        writeOperand(in, 0, r);
        setFlagsSub(a, b, r);
        if (wasFrame) {
            Family fam = regFamily(in.ops[0].reg);
            if (fam == Family::F_RSP) adjustStack(-in.ops[1].imm);
            else regs_->setStackRelative(fam, d - in.ops[1].imm);
        }
        return true;
    }
    case Mnem::Adc: {
        ValueId a = readOperand(in, 0);
        ValueId b = emitTruncTo(readOperand(in, 1), bytesOf(a));
        ValueId cf = zeroExtendBool(flagBitValue(ir::FlagCF), typeOf(a));
        ValueId r = bin(Op::Add, bin(Op::Add, a, b), cf);
        writeOperand(in, 0, r);
        setFlagsAdd(a, b, r);
        return true;
    }
    case Mnem::Sbb: {
        ValueId a = readOperand(in, 0);
        ValueId b = emitTruncTo(readOperand(in, 1), bytesOf(a));
        ValueId cf = zeroExtendBool(flagBitValue(ir::FlagCF), typeOf(a));
        ValueId r = bin(Op::Sub, bin(Op::Sub, a, b), cf);
        writeOperand(in, 0, r);
        setFlagsSub(a, b, r);
        return true;
    }
    case Mnem::Cmp: {
        ValueId a = readOperand(in, 0);
        ValueId b = emitTruncTo(readOperand(in, 1), bytesOf(a));
        setFlagsSub(a, b, bin(Op::Sub, a, b));
        return true;
    }
    case Mnem::Inc: {
        ValueId a = readOperand(in, 0);
        ValueId r = bin(Op::Add, a, konstLike(a, 1));
        writeOperand(in, 0, r);
        setFlagsIncDec(a, r, true);
        return true;
    }
    case Mnem::Dec: {
        ValueId a = readOperand(in, 0);
        ValueId r = bin(Op::Sub, a, konstLike(a, 1));
        writeOperand(in, 0, r);
        setFlagsIncDec(a, r, false);
        return true;
    }
    case Mnem::Neg: {
        ValueId a = readOperand(in, 0);
        ValueId r = un(Op::Neg, a);
        writeOperand(in, 0, r);
        setFlagsNeg(a, r);
        return true;
    }
    default:
        return false;
    }
}

bool Lifter::liftLogic(const Instruction& in) {
    auto simple = [&](Op op) {
        // "xor reg, same-reg" is the zeroing idiom. It must be recognised
        // before the operand is read, or the dead read makes the register
        // look live on entry and invents a parameter.
        if (op == Op::Xor && in.ops[0].isReg() && in.ops[1].isReg() && in.ops[0].reg == in.ops[1].reg) {
            ValueId z = konst(intTypeForBytes(in.ops[0].size ? in.ops[0].size : pointerBytes()), 0);
            writeOperand(in, 0, z);
            setFlagsLogic(z, z, z);
            return;
        }
        ValueId a = readOperand(in, 0);
        ValueId b = emitTruncTo(readOperand(in, 1), bytesOf(a));
        ValueId r = bin(op, a, b);
        writeOperand(in, 0, r);
        setFlagsLogic(a, b, r);
    };
    switch (in.mnem) {
    case Mnem::And: simple(Op::And); return true;
    case Mnem::Or: simple(Op::Or); return true;
    case Mnem::Xor: simple(Op::Xor); return true;
    case Mnem::Not: {
        ValueId a = readOperand(in, 0);
        writeOperand(in, 0, un(Op::Not, a)); // NOT does not touch flags
        return true;
    }
    case Mnem::Test: {
        ValueId a = readOperand(in, 0);
        ValueId b = emitTruncTo(readOperand(in, 1), bytesOf(a));
        bool same = in.ops[0].isReg() && in.ops[1].isReg() && in.ops[0].reg == in.ops[1].reg;
        ValueId r = same ? a : bin(Op::And, a, b);
        setFlagsLogic(a, b, r);
        return true;
    }
    case Mnem::Andn: {
        if (in.numOps != 3) return false;
        ValueId a = readOperand(in, 1);
        ValueId b = readOperand(in, 2);
        ValueId r = bin(Op::And, un(Op::Not, a), b);
        writeOperand(in, 0, r);
        setFlagsLogic(a, b, r);
        return true;
    }
    default:
        return false;
    }
}

bool Lifter::liftShift(const Instruction& in) {
    // shld and shrd take the count as their third operand; every other shift
    // takes it as the second.
    auto shiftCount = [&](ValueId base, unsigned opIndex = 1) {
        ValueId c = in.numOps > opIndex ? readOperand(in, opIndex) : konst(ir::kI8, 1);
        c = emitZExtTo(emitTruncTo(c, 1), bytesOf(base));
        return bin(Op::And, c, konstLike(base, shiftMask(bytesOf(base))));
    };
    switch (in.mnem) {
    case Mnem::Shl:
    case Mnem::Shr:
    case Mnem::Sar: {
        ValueId a = readOperand(in, 0);
        ValueId c = shiftCount(a);
        Op op = in.mnem == Mnem::Shl ? Op::Shl : (in.mnem == Mnem::Shr ? Op::LShr : Op::AShr);
        ValueId r = bin(op, a, c);
        writeOperand(in, 0, r);
        // CF is the last bit shifted out; OF only meaningful for count 1.
        ValueId cf;
        if (in.mnem == Mnem::Shl) {
            ValueId sh = bin(Op::Sub, konstLike(a, bytesOf(a) * 8), c);
            cf = emitTruncTo(bin(Op::LShr, a, sh), 1);
        } else {
            ValueId sh = bin(Op::Sub, c, konstLike(a, 1));
            cf = emitTruncTo(bin(Op::LShr, a, sh), 1);
        }
        cf = cmp(Op::CmpNe, bin(Op::And, cf, konstLike(cf, 1)), konstLike(cf, 0));
        setFlagsShift(r, cf, kNoValue);
        return true;
    }
    case Mnem::Rol:
    case Mnem::Ror: {
        ValueId a = readOperand(in, 0);
        ValueId c = shiftCount(a);
        ValueId r = bin(in.mnem == Mnem::Rol ? Op::Rol : Op::Ror, a, c);
        writeOperand(in, 0, r);
        // ZF/SF are untouched by rotates; only CF/OF change.
        FlagState saved = flags_;
        flags_ = saved;
        setFlagBit(ir::FlagCF, cmp(Op::CmpNe, bin(Op::And, r, konstLike(r, in.mnem == Mnem::Rol ? 1 : (1ull << (bytesOf(r) * 8 - 1)))), konstLike(r, 0)));
        setFlagBit(ir::FlagOF, undef(ir::kI1));
        return true;
    }
    case Mnem::Rcl:
    case Mnem::Rcr: {
        ValueId a = readOperand(in, 0);
        ValueId c = shiftCount(a);
        ValueId cf = zeroExtendBool(flagBitValue(ir::FlagCF), typeOf(a));
        ValueId r = intrinsic(in.mnem == Mnem::Rcl ? "_rotl_carry" : "_rotr_carry", typeOf(a), {a, c, cf});
        writeOperand(in, 0, r);
        setFlagBit(ir::FlagCF, undef(ir::kI1));
        setFlagBit(ir::FlagOF, undef(ir::kI1));
        return true;
    }
    case Mnem::Shld:
    case Mnem::Shrd: {
        if (in.numOps < 3) return false;
        ValueId a = readOperand(in, 0);
        ValueId b = emitTruncTo(readOperand(in, 1), bytesOf(a));
        ValueId c = shiftCount(a, 2);
        unsigned bits = bytesOf(a) * 8;
        ValueId inv = bin(Op::Sub, konstLike(a, bits), c);
        ValueId r = in.mnem == Mnem::Shld ? bin(Op::Or, bin(Op::Shl, a, c), bin(Op::LShr, b, inv))
                                          : bin(Op::Or, bin(Op::LShr, a, c), bin(Op::Shl, b, inv));
        // A count of zero leaves the destination alone. Spelling that out
        // matters: the complementary shift would otherwise be by the full
        // width, which the hardware masks back to no shift at all.
        const ir::Inst& ci = fn_->inst(c);
        if (!(ci.op == Op::Const && truncBits(ci.imm, ci.type.bits) != 0))
            r = select(cmp(Op::CmpEq, c, konstLike(c, 0)), a, r);
        writeOperand(in, 0, r);
        setFlagsShift(r, undef(ir::kI1), kNoValue);
        return true;
    }
    default:
        return false;
    }
}

bool Lifter::liftMulDiv(const Instruction& in) {
    switch (in.mnem) {
    case Mnem::Imul: {
        if (in.numOps == 1) {
            unsigned bytes = in.ops[0].size;
            ValueId a = regs_->readFamily(Family::F_RAX, bytes);
            ValueId b = readOperand(in, 0);
            ValueId lo = bin(Op::Mul, a, b);
            ValueId hi = bin(Op::MulHiS, a, b);
            if (bytes == 1) {
                regs_->writeFamily(Family::F_RAX, 2, 0, bin(Op::Mul, emitSExtTo(a, 2), emitSExtTo(b, 2)));
            } else {
                regs_->writeFamily(Family::F_RAX, bytes, 0, lo);
                regs_->writeFamily(Family::F_RDX, bytes, 0, hi);
            }
            setFlagsUnknown(kFlagsArith);
            setFlagBit(ir::FlagCF, cmp(Op::CmpNe, hi, konstLike(hi, 0)));
            setFlagBit(ir::FlagOF, cmp(Op::CmpNe, hi, konstLike(hi, 0)));
            return true;
        }
        ValueId a = readOperand(in, in.numOps == 2 ? 0 : 1);
        ValueId b = emitTruncTo(readOperand(in, in.numOps == 2 ? 1 : 2), bytesOf(a));
        ValueId r = bin(Op::Mul, a, b);
        writeOperand(in, 0, emitTruncTo(r, in.ops[0].size));
        setFlagsUnknown(kFlagsArith);
        return true;
    }
    case Mnem::Mul: {
        unsigned bytes = in.ops[0].size;
        ValueId a = regs_->readFamily(Family::F_RAX, bytes);
        ValueId b = readOperand(in, 0);
        ValueId lo = bin(Op::Mul, a, b);
        ValueId hi = bin(Op::MulHiU, a, b);
        if (bytes == 1) {
            regs_->writeFamily(Family::F_RAX, 2, 0, bin(Op::Mul, emitZExtTo(a, 2), emitZExtTo(b, 2)));
        } else {
            regs_->writeFamily(Family::F_RAX, bytes, 0, lo);
            regs_->writeFamily(Family::F_RDX, bytes, 0, hi);
        }
        setFlagsUnknown(kFlagsArith);
        setFlagBit(ir::FlagCF, cmp(Op::CmpNe, hi, konstLike(hi, 0)));
        setFlagBit(ir::FlagOF, cmp(Op::CmpNe, hi, konstLike(hi, 0)));
        return true;
    }
    case Mnem::Div:
    case Mnem::Idiv: {
        unsigned bytes = in.ops[0].size;
        bool sign = in.mnem == Mnem::Idiv;
        ValueId d = readOperand(in, 0);
        if (bytes == 1) {
            ValueId num = regs_->readFamily(Family::F_RAX, 2);
            ValueId dd = sign ? emitSExtTo(d, 2) : emitZExtTo(d, 2);
            ValueId q = bin(sign ? Op::SDiv : Op::UDiv, num, dd);
            ValueId r = bin(sign ? Op::SRem : Op::URem, num, dd);
            regs_->writeFamily(Family::F_RAX, 1, 0, emitTruncTo(q, 1));
            regs_->writeFamily(Family::F_RAX, 1, 1, emitTruncTo(r, 1));
        } else {
            // The dividend is RDX:RAX. Where RDX is just the sign/zero extension
            // of RAX (the usual compiler output) the wide division collapses to
            // a plain one at the operand width.
            ValueId lo = regs_->readFamily(Family::F_RAX, bytes);
            ValueId hi = regs_->readFamily(Family::F_RDX, bytes);
            bool narrow = false;
            const ir::Inst& hiIn = fn_->inst(hi);
            if (!sign && hiIn.op == Op::Const && hiIn.imm == 0) narrow = true;
            if (sign && hiIn.op == Op::AShr && hiIn.args[0] == lo) narrow = true;
            if (sign && hiIn.op == Op::Intrinsic && hiIn.text == "sign_extend_high" && hiIn.args.size() == 1 &&
                hiIn.args[0] == lo)
                narrow = true;
            ValueId q, r;
            if (narrow) {
                q = bin(sign ? Op::SDiv : Op::UDiv, lo, d);
                r = bin(sign ? Op::SRem : Op::URem, lo, d);
            } else {
                unsigned wide = bytes * 2;
                Type wt = Type::i((u16)(wide * 8));
                ValueId num = bin(Op::Or, fn_->binary(cur_, Op::Shl, wt, emitZExtTo(hi, wide), konst(wt, bytes * 8), addr_),
                                  emitZExtTo(lo, wide));
                ValueId dd = sign ? emitSExtTo(d, wide) : emitZExtTo(d, wide);
                q = emitTruncTo(bin(sign ? Op::SDiv : Op::UDiv, num, dd), bytes);
                r = emitTruncTo(bin(sign ? Op::SRem : Op::URem, num, dd), bytes);
            }
            regs_->writeFamily(Family::F_RAX, bytes, 0, q);
            regs_->writeFamily(Family::F_RDX, bytes, 0, r);
        }
        setFlagsUnknown(kFlagsArith);
        return true;
    }
    case Mnem::Cbw:
        regs_->writeFamily(Family::F_RAX, 2, 0, emitSExtTo(regs_->readFamily(Family::F_RAX, 1), 2));
        return true;
    case Mnem::Cwde:
        regs_->writeFamily(Family::F_RAX, 4, 0, emitSExtTo(regs_->readFamily(Family::F_RAX, 2), 4));
        return true;
    case Mnem::Cdqe:
        regs_->writeFamily(Family::F_RAX, 8, 0, emitSExtTo(regs_->readFamily(Family::F_RAX, 4), 8));
        return true;
    case Mnem::Cwd:
    case Mnem::Cdq:
    case Mnem::Cqo: {
        unsigned bytes = in.mnem == Mnem::Cwd ? 2 : (in.mnem == Mnem::Cdq ? 4 : 8);
        ValueId a = regs_->readFamily(Family::F_RAX, bytes);
        // Sign replication: RDX = a >> (bits-1) arithmetically.
        ValueId hi = bin(Op::AShr, a, konstLike(a, bytes * 8 - 1));
        regs_->writeFamily(Family::F_RDX, bytes, 0, hi);
        return true;
    }
    default:
        return false;
    }
}

bool Lifter::liftBits(const Instruction& in) {
    switch (in.mnem) {
    case Mnem::Bt:
    case Mnem::Bts:
    case Mnem::Btr:
    case Mnem::Btc: {
        ValueId a = readOperand(in, 0);
        ValueId b = emitTruncTo(readOperand(in, 1), bytesOf(a));
        ValueId idx = bin(Op::And, b, konstLike(a, bytesOf(a) * 8 - 1));
        ValueId mask = bin(Op::Shl, konstLike(a, 1), idx);
        ValueId bit = cmp(Op::CmpNe, bin(Op::And, a, mask), konstLike(a, 0));
        ValueId r = kNoValue;
        switch (in.mnem) {
        case Mnem::Bts: r = bin(Op::Or, a, mask); break;
        case Mnem::Btr: r = bin(Op::And, a, un(Op::Not, mask)); break;
        case Mnem::Btc: r = bin(Op::Xor, a, mask); break;
        default: break;
        }
        if (r != kNoValue) writeOperand(in, 0, r);
        flags_.clear();
        flags_.op = FlagOp::BitTest;
        setFlagBit(ir::FlagCF, bit);
        setFlagBit(ir::FlagOF, undef(ir::kI1));
        setFlagBit(ir::FlagSF, undef(ir::kI1));
        setFlagBit(ir::FlagPF, undef(ir::kI1));
        setFlagBit(ir::FlagAF, undef(ir::kI1));
        return true;
    }
    case Mnem::Bsf:
    case Mnem::Tzcnt: {
        ValueId a = readOperand(in, 1);
        ValueId r = intrinsic("_tzcnt_u32", typeOf(a), {a});
        writeOperand(in, 0, emitTruncTo(r, in.ops[0].size));
        setFlagsUnknown(kFlagsArith);
        setFlagBit(ir::FlagZF, cmp(Op::CmpEq, a, konstLike(a, 0)));
        return true;
    }
    case Mnem::Bsr: {
        ValueId a = readOperand(in, 1);
        ValueId r = intrinsic("_bit_scan_reverse", typeOf(a), {a});
        writeOperand(in, 0, emitTruncTo(r, in.ops[0].size));
        setFlagsUnknown(kFlagsArith);
        setFlagBit(ir::FlagZF, cmp(Op::CmpEq, a, konstLike(a, 0)));
        return true;
    }
    case Mnem::Lzcnt: {
        ValueId a = readOperand(in, 1);
        ValueId r = intrinsic("_lzcnt_u32", typeOf(a), {a});
        writeOperand(in, 0, emitTruncTo(r, in.ops[0].size));
        setFlagsUnknown(kFlagsArith);
        return true;
    }
    case Mnem::Popcnt: {
        ValueId a = readOperand(in, 1);
        ValueId r = intrinsic("__popcnt", typeOf(a), {a});
        writeOperand(in, 0, emitTruncTo(r, in.ops[0].size));
        setFlagsUnknown(kFlagsArith);
        setFlagBit(ir::FlagZF, cmp(Op::CmpEq, a, konstLike(a, 0)));
        return true;
    }
    case Mnem::Bswap: {
        ValueId a = readOperand(in, 0);
        writeOperand(in, 0, intrinsic("_byteswap", typeOf(a), {a}));
        return true;
    }
    default:
        return false;
    }
}

// --- SSE / x87 -------------------------------------------------------------

ValueId Lifter::readFloat(const Instruction& in, unsigned i, Type ft) {
    const Operand& op = in.ops[i];
    if (op.isMem()) return fn_->load(cur_, ft, effectiveAddress(in, op), addr_);
    ValueId v = regs_->readFamily(regFamily(op.reg), ft.bytes());
    Type t = typeOf(v);
    if (t == ft) return v;
    if (t.bits == ft.bits) return fn_->cast(cur_, Op::Bitcast, ft, v, addr_);
    return fn_->cast(cur_, Op::Bitcast, ft, emitTruncTo(v, ft.bytes()), addr_);
}

void Lifter::writeFloat(const Instruction& in, unsigned i, ValueId v) {
    const Operand& op = in.ops[i];
    if (op.isMem()) {
        fn_->store(cur_, effectiveAddress(in, op), v, addr_);
        return;
    }
    regs_->writeFamily(regFamily(op.reg), typeOf(v).bytes(), 0, v);
}

bool Lifter::liftSse(const Instruction& in) {
    auto f32 = ir::kF32;
    auto f64 = ir::kF64;
    auto arith = [&](Op op, Type ft) {
        unsigned src = in.numOps == 3 ? 2 : 1; // AVX three-operand form
        unsigned lhs = in.numOps == 3 ? 1 : 0;
        ValueId a = readFloat(in, lhs, ft);
        ValueId b = readFloat(in, src, ft);
        writeFloat(in, 0, fn_->binary(cur_, op, ft, a, b, addr_));
    };
    auto moveFloat = [&](Type ft) {
        ValueId v = readFloat(in, 1, ft);
        writeFloat(in, 0, v);
    };
    auto compare = [&](Type ft) {
        ValueId a = readFloat(in, 0, ft);
        ValueId b = readFloat(in, 1, ft);
        flags_.clear();
        flags_.op = FlagOp::Explicit;
        // ZF/PF/CF encode the unordered comparison result.
        setFlagBit(ir::FlagZF, fn_->binary(cur_, Op::FCmpEq, ir::kI1, a, b, addr_));
        setFlagBit(ir::FlagCF, fn_->binary(cur_, Op::FCmpLt, ir::kI1, a, b, addr_));
        setFlagBit(ir::FlagPF, fn_->binary(cur_, Op::FCmpUno, ir::kI1, a, b, addr_));
        setFlagBit(ir::FlagOF, boolConst(false));
        setFlagBit(ir::FlagSF, boolConst(false));
        setFlagBit(ir::FlagAF, boolConst(false));
        flags_.lhs = a;
        flags_.rhs = b;
        flags_.type = ft;
    };
    switch (in.mnem) {
    case Mnem::Movss: case Mnem::Vmovss: moveFloat(f32); return true;
    case Mnem::Movsd: case Mnem::Vmovsd: moveFloat(f64); return true;
    case Mnem::Addss: case Mnem::Vaddss: arith(Op::FAdd, f32); return true;
    case Mnem::Addsd: case Mnem::Vaddsd: arith(Op::FAdd, f64); return true;
    case Mnem::Subss: case Mnem::Vsubss: arith(Op::FSub, f32); return true;
    case Mnem::Subsd: case Mnem::Vsubsd: arith(Op::FSub, f64); return true;
    case Mnem::Mulss: case Mnem::Vmulss: arith(Op::FMul, f32); return true;
    case Mnem::Mulsd: case Mnem::Vmulsd: arith(Op::FMul, f64); return true;
    case Mnem::Divss: case Mnem::Vdivss: arith(Op::FDiv, f32); return true;
    case Mnem::Divsd: case Mnem::Vdivsd: arith(Op::FDiv, f64); return true;
    case Mnem::Minss: arith(Op::FMin, f32); return true;
    case Mnem::Minsd: arith(Op::FMin, f64); return true;
    case Mnem::Maxss: arith(Op::FMax, f32); return true;
    case Mnem::Maxsd: arith(Op::FMax, f64); return true;
    case Mnem::Sqrtss: writeFloat(in, 0, fn_->unary(cur_, Op::FSqrt, f32, readFloat(in, 1, f32), addr_)); return true;
    case Mnem::Sqrtsd: writeFloat(in, 0, fn_->unary(cur_, Op::FSqrt, f64, readFloat(in, 1, f64), addr_)); return true;
    case Mnem::Comiss: case Mnem::Ucomiss: case Mnem::Vcomiss: case Mnem::Vucomiss: compare(f32); return true;
    case Mnem::Comisd: case Mnem::Ucomisd: case Mnem::Vcomisd: case Mnem::Vucomisd: compare(f64); return true;
    case Mnem::Cvtsi2ss: case Mnem::Vcvtsi2ss: {
        ValueId a = readOperand(in, in.numOps == 3 ? 2 : 1);
        writeFloat(in, 0, fn_->cast(cur_, Op::SIToFP, f32, a, addr_));
        return true;
    }
    case Mnem::Cvtsi2sd: case Mnem::Vcvtsi2sd: {
        ValueId a = readOperand(in, in.numOps == 3 ? 2 : 1);
        writeFloat(in, 0, fn_->cast(cur_, Op::SIToFP, f64, a, addr_));
        return true;
    }
    case Mnem::Cvttss2si: case Mnem::Cvtss2si: case Mnem::Vcvttss2si: {
        ValueId a = readFloat(in, 1, f32);
        writeOperand(in, 0, fn_->cast(cur_, Op::FPToSI, intTypeForBytes(in.ops[0].size), a, addr_));
        return true;
    }
    case Mnem::Cvttsd2si: case Mnem::Cvtsd2si: case Mnem::Vcvttsd2si: {
        ValueId a = readFloat(in, 1, f64);
        writeOperand(in, 0, fn_->cast(cur_, Op::FPToSI, intTypeForBytes(in.ops[0].size), a, addr_));
        return true;
    }
    case Mnem::Cvtss2sd: case Mnem::Vcvtss2sd:
        writeFloat(in, 0, fn_->cast(cur_, Op::FPExt, f64, readFloat(in, 1, f32), addr_));
        return true;
    case Mnem::Cvtsd2ss: case Mnem::Vcvtsd2ss:
        writeFloat(in, 0, fn_->cast(cur_, Op::FPTrunc, f32, readFloat(in, 1, f64), addr_));
        return true;
    case Mnem::Xorps: case Mnem::Xorpd: case Mnem::Pxor: case Mnem::Vxorps: case Mnem::Vxorpd: case Mnem::Vpxor: {
        // The standard zeroing idiom.
        unsigned a = in.numOps == 3 ? 1 : 0, b = in.numOps == 3 ? 2 : 1;
        if (in.ops[a].isReg() && in.ops[b].isReg() && in.ops[a].reg == in.ops[b].reg) {
            unsigned bytes = std::min<unsigned>(familyWidth(regFamily(in.ops[0].reg)), 8);
            regs_->writeFamily(regFamily(in.ops[0].reg), bytes, 0, konst(intTypeForBytes(bytes), 0));
            return true;
        }
        unsigned bytes = std::min<unsigned>(in.ops[0].size ? in.ops[0].size : 16, 8);
        ValueId x = emitTruncTo(readOperand(in, a), bytes);
        ValueId y = emitTruncTo(readOperand(in, b), bytes);
        regs_->writeFamily(regFamily(in.ops[0].reg), bytes, 0, bin(Op::Xor, x, y));
        return true;
    }
    case Mnem::Movd: case Mnem::Vmovd: case Mnem::Movq: case Mnem::Vmovq: {
        unsigned bytes = (in.mnem == Mnem::Movq || in.mnem == Mnem::Vmovq) ? 8 : 4;
        ValueId v;
        if (in.ops[1].isMem()) v = fn_->load(cur_, intTypeForBytes(bytes), effectiveAddress(in, in.ops[1]), addr_);
        else v = emitTruncTo(regs_->readFamily(regFamily(in.ops[1].reg), bytes), bytes);
        if (in.ops[0].isMem()) {
            fn_->store(cur_, effectiveAddress(in, in.ops[0]), v, addr_);
        } else {
            Family dst = regFamily(in.ops[0].reg);
            regs_->writeFamily(dst, bytes, 0, v);
            // movd and movq into a vector register clear everything above the
            // value they move.
            if (isXmmFamily(dst)) regs_->writeXmmHigh(dst, konst(ir::kI64, 0));
        }
        return true;
    }
    case Mnem::Movaps: case Mnem::Movups: case Mnem::Movapd: case Mnem::Movupd:
    case Mnem::Movdqa: case Mnem::Movdqu: case Mnem::Vmovaps: case Mnem::Vmovups:
    case Mnem::Vmovdqa: case Mnem::Vmovdqu: case Mnem::Movntdq: {
        // A 128-bit move, carried as its two 64-bit lanes so that every value
        // stays inside a machine word the rest of the pipeline can reason
        // about.
        ValueId lo, hi;
        if (in.ops[1].isMem()) {
            ValueId base = effectiveAddress(in, in.ops[1]);
            lo = fn_->load(cur_, ir::kI64, base, addr_);
            hi = fn_->load(cur_, ir::kI64, bin(Op::Add, base, konstLike(base, 8)), addr_);
        } else {
            Family src = regFamily(in.ops[1].reg);
            lo = emitTruncTo(regs_->readFamily(src, 8), 8);
            hi = regs_->readXmmHigh(src);
        }
        if (in.ops[0].isMem()) {
            ValueId base = effectiveAddress(in, in.ops[0]);
            fn_->store(cur_, base, lo, addr_);
            fn_->store(cur_, bin(Op::Add, base, konstLike(base, 8)), hi, addr_);
        } else {
            Family dst = regFamily(in.ops[0].reg);
            regs_->writeFamily(dst, 8, 0, lo);
            regs_->writeXmmHigh(dst, hi);
        }
        return true;
    }
    case Mnem::Movnti: {
        ValueId v = readOperand(in, 1);
        writeOperand(in, 0, v);
        return true;
    }
    case Mnem::Punpckldq: {
        // Interleaves the low dwords: result = dst.d0 | (src.d0 << 32).
        ValueId a = emitTruncTo(readOperand(in, 0), 4);
        ValueId b2 = emitTruncTo(readOperand(in, 1), 4);
        ValueId lo = emitZExtTo(a, 8);
        ValueId hi = bin(Op::Shl, emitZExtTo(b2, 8), konst(ir::kI64, 32));
        regs_->writeFamily(regFamily(in.ops[0].reg), 8, 0, bin(Op::Or, lo, hi));
        return true;
    }
    case Mnem::Punpcklqdq: case Mnem::Unpcklpd: {
        // Moves the source's low lane into the destination's high lane. The
        // low lane is untouched, so the two-lane model expresses it exactly.
        if (!in.ops[0].isReg()) return false;
        regs_->writeXmmHigh(regFamily(in.ops[0].reg), emitTruncTo(readOperand(in, 1), 8));
        return true;
    }
    default:
        return false;
    }
}

bool Lifter::liftX87(const Instruction& in) {
    // The x87 stack is modelled as eight rotating families. Compiler output
    // keeps the stack balanced across blocks, which is what this assumes.
    auto stReg = [&](int i) { return (Family)((int)Family::F_ST0 + ((fpuTop_ + i) & 7)); };
    auto push = [&](ValueId v) {
        fpuTop_ = (fpuTop_ - 1) & 7;
        regs_->writeFamily(stReg(0), 8, 0, v);
    };
    auto pop = [&]() { fpuTop_ = (fpuTop_ + 1) & 7; };
    auto readSt = [&](int i) {
        ValueId v = regs_->readFamily(stReg(i), 8);
        if (typeOf(v).isFloat()) return v;
        return fn_->cast(cur_, Op::Bitcast, ir::kF64, v, addr_);
    };
    auto memFloat = [&](const Operand& op) {
        Type ft = op.size == 4 ? ir::kF32 : ir::kF64;
        ValueId v = fn_->load(cur_, ft, effectiveAddress(in, op), addr_);
        return ft.bits == 32 ? fn_->cast(cur_, Op::FPExt, ir::kF64, v, addr_) : v;
    };
    auto operandValue = [&]() -> ValueId {
        if (in.numOps == 0) return readSt(1);
        if (in.ops[0].isMem()) return memFloat(in.ops[0]);
        return readSt((int)((int)regFamily(in.ops[0].reg) - (int)Family::F_ST0 - fpuTop_) & 7);
    };
    switch (in.mnem) {
    case Mnem::Fld: push(operandValue()); return true;
    case Mnem::Fld1: push(fn_->constInt(cur_, ir::kF64, 0x3FF0000000000000ull, addr_)); return true;
    case Mnem::Fldz: push(fn_->constInt(cur_, ir::kF64, 0, addr_)); return true;
    case Mnem::Fild: {
        ValueId iv = fn_->load(cur_, intTypeForBytes(in.ops[0].size), effectiveAddress(in, in.ops[0]), addr_);
        push(fn_->cast(cur_, Op::SIToFP, ir::kF64, iv, addr_));
        return true;
    }
    case Mnem::Fst:
    case Mnem::Fstp: {
        ValueId v = readSt(0);
        if (in.numOps && in.ops[0].isMem()) {
            Type ft = in.ops[0].size == 4 ? ir::kF32 : ir::kF64;
            ValueId sv = ft.bits == 32 ? fn_->cast(cur_, Op::FPTrunc, ft, v, addr_) : v;
            fn_->store(cur_, effectiveAddress(in, in.ops[0]), sv, addr_);
        } else if (in.numOps) {
            regs_->writeFamily(regFamily(in.ops[0].reg), 8, 0, v);
        }
        if (in.mnem == Mnem::Fstp) pop();
        return true;
    }
    case Mnem::Fist:
    case Mnem::Fistp:
    case Mnem::Fisttp: {
        ValueId v = readSt(0);
        ValueId iv = fn_->cast(cur_, Op::FPToSI, intTypeForBytes(in.ops[0].size), v, addr_);
        fn_->store(cur_, effectiveAddress(in, in.ops[0]), iv, addr_);
        if (in.mnem != Mnem::Fist) pop();
        return true;
    }
    case Mnem::Fadd: case Mnem::Faddp: case Mnem::Fsub: case Mnem::Fsubp:
    case Mnem::Fsubr: case Mnem::Fsubrp: case Mnem::Fmul: case Mnem::Fmulp:
    case Mnem::Fdiv: case Mnem::Fdivp: case Mnem::Fdivr: case Mnem::Fdivrp: {
        bool popping = in.mnem == Mnem::Faddp || in.mnem == Mnem::Fsubp || in.mnem == Mnem::Fsubrp ||
                       in.mnem == Mnem::Fmulp || in.mnem == Mnem::Fdivp || in.mnem == Mnem::Fdivrp;
        bool reverse = in.mnem == Mnem::Fsubr || in.mnem == Mnem::Fsubrp || in.mnem == Mnem::Fdivr ||
                       in.mnem == Mnem::Fdivrp;
        Op op = Op::FAdd;
        if (in.mnem == Mnem::Fsub || in.mnem == Mnem::Fsubp || in.mnem == Mnem::Fsubr || in.mnem == Mnem::Fsubrp)
            op = Op::FSub;
        else if (in.mnem == Mnem::Fmul || in.mnem == Mnem::Fmulp) op = Op::FMul;
        else if (in.mnem == Mnem::Fdiv || in.mnem == Mnem::Fdivp || in.mnem == Mnem::Fdivr || in.mnem == Mnem::Fdivrp)
            op = Op::FDiv;
        ValueId dst, src;
        int dstIndex = 0;
        if (popping || in.numOps == 0) {
            dst = readSt(1);
            src = readSt(0);
            dstIndex = 1;
        } else if (in.ops[0].isMem()) {
            dst = readSt(0);
            src = memFloat(in.ops[0]);
        } else {
            dst = readSt(0);
            src = operandValue();
        }
        ValueId r = reverse ? fn_->binary(cur_, op, ir::kF64, src, dst, addr_)
                            : fn_->binary(cur_, op, ir::kF64, dst, src, addr_);
        regs_->writeFamily(stReg(dstIndex), 8, 0, r);
        if (popping) pop();
        return true;
    }
    case Mnem::Fchs: regs_->writeFamily(stReg(0), 8, 0, fn_->unary(cur_, Op::FNeg, ir::kF64, readSt(0), addr_)); return true;
    case Mnem::Fabs: regs_->writeFamily(stReg(0), 8, 0, fn_->unary(cur_, Op::FAbs, ir::kF64, readSt(0), addr_)); return true;
    case Mnem::Fsqrt: regs_->writeFamily(stReg(0), 8, 0, fn_->unary(cur_, Op::FSqrt, ir::kF64, readSt(0), addr_)); return true;
    case Mnem::Fxch: {
        int other = in.numOps ? (((int)regFamily(in.ops[0].reg) - (int)Family::F_ST0 - fpuTop_) & 7) : 1;
        ValueId a = readSt(0), b = readSt(other);
        regs_->writeFamily(stReg(0), 8, 0, b);
        regs_->writeFamily(stReg(other), 8, 0, a);
        return true;
    }
    case Mnem::Fcomi: case Mnem::Fcomip: case Mnem::Fucomi: case Mnem::Fucomip: {
        ValueId a = readSt(0);
        ValueId b = operandValue();
        flags_.clear();
        flags_.op = FlagOp::Explicit;
        setFlagBit(ir::FlagZF, fn_->binary(cur_, Op::FCmpEq, ir::kI1, a, b, addr_));
        setFlagBit(ir::FlagCF, fn_->binary(cur_, Op::FCmpLt, ir::kI1, a, b, addr_));
        setFlagBit(ir::FlagPF, fn_->binary(cur_, Op::FCmpUno, ir::kI1, a, b, addr_));
        if (in.mnem == Mnem::Fcomip || in.mnem == Mnem::Fucomip) pop();
        return true;
    }
    case Mnem::Fcom: case Mnem::Fcomp: case Mnem::Fcompp:
    case Mnem::Fucom: case Mnem::Fucomp: case Mnem::Fucompp: {
        ValueId a = readSt(0);
        ValueId b = operandValue();
        ValueId sw = intrinsic("fpu_compare", ir::kI16, {a, b});
        regs_->writeFamily(Family::F_FPSW, 2, 0, sw);
        if (in.mnem == Mnem::Fcomp || in.mnem == Mnem::Fucomp) pop();
        if (in.mnem == Mnem::Fcompp || in.mnem == Mnem::Fucompp) { pop(); pop(); }
        return true;
    }
    case Mnem::Fnstsw: case Mnem::Fstsw: {
        ValueId sw = regs_->readFamily(Family::F_FPSW, 2);
        if (in.numOps && in.ops[0].isReg()) regs_->writeFamily(regFamily(in.ops[0].reg), 2, 0, sw);
        else if (in.numOps) fn_->store(cur_, effectiveAddress(in, in.ops[0]), sw, addr_);
        return true;
    }
    case Mnem::Frndint:
        regs_->writeFamily(stReg(0), 8, 0, intrinsic("round_to_int", ir::kF64, {readSt(0)}));
        return true;
    case Mnem::Fldcw: case Mnem::Fnstcw: case Mnem::Fninit: case Mnem::Fwait: case Mnem::Ffree:
        return true; // control-word handling has no effect on recovered values
    default:
        return false;
    }
}

// --- stack, strings, miscellaneous -----------------------------------------

bool Lifter::liftStack(const Instruction& in) {
    unsigned ps = pointerBytes();
    switch (in.mnem) {
    case Mnem::Push: {
        ValueId v = readOperand(in, 0);
        pushValue(v);
        return true;
    }
    case Mnem::Pop: {
        ValueId v = popValue(intTypeForBytes(ps));
        writeOperand(in, 0, emitTruncTo(v, in.ops[0].size ? in.ops[0].size : ps));
        return true;
    }
    case Mnem::Leave: {
        // mov rsp, rbp ; pop rbp
        i64 d;
        Family bp = Family::F_RBP;
        if (regs_->stackRelative(bp, d)) {
            spDelta_ = d;
            regs_->setStackRelative(Family::F_RSP, spDelta_);
        } else {
            regs_->writeFamily(Family::F_RSP, ps, 0, regs_->readFamily(bp, ps));
            spKnown_ = false;
        }
        ValueId v = popValue(intTypeForBytes(ps));
        regs_->writeFamily(bp, ps, 0, v);
        return true;
    }
    case Mnem::Enter: {
        pushValue(regs_->readFamily(Family::F_RBP, ps));
        regs_->writeFamily(Family::F_RBP, ps, 0, emitTruncTo(stackAddr(spDelta_), ps));
        regs_->setStackRelative(Family::F_RBP, spDelta_);
        if (in.numOps && in.ops[0].isImm()) adjustStack(-(i64)in.ops[0].imm);
        return true;
    }
    case Mnem::Pushfd:
    case Mnem::Pushfq: {
        ValueId v = intrinsic("read_flags", intTypeForBytes(ps), {});
        pushValue(v);
        return true;
    }
    case Mnem::Popfd:
    case Mnem::Popfq: {
        ValueId v = popValue(intTypeForBytes(ps));
        intrinsic("write_flags", Type::voidTy(), {v}, true);
        setFlagsUnknown(kFlagsArith | flagBit(ir::FlagDF));
        return true;
    }
    default:
        return false;
    }
}

bool Lifter::liftStringOp(const Instruction& in) {
    unsigned ps = pointerBytes();
    unsigned esz = 0;
    const char* base = nullptr;
    switch (in.mnem) {
    case Mnem::Movsb: esz = 1; base = "movs"; break;
    case Mnem::Movsw: esz = 2; base = "movs"; break;
    case Mnem::MovsdStr: esz = 4; base = "movs"; break;
    case Mnem::Movsq: esz = 8; base = "movs"; break;
    case Mnem::Stosb: esz = 1; base = "stos"; break;
    case Mnem::Stosw: esz = 2; base = "stos"; break;
    case Mnem::Stosd: esz = 4; base = "stos"; break;
    case Mnem::Stosq: esz = 8; base = "stos"; break;
    case Mnem::Lodsb: esz = 1; base = "lods"; break;
    case Mnem::Lodsw: esz = 2; base = "lods"; break;
    case Mnem::Lodsd: esz = 4; base = "lods"; break;
    case Mnem::Lodsq: esz = 8; base = "lods"; break;
    case Mnem::Scasb: esz = 1; base = "scas"; break;
    case Mnem::Scasw: esz = 2; base = "scas"; break;
    case Mnem::Scasd: esz = 4; base = "scas"; break;
    case Mnem::Scasq: esz = 8; base = "scas"; break;
    case Mnem::Cmpsb: esz = 1; base = "cmps"; break;
    case Mnem::Cmpsw: esz = 2; base = "cmps"; break;
    case Mnem::CmpsdStr: esz = 4; base = "cmps"; break;
    case Mnem::Cmpsq: esz = 8; base = "cmps"; break;
    default: return false;
    }
    Type et = intTypeForBytes(esz);
    bool rep = (in.prefixes & (PrefixRep | PrefixRepne)) != 0;
    ValueId si = regs_->readFamily(Family::F_RSI, ps);
    ValueId di = regs_->readFamily(Family::F_RDI, ps);
    ValueId ax = regs_->readFamily(Family::F_RAX, esz);

    if (rep) {
        // A repeated string operation becomes one bulk intrinsic; the pointer
        // and counter updates it implies are modelled explicitly.
        ValueId cnt = regs_->readFamily(Family::F_RCX, ps);
        std::string name = std::string("rep_") + base + std::to_string(esz * 8);
        std::vector<ValueId> args;
        if (std::strcmp(base, "movs") == 0) args = {di, si, cnt};
        else if (std::strcmp(base, "stos") == 0) args = {di, ax, cnt};
        else if (std::strcmp(base, "lods") == 0) args = {si, cnt};
        else if (std::strcmp(base, "scas") == 0) args = {di, ax, cnt};
        else args = {di, si, cnt};
        ValueId r = intrinsic(name.c_str(), intTypeForBytes(ps), args, true);
        ValueId bytes = bin(Op::Mul, cnt, konst(intTypeForBytes(ps), esz));
        if (std::strcmp(base, "movs") == 0 || std::strcmp(base, "cmps") == 0) {
            regs_->writeFamily(Family::F_RSI, ps, 0, bin(Op::Add, si, bytes));
            regs_->writeFamily(Family::F_RDI, ps, 0, bin(Op::Add, di, bytes));
        } else if (std::strcmp(base, "lods") == 0) {
            regs_->writeFamily(Family::F_RSI, ps, 0, bin(Op::Add, si, bytes));
        } else {
            regs_->writeFamily(Family::F_RDI, ps, 0, bin(Op::Add, di, bytes));
        }
        regs_->writeFamily(Family::F_RCX, ps, 0, konst(intTypeForBytes(ps), 0));
        if (std::strcmp(base, "scas") == 0 || std::strcmp(base, "cmps") == 0)
            setFlagsUnknown(kFlagsArith);
        (void)r;
        return true;
    }
    // Single step. DF is assumed clear, which is the ABI-required state.
    ValueId step = konst(intTypeForBytes(ps), esz);
    if (std::strcmp(base, "movs") == 0) {
        fn_->store(cur_, di, fn_->load(cur_, et, si, addr_), addr_);
        regs_->writeFamily(Family::F_RSI, ps, 0, bin(Op::Add, si, step));
        regs_->writeFamily(Family::F_RDI, ps, 0, bin(Op::Add, di, step));
    } else if (std::strcmp(base, "stos") == 0) {
        fn_->store(cur_, di, ax, addr_);
        regs_->writeFamily(Family::F_RDI, ps, 0, bin(Op::Add, di, step));
    } else if (std::strcmp(base, "lods") == 0) {
        regs_->writeFamily(Family::F_RAX, esz, 0, fn_->load(cur_, et, si, addr_));
        regs_->writeFamily(Family::F_RSI, ps, 0, bin(Op::Add, si, step));
    } else if (std::strcmp(base, "scas") == 0) {
        ValueId m = fn_->load(cur_, et, di, addr_);
        setFlagsSub(ax, m, bin(Op::Sub, ax, m));
        regs_->writeFamily(Family::F_RDI, ps, 0, bin(Op::Add, di, step));
    } else {
        ValueId a = fn_->load(cur_, et, si, addr_);
        ValueId b = fn_->load(cur_, et, di, addr_);
        setFlagsSub(a, b, bin(Op::Sub, a, b));
        regs_->writeFamily(Family::F_RSI, ps, 0, bin(Op::Add, si, step));
        regs_->writeFamily(Family::F_RDI, ps, 0, bin(Op::Add, di, step));
    }
    return true;
}

bool Lifter::liftMisc(const Instruction& in) {
    switch (in.mnem) {
    case Mnem::Nop:
    case Mnem::Pause:
    case Mnem::Endbr64:
    case Mnem::Endbr32:
    case Mnem::Lfence:
    case Mnem::Mfence:
    case Mnem::Sfence:
    case Mnem::Prefetcht0:
    case Mnem::Prefetcht1:
    case Mnem::Prefetcht2:
    case Mnem::Prefetchnta:
    case Mnem::Prefetchw:
    case Mnem::Vzeroupper:
        return true;
    case Mnem::Clc: setFlagBit(ir::FlagCF, boolConst(false)); return true;
    case Mnem::Stc: setFlagBit(ir::FlagCF, boolConst(true)); return true;
    case Mnem::Cmc: setFlagBit(ir::FlagCF, bin(Op::Xor, flagBitValue(ir::FlagCF), boolConst(true))); return true;
    case Mnem::Cld: setFlagBit(ir::FlagDF, boolConst(false)); return true;
    case Mnem::Std: setFlagBit(ir::FlagDF, boolConst(true)); return true;
    case Mnem::Lahf: {
        ValueId v = intrinsic("read_flags", ir::kI8, {});
        regs_->writeFamily(Family::F_RAX, 1, 1, v);
        return true;
    }
    case Mnem::Sahf: {
        intrinsic("write_flags", Type::voidTy(), {regs_->readFamily(Family::F_RAX, 1, 1)}, true);
        setFlagsUnknown(kFlagsArith);
        return true;
    }
    case Mnem::Cpuid: {
        ValueId leaf = regs_->readFamily(Family::F_RAX, 4);
        for (Family f : {Family::F_RAX, Family::F_RBX, Family::F_RCX, Family::F_RDX})
            regs_->writeFamily(f, 4, 0, intrinsic("cpuid", ir::kI32, {leaf}, true));
        return true;
    }
    case Mnem::Rdtsc: {
        ValueId v = intrinsic("rdtsc", ir::kI64, {}, true);
        regs_->writeFamily(Family::F_RAX, 4, 0, emitTruncTo(v, 4));
        regs_->writeFamily(Family::F_RDX, 4, 0, emitTruncTo(emitShiftRightConst(v, 32), 4));
        return true;
    }
    case Mnem::Int3:
    case Mnem::Ud2:
    case Mnem::Hlt:
    case Mnem::Int:
        intrinsic(in.mnem == Mnem::Ud2 ? "trap" : "debug_break", Type::voidTy(), {}, true);
        return true;
    case Mnem::Syscall:
        intrinsic("syscall", Type::voidTy(), {}, true);
        clobberCallRegisters();
        return true;
    default:
        return false;
    }
}

void Lifter::clobberCallRegisters() {
    for (size_t i = 0; i < (size_t)Family::Count; ++i) {
        Family f = (Family)i;
        if (!isVolatileFamily(f, is64_)) continue;
        unsigned w = familyWidth(f);
        regs_->writeFamily(f, w, 0, undef(intTypeForBytes(w)));
        regs_->clearStackRelative(f);
    }
    setFlagsUnknown(kFlagsArith | flagBit(ir::FlagDF));
}

void Lifter::liftCall(const Instruction& in, const CallSite* cs) {
    unsigned ps = pointerBytes();
    CalleeSignature sig;
    const pe::Import* imp = cs ? cs->import : nullptr;
    bool direct = in.flow == Flow::Call || in.flow == Flow::Jump;
    u64 target = direct ? in.target : (cs ? cs->target : 0);
    if (opt_.resolveCallee) opt_.resolveCallee(target, imp, sig);
    if (!sig.known) {
        sig.conv = opt_.convention != CallConv::Unknown ? opt_.convention : defaultConvention(is64_);
        sig.returnType = intTypeForBytes(ps);
    }
    ConventionInfo ci = conventionInfo(sig.conv == CallConv::Unknown ? defaultConvention(is64_) : sig.conv, is64_);
    // With no signature, the arguments are whatever the caller set up. Without
    // this an indirect call would appear to take none at all.
    if (!sig.known) {
        std::vector<bool> floatArg;
        std::vector<unsigned> argWidths;
        unsigned n = guessArgumentCount(in, ci, floatArg, argWidths);
        for (unsigned i = 0; i < n; ++i)
            sig.paramTypes.push_back(floatArg[i] ? ir::kF64 : intTypeForBytes(argWidths[i]));
    }

    auto callInfo = std::make_unique<ir::CallInfo>();
    callInfo->target = target;
    callInfo->isImport = imp != nullptr;
    callInfo->noReturn = sig.noReturn || (cs && cs->noReturn);
    callInfo->variadic = sig.variadic;
    callInfo->returnType = sig.returnType;
    callInfo->paramTypes = sig.paramTypes;
    if (imp) callInfo->name = imp->displayName();
    else if (!sig.name.empty()) callInfo->name = sig.name;
    else if (target) callInfo->name = prog_.nameForAddress(target);

    std::vector<ValueId> args;
    size_t intIdx = 0, fltIdx = 0, stackIdx = 0;
    for (size_t i = 0; i < sig.paramTypes.size(); ++i) {
        Type pt = sig.paramTypes[i];
        bool useFloat = pt.isFloat();
        ValueId v = kNoValue;
        size_t pos = ci.positionalFloatRegs ? i : (useFloat ? fltIdx : intIdx);
        if (useFloat && pos < ci.floatArgRegs.size()) {
            Family f = xmmFamily(ci.floatArgRegs[pos]);
            ValueId raw = regs_->readFamily(f, pt.bytes());
            v = typeOf(raw) == pt ? raw : fn_->cast(cur_, Op::Bitcast, pt, emitTruncTo(raw, pt.bytes()), addr_);
            ++fltIdx;
        } else if (!useFloat && pos < ci.intArgRegs.size()) {
            v = emitTruncTo(regs_->readFamily(ci.intArgRegs[pos], ps), std::min<unsigned>(pt.bytes(), ps));
            ++intIdx;
        } else {
            // At the call the return address has not been pushed yet, so the
            // callee's first stack slot sits one pointer below where it will
            // appear in the callee's own frame.
            i64 off = spDelta_ + (ci.stackArgStart - (i64)ps) + (i64)stackIdx * ps;
            ++stackIdx;
            ValueId a = spKnown_ ? stackAddr(off) : bin(Op::Add, regs_->readFamily(Family::F_RSP, ps), konst(intTypeForBytes(ps), (u64)(off - spDelta_)));
            v = fn_->load(cur_, pt, a, addr_);
        }
        args.push_back(v);
        callInfo->argNotes.push_back(pt.str());
    }

    ir::Inst call;
    call.op = Op::Call;
    call.type = sig.returnType;
    call.args = std::move(args);
    call.addr = addr_;
    if (!direct && !imp) {
        ValueId t = in.ops[0].isMem() ? fn_->load(cur_, ptrType(), effectiveAddress(in, in.ops[0]), addr_)
                                      : emitZExtTo(readOperand(in, 0), ps);
        callInfo->indirectTarget = t;
        call.args.insert(call.args.begin(), t);
        call.aux = 1; // first operand is the callee
    } else if (imp && !direct) {
        callInfo->name = imp->displayName();
    }
    call.call = std::move(callInfo);
    ValueId result = fn_->add(cur_, std::move(call));

    clobberCallRegisters();
    // The callee's return value lands in the convention's return register.
    if (!sig.returnType.isVoid()) {
        if (sig.returnType.isFloat()) regs_->writeFamily(xmmFamily(0), sig.returnType.bytes(), 0, result);
        else regs_->writeFamily(ci.intReturn, std::min<unsigned>(sig.returnType.bytes(), ps), 0, result);
    }
    // Stack discipline: the pushed return address is removed by the callee's
    // ret, and callee-cleanup conventions also drop the stack arguments.
    if (sig.stackBytesCleaned) adjustStack((i64)sig.stackBytesCleaned);
}

void Lifter::liftInstruction(const Instruction& in) {
    addr_ = in.address;
    if (in.mnem == Mnem::Unknown) {
        unsupported(in);
        return;
    }
    if (liftDataMovement(in)) return;
    if (liftArithmetic(in)) return;
    if (liftLogic(in)) return;
    if (liftShift(in)) return;
    if (liftMulDiv(in)) return;
    if (liftBits(in)) return;
    if (liftStack(in)) return;
    if (liftPacked(in)) return;
    if (liftSse(in)) return;
    if (liftX87(in)) return;
    if (liftStringOp(in)) return;
    if (liftMisc(in)) return;
    // Control flow is handled by the terminator emitter.
    switch (in.mnem) {
    case Mnem::Jmp: case Mnem::Call: case Mnem::Ret: case Mnem::Retf:
    case Mnem::Jcxz: case Mnem::Jecxz: case Mnem::Jrcxz:
    case Mnem::Loop: case Mnem::Loope: case Mnem::Loopne:
        return;
    default:
        break;
    }
    if (in.mnem >= Mnem::Jo && in.mnem <= Mnem::Jg) return;
    unsupported(in);
}

// ---------------------------------------------------------------------------
// Block plumbing
// ---------------------------------------------------------------------------

namespace {

// Conservative test for whether an instruction writes a register family.
bool instWritesFamily(const Instruction& in, Family fam) {
    if (fam == Family::None) return false;
    switch (in.mnem) {
    case Mnem::Cmp: case Mnem::Test: case Mnem::Push: case Mnem::Nop: case Mnem::Bt:
    case Mnem::Jmp: case Mnem::Ret: case Mnem::Retf:
        break;
    default:
        if (in.numOps >= 1 && in.ops[0].isReg() && regFamily(in.ops[0].reg) == fam) return true;
        if (in.mnem == Mnem::Xchg && in.numOps == 2 && in.ops[1].isReg() && regFamily(in.ops[1].reg) == fam)
            return true;
        break;
    }
    switch (in.mnem) {
    case Mnem::Mul: case Mnem::Div: case Mnem::Idiv: case Mnem::Cdq: case Mnem::Cqo: case Mnem::Cwd:
        return fam == Family::F_RAX || fam == Family::F_RDX;
    case Mnem::Imul:
        return in.numOps == 1 && (fam == Family::F_RAX || fam == Family::F_RDX);
    case Mnem::Cdqe: case Mnem::Cwde: case Mnem::Cbw:
        return fam == Family::F_RAX;
    case Mnem::Push: case Mnem::Pop: case Mnem::Enter:
        return fam == Family::F_RSP;
    case Mnem::Leave:
        return fam == Family::F_RSP || fam == Family::F_RBP;
    case Mnem::Movsb: case Mnem::Movsw: case Mnem::MovsdStr: case Mnem::Movsq:
    case Mnem::Stosb: case Mnem::Stosw: case Mnem::Stosd: case Mnem::Stosq:
    case Mnem::Lodsb: case Mnem::Lodsw: case Mnem::Lodsd: case Mnem::Lodsq:
    case Mnem::Scasb: case Mnem::Scasw: case Mnem::Scasd: case Mnem::Scasq:
    case Mnem::Cmpsb: case Mnem::Cmpsw: case Mnem::CmpsdStr: case Mnem::Cmpsq:
        return fam == Family::F_RSI || fam == Family::F_RDI || fam == Family::F_RCX;
    default:
        return false;
    }
}

// True when `in` changes anything the operands of `def` read, which would make
// re-evaluating `def` later produce a different result than the flags hold.
bool clobbersOperandsOf(const Instruction& def, const Instruction& in) {
    if (&def == &in) return false;
    if (in.isCall()) return true;
    bool defReadsMemory = false;
    std::vector<Family> needed;
    for (unsigned i = 0; i < def.numOps; ++i) {
        const Operand& op = def.ops[i];
        if (op.isReg()) needed.push_back(regFamily(op.reg));
        else if (op.isMem()) {
            defReadsMemory = true;
            if (op.mem.base != Reg::None) needed.push_back(regFamily(op.mem.base));
            if (op.mem.index != Reg::None) needed.push_back(regFamily(op.mem.index));
        }
    }
    // Any store may change what a memory operand would read.
    if (defReadsMemory) {
        for (unsigned i = 0; i < in.numOps; ++i)
            if (in.ops[i].isMem() && i == 0 && in.mnem != Mnem::Cmp && in.mnem != Mnem::Test) return true;
        switch (in.mnem) {
        case Mnem::Push: case Mnem::Movsb: case Mnem::Movsw: case Mnem::MovsdStr: case Mnem::Movsq:
        case Mnem::Stosb: case Mnem::Stosw: case Mnem::Stosd: case Mnem::Stosq:
            return true;
        default:
            break;
        }
    }
    for (Family f : needed)
        if (instWritesFamily(in, f)) return true;
    return false;
}

} // namespace

// Propagates the stack pointer, and every register holding a frame address,
// through the machine CFG. Without this a function using rbp as a frame
// pointer would only resolve [rbp-N] inside the block that set rbp up.
void Lifter::computeStackDeltas() {
    size_t n = mf_.blocks.size();
    blockEntrySp_.assign(n, 0);
    blockSpKnown_.assign(n, 0);
    blockFrameRegs_.assign(n, {});
    unsigned ps = pointerBytes();
    Reg spReg = is64_ ? Reg::RSP : Reg::ESP;

    struct State {
        bool spKnown = false;
        i64 sp = 0;
        std::map<Family, i64> frameRegs;
        bool operator==(const State& o) const {
            return spKnown == o.spKnown && sp == o.sp && frameRegs == o.frameRegs;
        }
    };
    std::vector<State> entry(n), exitState(n);
    std::vector<char> hasEntry(n, 0), hasExit(n, 0);
    entry[0].spKnown = true;
    entry[0].sp = 0;
    hasEntry[0] = 1;

    auto transfer = [&](size_t bi, State st) {
        for (const auto& in : mf_.blocks[bi].insns) {
            auto frameOf = [&](Reg r, i64& out) {
                if (r == Reg::None) return false;
                if (regSize(r) != ps) return false;
                Family f = regFamily(r);
                if (f == Family::F_RSP) {
                    if (!st.spKnown) return false;
                    out = st.sp;
                    return true;
                }
                auto it = st.frameRegs.find(f);
                if (it == st.frameRegs.end()) return false;
                out = it->second;
                return true;
            };
            auto setFrame = [&](Reg r, i64 v) {
                Family f = regFamily(r);
                if (f == Family::F_RSP) { st.sp = v; st.spKnown = true; }
                else st.frameRegs[f] = v;
            };
            auto clearFrame = [&](Family f) {
                if (f == Family::F_RSP) st.spKnown = false;
                else st.frameRegs.erase(f);
            };
            switch (in.mnem) {
            case Mnem::Push: st.sp -= ps; continue;
            case Mnem::Pushfd: case Mnem::Pushfq: st.sp -= ps; continue;
            case Mnem::Pop:
                st.sp += ps;
                if (in.numOps && in.ops[0].isReg()) clearFrame(regFamily(in.ops[0].reg));
                continue;
            case Mnem::Popfd: case Mnem::Popfq: st.sp += ps; continue;
            case Mnem::Leave: {
                i64 v;
                if (frameOf(is64_ ? Reg::RBP : Reg::EBP, v)) { st.sp = v + ps; st.spKnown = true; }
                else st.spKnown = false;
                st.frameRegs.erase(Family::F_RBP);
                continue;
            }
            case Mnem::Enter:
                st.frameRegs[Family::F_RBP] = st.sp - (i64)ps;
                st.sp -= (i64)ps + (in.numOps && in.ops[0].isImm() ? in.ops[0].imm : 0);
                continue;
            case Mnem::Add:
            case Mnem::Sub: {
                if (in.numOps != 2 || !in.ops[0].isReg()) break;
                i64 sign = in.mnem == Mnem::Add ? 1 : -1;
                i64 cur;
                if (in.ops[1].isImm() && frameOf(in.ops[0].reg, cur)) {
                    setFrame(in.ops[0].reg, cur + sign * in.ops[1].imm);
                    continue;
                }
                clearFrame(regFamily(in.ops[0].reg));
                continue;
            }
            case Mnem::Mov: {
                if (in.numOps != 2 || !in.ops[0].isReg()) break;
                i64 v;
                if (in.ops[1].isReg() && frameOf(in.ops[1].reg, v) && regSize(in.ops[0].reg) == ps) {
                    setFrame(in.ops[0].reg, v);
                    continue;
                }
                clearFrame(regFamily(in.ops[0].reg));
                continue;
            }
            case Mnem::Lea: {
                if (in.numOps != 2 || !in.ops[0].isReg() || !in.ops[1].isMem()) break;
                const MemOperand& m = in.ops[1].mem;
                i64 v;
                if (m.index == Reg::None && m.base != Reg::None && frameOf(m.base, v) &&
                    regSize(in.ops[0].reg) == ps) {
                    setFrame(in.ops[0].reg, v + m.disp);
                    continue;
                }
                clearFrame(regFamily(in.ops[0].reg));
                continue;
            }
            case Mnem::And:
                // Stack realignment makes the offset unknowable.
                if (in.numOps == 2 && in.ops[0].isReg(spReg)) st.spKnown = false;
                else if (in.numOps >= 1 && in.ops[0].isReg()) clearFrame(regFamily(in.ops[0].reg));
                continue;
            case Mnem::Xchg:
                if (in.numOps == 2) {
                    if (in.ops[0].isReg()) clearFrame(regFamily(in.ops[0].reg));
                    if (in.ops[1].isReg()) clearFrame(regFamily(in.ops[1].reg));
                }
                continue;
            default:
                break;
            }
            if (in.isCall()) {
                // Volatile registers do not survive a call.
                for (auto it = st.frameRegs.begin(); it != st.frameRegs.end();)
                    it = isVolatileFamily(it->first, is64_) ? st.frameRegs.erase(it) : std::next(it);
                continue;
            }
            // Anything else that writes a tracked register invalidates it.
            for (auto it = st.frameRegs.begin(); it != st.frameRegs.end();)
                it = instWritesFamily(in, it->first) ? st.frameRegs.erase(it) : std::next(it);
            if (instWritesFamily(in, Family::F_RSP)) st.spKnown = false;
        }
        return st;
    };

    // Reverse post-order converges fastest, and a predecessor whose exit is
    // not yet known must be ignored rather than treated as holding nothing:
    // this is a must-analysis, so an unknown predecessor would wrongly erase
    // every fact at the merge.
    Digraph g((int)n);
    g.entry = 0;
    for (size_t i = 0; i < n; ++i)
        for (const auto& e : mf_.blocks[i].succs)
            if (e.target >= 0) g.addEdge((int)i, e.target);
    std::vector<int> order = reversePostOrder(g);
    for (size_t i = 0; i < n; ++i)
        if (std::find(order.begin(), order.end(), (int)i) == order.end()) order.push_back((int)i);

    for (int round = 0; round < 32; ++round) {
        bool changed = false;
        for (int i : order) {
            if (!hasEntry[i]) continue;
            State out = transfer(i, entry[i]);
            if (!hasExit[i] || !(out == exitState[i])) {
                exitState[i] = out;
                hasExit[i] = 1;
                changed = true;
            }
        }
        for (int i : order) {
            State merged;
            bool first = true;
            bool any = false;
            for (int p : mf_.blocks[i].preds) {
                if (!hasExit[p]) continue;
                any = true;
                const State& e = exitState[p];
                if (first) {
                    merged = e;
                    first = false;
                    continue;
                }
                if (merged.sp != e.sp || !e.spKnown) merged.spKnown = merged.spKnown && e.spKnown && merged.sp == e.sp;
                // Keep only the frame registers every predecessor agrees on.
                for (auto it = merged.frameRegs.begin(); it != merged.frameRegs.end();) {
                    auto o = e.frameRegs.find(it->first);
                    it = (o == e.frameRegs.end() || o->second != it->second) ? merged.frameRegs.erase(it)
                                                                             : std::next(it);
                }
            }
            if (i == 0) {
                merged = State{};
                merged.spKnown = true;
                any = true;
            }
            if (!any) continue;
            if (!hasEntry[i] || !(entry[i] == merged)) {
                entry[i] = merged;
                hasEntry[i] = 1;
                changed = true;
            }
        }
        if (!changed) break;
    }
    for (size_t i = 0; i < n; ++i) {
        blockEntrySp_[i] = entry[i].sp;
        blockSpKnown_[i] = entry[i].spKnown ? 1 : 0;
        blockFrameRegs_[i] = entry[i].frameRegs;
    }
}

// Which registers are written on every path from the entry to each block.
// A call whose signature is unknown still has arguments, and the registers
// the caller set up are the only evidence of how many.
void Lifter::computeDefinedRegs() {
    size_t n = mf_.blocks.size();
    blockDefinedGpr_.assign(n, 0);
    blockDefinedXmm_.assign(n, 0);
    std::vector<u32> outGpr(n, 0), outXmm(n, 0);
    std::vector<char> hasOut(n, 0), hasIn(n, 0);
    hasIn[0] = 1;

    auto writesIn = [&](size_t bi, u32& gpr, u32& xmm) {
        for (const auto& in : mf_.blocks[bi].insns) {
            for (size_t fi = 0; fi < (size_t)Family::Count; ++fi) {
                Family f = (Family)fi;
                if (!instWritesFamily(in, f)) continue;
                if (isGprFamily(f)) gpr |= 1u << gprIndex(f);
                else if (isXmmFamily(f)) xmm |= 1u << xmmIndex(f);
            }
            // SSE moves write their destination register.
            if (in.numOps >= 1 && in.ops[0].isReg() && isXmmFamily(regFamily(in.ops[0].reg)))
                xmm |= 1u << xmmIndex(regFamily(in.ops[0].reg));
        }
    };

    for (int round = 0; round < 8; ++round) {
        bool changed = false;
        for (size_t i = 0; i < n; ++i) {
            if (!hasIn[i]) continue;
            u32 g = blockDefinedGpr_[i], x = blockDefinedXmm_[i];
            writesIn(i, g, x);
            if (!hasOut[i] || outGpr[i] != g || outXmm[i] != x) {
                outGpr[i] = g;
                outXmm[i] = x;
                hasOut[i] = 1;
                changed = true;
            }
        }
        for (size_t i = 0; i < n; ++i) {
            if (i == 0) continue;
            u32 g = 0xFFFFFFFFu, x = 0xFFFFFFFFu;
            bool any = false;
            for (int p : mf_.blocks[i].preds) {
                if (!hasOut[p]) continue;
                g &= outGpr[p];
                x &= outXmm[p];
                any = true;
            }
            if (!any) continue;
            if (!hasIn[i] || blockDefinedGpr_[i] != g || blockDefinedXmm_[i] != x) {
                blockDefinedGpr_[i] = g;
                blockDefinedXmm_[i] = x;
                hasIn[i] = 1;
                changed = true;
            }
        }
        if (!changed) break;
    }
}

// A function whose result is a double leaves it in xmm0 and never writes the
// integer return register. Without noticing that, the return reads rax, finds
// the value the caller passed in, and the signature comes out void.
void Lifter::computeFloatReturn() {
    floatReturn_ = false;
    bool anyReturn = false;
    for (size_t bi = 0; bi < mf_.blocks.size(); ++bi) {
        const BasicBlock& b = mf_.blocks[bi];
        if (b.term != Terminator::Return) continue;
        anyReturn = true;
        u32 gpr = bi < blockDefinedGpr_.size() ? blockDefinedGpr_[bi] : 0;
        u32 xmm = bi < blockDefinedXmm_.size() ? blockDefinedXmm_[bi] : 0;
        for (const auto& in : b.insns) {
            for (size_t fi = 0; fi < (size_t)Family::Count; ++fi) {
                Family f = (Family)fi;
                if (!instWritesFamily(in, f)) continue;
                if (isGprFamily(f)) gpr |= 1u << gprIndex(f);
                else if (isXmmFamily(f)) xmm |= 1u << xmmIndex(f);
            }
            if (in.numOps >= 1 && in.ops[0].isReg() && isXmmFamily(regFamily(in.ops[0].reg)))
                xmm |= 1u << xmmIndex(regFamily(in.ops[0].reg));
        }
        ConventionInfo ci = conventionInfo(
            opt_.convention == CallConv::Unknown ? defaultConvention(is64_) : opt_.convention, is64_);
        bool intSet = (gpr & (1u << gprIndex(ci.intReturn))) != 0;
        bool fltSet = (xmm & 1u) != 0;
        if (intSet || !fltSet) return;
    }
    floatReturn_ = anyReturn;
}

unsigned Lifter::guessArgumentCount(const Instruction& call, const ConventionInfo& ci,
                                    std::vector<bool>& isFloat, std::vector<unsigned>& widths) const {
    // Width the argument register was most recently written at, so a 32-bit
    // argument is not widened to a pointer for no reason.
    std::array<unsigned, (size_t)Family::Count> lastWidth{};
    u32 gpr = curMachine_ < (int)blockDefinedGpr_.size() ? blockDefinedGpr_[curMachine_] : 0;
    u32 xmm = curMachine_ < (int)blockDefinedXmm_.size() ? blockDefinedXmm_[curMachine_] : 0;
    // Plus anything set earlier in this block.
    for (const auto& in : mf_.blocks[curMachine_].insns) {
        if (in.address >= call.address) break;
        for (size_t fi = 0; fi < (size_t)Family::Count; ++fi) {
            Family f = (Family)fi;
            if (!instWritesFamily(in, f)) continue;
            if (isGprFamily(f)) gpr |= 1u << gprIndex(f);
            else if (isXmmFamily(f)) xmm |= 1u << xmmIndex(f);
            if (in.numOps >= 1 && in.ops[0].isReg() && regFamily(in.ops[0].reg) == f)
                lastWidth[fi] = regSize(in.ops[0].reg);
        }
        if (in.numOps >= 1 && in.ops[0].isReg() && isXmmFamily(regFamily(in.ops[0].reg)))
            xmm |= 1u << xmmIndex(regFamily(in.ops[0].reg));
    }
    isFloat.clear();
    widths.clear();
    unsigned count = 0;
    size_t maxArgs = std::max(ci.intArgRegs.size(), ci.floatArgRegs.size());
    for (size_t i = 0; i < maxArgs; ++i) {
        bool intSet = i < ci.intArgRegs.size() && (gpr & (1u << gprIndex(ci.intArgRegs[i])));
        bool fltSet = ci.positionalFloatRegs && i < ci.floatArgRegs.size() &&
                      (xmm & (1u << ci.floatArgRegs[i]));
        if (!intSet && !fltSet) break;
        isFloat.push_back(!intSet && fltSet);
        unsigned w = intSet ? lastWidth[(size_t)ci.intArgRegs[i]] : 0;
        widths.push_back(w ? w : (unsigned)pointerBytes());
        ++count;
    }

    // Stack arguments. With the argument registers used up (or a convention
    // that has none), the caller stages the rest just below the stack
    // pointer, either by writing the slots or by pushing them. Without
    // counting those an indirect call on x86 looks like it takes nothing.
    if (count == maxArgs) {
        unsigned ps = pointerBytes();
        i64 base = ci.stackArgStart - (i64)ps;   // the return address is not pushed yet
        std::set<i64> slots;
        unsigned pushes = 0;
        const auto& insns = mf_.blocks[curMachine_].insns;
        size_t at = insns.size();
        for (size_t i = 0; i < insns.size(); ++i)
            if (insns[i].address == call.address) { at = i; break; }
        bool pushRun = true;
        for (size_t k = at; k-- > 0;) {
            const Instruction& p = insns[k];
            if (p.isCall()) break;
            if (p.mnem == Mnem::Push) {
                if (pushRun) ++pushes;
                continue;
            }
            pushRun = false;
            if (p.mnem != Mnem::Mov || p.numOps != 2 || !p.ops[0].isMem()) continue;
            const MemOperand& m = p.ops[0].mem;
            if (m.index != Reg::None) continue;
            if (regFamily(m.base) != Family::F_RSP) continue;
            if (p.ops[0].size != ps) continue;
            i64 off = m.disp - base;
            if (off < 0 || off % (i64)ps) continue;
            slots.insert(off / (i64)ps);
        }
        unsigned n = 0;
        while (slots.count((i64)n)) ++n;
        if (pushes > n) n = pushes;
        for (unsigned i = 0; i < n; ++i) {
            isFloat.push_back(false);
            widths.push_back(ps);
        }
        count += n;
    }
    return count;
}

// A flag record only survives into a block when every predecessor leaves the
// same defining instruction, the flags were not clobbered, and nothing has
// changed the values that instruction compared.
void Lifter::computeFlagEntryStates() {
    size_t n = mf_.blocks.size();
    flagDefIn_.assign(n, nullptr);
    flagDefOut_.assign(n, nullptr);
    const x86::Instruction* const kConflict = (const x86::Instruction*)1;
    for (int round = 0; round < 4; ++round) {
        bool changed = false;
        for (size_t i = 0; i < n; ++i) {
            const x86::Instruction* def = flagDefIn_[i] == kConflict ? nullptr : flagDefIn_[i];
            for (const auto& in : mf_.blocks[i].insns) {
                FlagMask r, w;
                flagEffects(in, r, w);
                if (in.isCall()) def = nullptr;
                else if (w) def = &in;
                else if (def && clobbersOperandsOf(*def, in)) def = nullptr;
                // Only cmp and test can be replayed; other flag writers have
                // results that are not recoverable from the operands alone.
                if (def && def->mnem != Mnem::Cmp && def->mnem != Mnem::Test) def = nullptr;
            }
            if (flagDefOut_[i] != def) {
                flagDefOut_[i] = def;
                changed = true;
            }
        }
        for (size_t i = 0; i < n; ++i) {
            const x86::Instruction* merged = nullptr;
            bool first = true, conflict = false;
            for (int p : mf_.blocks[i].preds) {
                const x86::Instruction* d = flagDefOut_[p];
                if (first) { merged = d; first = false; }
                else if (merged != d) conflict = true;
            }
            const x86::Instruction* want = (first || conflict) ? nullptr : merged;
            if (flagDefIn_[i] != want) {
                flagDefIn_[i] = want;
                changed = true;
            }
        }
        if (!changed) break;
    }
}

void Lifter::liftBlock(int mb) {
    const BasicBlock& b = mf_.blocks[mb];
    curMachine_ = mb;
    cur_ = blockMap_[mb];
    regs_->reset();
    flags_.clear();
    fpuTop_ = 0;
    switchIndex_ = kNoValue;
    spDelta_ = blockEntrySp_[mb];
    spKnown_ = blockSpKnown_[mb] != 0;
    if (spKnown_) regs_->setStackRelative(Family::F_RSP, spDelta_);
    if (mb < (int)blockFrameRegs_.size())
        for (const auto& [fam, delta] : blockFrameRegs_[mb]) regs_->setStackRelative(fam, delta);

    // Re-evaluate the comparison that set the incoming flags so conditions in
    // this block fold to a single comparison instead of composing flag bits.
    // The operands are re-read as ordinary location reads, which SSA resolves
    // back to the same values the defining block computed.
    if (mb < (int)flagDefIn_.size() && flagDefIn_[mb]) {
        const Instruction& def = *flagDefIn_[mb];
        u64 saveAddr = addr_;
        addr_ = def.address;
        switch (def.mnem) {
        case Mnem::Cmp: {
            ValueId a = readOperand(def, 0);
            ValueId c = emitTruncTo(readOperand(def, 1), bytesOf(a));
            setFlagsSub(a, c, bin(Op::Sub, a, c));
            break;
        }
        case Mnem::Test: {
            ValueId a = readOperand(def, 0);
            ValueId c = emitTruncTo(readOperand(def, 1), bytesOf(a));
            bool same = def.ops[0].isReg() && def.ops[1].isReg() && def.ops[0].reg == def.ops[1].reg;
            setFlagsLogic(a, c, same ? a : bin(Op::And, a, c));
            break;
        }
        default:
            break;
        }
        addr_ = saveAddr;
    }

    const JumpTable* jt = b.jumpTable >= 0 ? &mf_.jumpTables[b.jumpTable] : nullptr;
    // The index register is reused for the table base further down, so it has
    // to be read at the point the slicer identified, not at the table load.
    if (jt && jt->indexFamily != Family::None) {
        // Read it at block entry first, which is right when the index was
        // computed in a predecessor. If it is computed in this block the read
        // below replaces this one, and this one becomes dead.
        addr_ = b.start;
        switchIndex_ = regs_->readFamily(jt->indexFamily, std::min<unsigned>(familyWidth(jt->indexFamily), 4));
    }
    size_t callIdx = 0;
    for (size_t i = 0; i < b.insns.size(); ++i) {
        const Instruction& in = b.insns[i];
        addr_ = in.address;
        bool last = i + 1 == b.insns.size();
        if (in.isCall()) {
            const CallSite* cs = nullptr;
            while (callIdx < b.calls.size() && b.calls[callIdx].address < in.address) ++callIdx;
            if (callIdx < b.calls.size() && b.calls[callIdx].address == in.address) cs = &b.calls[callIdx];
            liftCall(in, cs);
            continue;
        }
        if (last && (in.endsBlock() || b.term == Terminator::TailCall)) break;
        liftInstruction(in);
        if (jt && jt->indexAddress == in.address && jt->indexFamily != Family::None) {
            addr_ = in.address;
            switchIndex_ = regs_->readFamily(jt->indexFamily, std::min<unsigned>(familyWidth(jt->indexFamily), 4));
        }
    }
    emitTerminator(b);
}

void Lifter::emitTerminator(const BasicBlock& b) {
    const Instruction& in = b.last();
    addr_ = in.address;
    unsigned ps = pointerBytes();
    auto succIr = [&](int machineBlock) { return blockMap_[machineBlock]; };

    auto finish = [&](ir::Inst term, std::vector<int> succs, const std::vector<std::vector<i64>>& cases = {}, int defSucc = -1) {
        regs_->flush();
        flushFlags(flagLive_.liveOut[curMachine_]);
        term.addr = addr_;
        fn_->add(cur_, std::move(term));
        fn_->block(cur_).succs = std::move(succs);
        fn_->block(cur_).caseValues = cases;
        fn_->block(cur_).defaultSucc = defSucc;
    };
    auto returnValue = [&]() -> ValueId {
        if (opt_.returnTypeKnown && opt_.returnType.isVoid()) return kNoValue;
        ConventionInfo ci = conventionInfo(opt_.convention == CallConv::Unknown ? defaultConvention(is64_) : opt_.convention, is64_);
        // With no declared type, read the return register at the width the
        // function itself uses, so the synthetic read never widens the family.
        Type rt = opt_.returnTypeKnown ? opt_.returnType
                                       : intTypeForBytes(std::min<unsigned>(familyWidth(ci.intReturn), ps));
        if (!opt_.returnTypeKnown && floatReturn_)
            rt = familyWidth(xmmFamily(0)) == 4 ? ir::kF32 : ir::kF64;
        if (rt.isFloat()) {
            ValueId v = regs_->readFamily(xmmFamily(0), rt.bytes());
            return typeOf(v) == rt ? v : fn_->cast(cur_, Op::Bitcast, rt, emitTruncTo(v, rt.bytes()), addr_);
        }
        return emitTruncTo(regs_->readFamily(ci.intReturn, std::max<unsigned>(rt.bytes(), 1)), rt.bytes());
    };

    switch (b.term) {
    case Terminator::Fallthrough:
    case Terminator::Jump: {
        ir::Inst t;
        t.op = Op::Jump;
        std::vector<int> s;
        for (const auto& e : b.succs)
            if (e.target >= 0) s.push_back(succIr(e.target));
        if (s.empty()) {
            t.op = Op::Unreachable;
            finish(std::move(t), {});
            return;
        }
        s.resize(1);
        finish(std::move(t), std::move(s));
        return;
    }
    case Terminator::Branch: {
        ValueId c;
        if (in.mnem == Mnem::Jcxz || in.mnem == Mnem::Jecxz || in.mnem == Mnem::Jrcxz) {
            unsigned w = in.mnem == Mnem::Jrcxz ? 8 : (in.mnem == Mnem::Jecxz ? 4 : 2);
            ValueId cx = regs_->readFamily(Family::F_RCX, w);
            c = cmp(Op::CmpEq, cx, konstLike(cx, 0));
        } else if (in.mnem == Mnem::Loop || in.mnem == Mnem::Loope || in.mnem == Mnem::Loopne) {
            ValueId cx = regs_->readFamily(Family::F_RCX, ps);
            ValueId dec = bin(Op::Sub, cx, konstLike(cx, 1));
            regs_->writeFamily(Family::F_RCX, ps, 0, dec);
            c = cmp(Op::CmpNe, dec, konstLike(dec, 0));
            if (in.mnem == Mnem::Loope) c = bin(Op::And, c, flagBitValue(ir::FlagZF));
            if (in.mnem == Mnem::Loopne) c = bin(Op::And, c, bin(Op::Xor, flagBitValue(ir::FlagZF), boolConst(true)));
        } else {
            c = materializeCond(in.condition());
        }
        int t = -1, f = -1;
        for (const auto& e : b.succs) {
            if (e.kind == EdgeKind::True) t = succIr(e.target);
            else if (e.kind == EdgeKind::False) f = succIr(e.target);
        }
        if (t < 0 || f < 0) {
            ir::Inst u;
            u.op = Op::Unreachable;
            finish(std::move(u), {});
            return;
        }
        ir::Inst term;
        term.op = Op::Branch;
        term.args = {c};
        finish(std::move(term), {t, f});
        return;
    }
    case Terminator::Switch: {
        ValueId idx = switchIndex_;
        if (idx == kNoValue) idx = undef(ir::kI32);
        ir::Inst term;
        term.op = Op::Switch;
        term.args = {idx};
        std::vector<int> succs;
        std::vector<std::vector<i64>> cases;
        for (const auto& e : b.succs) {
            if (e.target < 0) continue;
            succs.push_back(succIr(e.target));
            cases.push_back(e.caseValues);
        }
        int defSucc = -1;
        const JumpTable& jt = mf_.jumpTables[b.jumpTable];
        if (jt.defaultTarget) {
            auto it = mf_.blockAt.find(jt.defaultTarget);
            if (it != mf_.blockAt.end()) {
                int d = succIr(it->second);
                if (std::find(succs.begin(), succs.end(), d) == succs.end()) {
                    succs.push_back(d);
                    cases.push_back({});
                }
                defSucc = d;
            }
        }
        finish(std::move(term), std::move(succs), cases, defSucc);
        return;
    }
    case Terminator::Return: {
        if (in.numOps >= 1 && in.ops[0].isImm()) adjustStack(in.ops[0].imm);
        ValueId rv = returnValue();
        ir::Inst term;
        term.op = Op::Return;
        if (rv != kNoValue) term.args = {rv};
        finish(std::move(term), {});
        return;
    }
    case Terminator::TailCall: {
        CallSite cs;
        cs.address = in.address;
        cs.target = b.tailTarget;
        cs.import = b.tailImport;
        cs.indirect = b.tailTarget == 0 && b.tailImport == nullptr;
        liftCall(in, &cs);
        ValueId rv = returnValue();
        ir::Inst term;
        term.op = Op::Return;
        if (rv != kNoValue) term.args = {rv};
        finish(std::move(term), {});
        return;
    }
    case Terminator::NoReturnCall: {
        ir::Inst term;
        term.op = Op::Unreachable;
        finish(std::move(term), {});
        return;
    }
    case Terminator::Halt: {
        ir::Inst term;
        term.op = Op::Unreachable;
        finish(std::move(term), {});
        return;
    }
    case Terminator::IndirectJump: {
        ValueId t = in.numOps && in.ops[0].isMem() ? fn_->load(cur_, ptrType(), effectiveAddress(in, in.ops[0]), addr_)
                    : in.numOps ? emitZExtTo(readOperand(in, 0), ps)
                                : undef(ptrType());
        intrinsic("indirect_jump", Type::voidTy(), {t}, true);
        fn_->notes().push_back(strfmt("unresolved indirect jump at %s", hex(in.address).c_str()));
        ir::Inst term;
        term.op = Op::Unreachable;
        finish(std::move(term), {});
        return;
    }
    case Terminator::DecodeError: {
        intrinsic("undecodable_bytes", Type::voidTy(), {}, true);
        fn_->notes().push_back(strfmt("undecodable bytes after %s", hex(in.address).c_str()));
        ir::Inst term;
        term.op = Op::Unreachable;
        finish(std::move(term), {});
        return;
    }
    }
}

LiftResult Lifter::run() {
    computeStackDeltas();
    computeDefinedRegs();
    computeFloatReturn();
    computeFlagEntryStates();
    blockMap_.assign(mf_.blocks.size(), -1);
    for (size_t i = 0; i < mf_.blocks.size(); ++i) blockMap_[i] = fn_->addBlock(mf_.blocks[i].start);
    for (size_t i = 0; i < mf_.blocks.size(); ++i) liftBlock((int)i);
    fn_->recomputePreds();

    LiftResult r;
    r.blockMap = blockMap_;
    r.unsupported = unsupported_;
    r.func = std::move(fn_);
    return r;
}

LiftResult liftFunction(Program& prog, const Function& f, const LiftOptions& opt) {
    Lifter l(prog, f, opt);
    return l.run();
}

} // namespace dc::lift
