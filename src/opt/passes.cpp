#include "opt/passes.h"

#include "analysis/graph.h"
#include "ssa/ssa.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <map>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace dc::opt {

using ir::Op;
using ir::Type;
using ir::ValueId;
using ir::kNoValue;

std::string Stats::print() const {
    std::ostringstream os;
    os << "optimisation: " << rounds << " rounds, " << total() << " changes"
       << "\n  constants folded:     " << constantsFolded
       << "\n  copies propagated:    " << copiesPropagated
       << "\n  algebraic rewrites:   " << algebraicSimplifications
       << "\n  branches simplified:  " << branchesSimplified
       << "\n  expressions shared:   " << expressionsShared
       << "\n  stack loads forwarded:" << loadsForwarded
       << "\n  casts removed:        " << castsRemoved
       << "\n  values narrowed:      " << valuesNarrowed
       << "\n  phis removed:         " << phisRemoved
       << "\n  instructions removed: " << instructionsRemoved << "\n";
    return os.str();
}

namespace {

bool isConst(const ir::Function& f, ValueId v, u64& out) {
    if (v == kNoValue) return false;
    const ir::Inst& in = f.inst(v);
    if (in.op != Op::Const) return false;
    out = in.imm;
    return true;
}

bool isConstEq(const ir::Function& f, ValueId v, u64 k) {
    u64 c;
    return isConst(f, v, c) && c == truncBits(k, f.inst(v).type.bits);
}

// Replaces an instruction with a copy of another value.
void replaceWith(ir::Function& f, ValueId v, ValueId with) {
    f.replaceAllUses(v, with);
    f.inst(v).dead = true;
}

void makeConst(ir::Function& f, ValueId v, u64 value) {
    ir::Inst& in = f.inst(v);
    in.op = Op::Const;
    in.imm = in.type.bits >= 64 ? value : truncBits(value, in.type.bits);
    in.args.clear();
    in.call.reset();
    in.text.clear();
}

double bitsToDouble(u64 b) {
    double d;
    std::memcpy(&d, &b, 8);
    return d;
}
float bitsToFloat(u32 b) {
    float d;
    std::memcpy(&d, &b, 4);
    return d;
}
u64 doubleToBits(double d) {
    u64 b;
    std::memcpy(&b, &d, 8);
    return b;
}
u32 floatToBits(float d) {
    u32 b;
    std::memcpy(&b, &d, 4);
    return b;
}

} // namespace

bool evalConst(Op op, Type t, u64 a, u64 b, u64& out) {
    unsigned bits = t.bits;
    u64 mask = maskBits(bits);
    auto sa = [&] { return signExtend(a, bits); };
    auto sb = [&] { return signExtend(b, bits); };
    if (t.isFloat()) {
        if (bits == 64) {
            double x = bitsToDouble(a), y = bitsToDouble(b);
            switch (op) {
            case Op::FAdd: out = doubleToBits(x + y); return true;
            case Op::FSub: out = doubleToBits(x - y); return true;
            case Op::FMul: out = doubleToBits(x * y); return true;
            case Op::FDiv: if (y == 0) return false; out = doubleToBits(x / y); return true;
            case Op::FNeg: out = doubleToBits(-x); return true;
            case Op::FAbs: out = doubleToBits(std::fabs(x)); return true;
            default: return false;
            }
        }
        if (bits == 32) {
            float x = bitsToFloat((u32)a), y = bitsToFloat((u32)b);
            switch (op) {
            case Op::FAdd: out = floatToBits(x + y); return true;
            case Op::FSub: out = floatToBits(x - y); return true;
            case Op::FMul: out = floatToBits(x * y); return true;
            case Op::FDiv: if (y == 0) return false; out = floatToBits(x / y); return true;
            case Op::FNeg: out = floatToBits(-x); return true;
            case Op::FAbs: out = floatToBits(std::fabs(x)); return true;
            default: return false;
            }
        }
        return false;
    }
    switch (op) {
    case Op::Add: out = (a + b) & mask; return true;
    case Op::Sub: out = (a - b) & mask; return true;
    case Op::Mul: out = (a * b) & mask; return true;
    case Op::And: out = a & b & mask; return true;
    case Op::Or: out = (a | b) & mask; return true;
    case Op::Xor: out = (a ^ b) & mask; return true;
    case Op::Not: out = (~a) & mask; return true;
    case Op::Neg: out = (0 - a) & mask; return true;
    case Op::UDiv: if (!b) return false; out = (a & mask) / (b & mask); return true;
    case Op::URem: if (!b) return false; out = (a & mask) % (b & mask); return true;
    case Op::SDiv: {
        i64 x = sa(), y = sb();
        if (y == 0 || (y == -1 && x == INT64_MIN)) return false;
        out = (u64)(x / y) & mask;
        return true;
    }
    case Op::SRem: {
        i64 x = sa(), y = sb();
        if (y == 0 || (y == -1 && x == INT64_MIN)) return false;
        out = (u64)(x % y) & mask;
        return true;
    }
    case Op::Shl: {
        u64 s = b & (bits - 1);
        out = (a << s) & mask;
        return true;
    }
    case Op::LShr: {
        u64 s = b & (bits - 1);
        out = ((a & mask) >> s) & mask;
        return true;
    }
    case Op::AShr: {
        u64 s = b & (bits - 1);
        out = (u64)(sa() >> s) & mask;
        return true;
    }
    case Op::Rol: {
        unsigned s = (unsigned)(b & (bits - 1));
        if (!s) { out = a & mask; return true; }
        out = (((a & mask) << s) | ((a & mask) >> (bits - s))) & mask;
        return true;
    }
    case Op::Ror: {
        unsigned s = (unsigned)(b & (bits - 1));
        if (!s) { out = a & mask; return true; }
        out = (((a & mask) >> s) | ((a & mask) << (bits - s))) & mask;
        return true;
    }
    case Op::CmpEq: out = (a & mask) == (b & mask); return true;
    case Op::CmpNe: out = (a & mask) != (b & mask); return true;
    case Op::CmpUlt: out = (a & mask) < (b & mask); return true;
    case Op::CmpUle: out = (a & mask) <= (b & mask); return true;
    case Op::CmpUgt: out = (a & mask) > (b & mask); return true;
    case Op::CmpUge: out = (a & mask) >= (b & mask); return true;
    case Op::CmpSlt: out = sa() < sb(); return true;
    case Op::CmpSle: out = sa() <= sb(); return true;
    case Op::CmpSgt: out = sa() > sb(); return true;
    case Op::CmpSge: out = sa() >= sb(); return true;
    default: return false;
    }
}

int constantFold(ir::Function& f) {
    int changed = 0;
    for (auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            ir::Inst& in = f.inst(v);
            if (in.dead || in.op == Op::Const) continue;
            u64 a = 0, c = 0, out = 0;
            if (ir::isCast(in.op) && in.args.size() == 1 && isConst(f, in.args[0], a)) {
                Type src = f.inst(in.args[0]).type;
                switch (in.op) {
                case Op::Trunc: makeConst(f, v, truncBits(a, in.type.bits)); ++changed; continue;
                case Op::ZExt: makeConst(f, v, truncBits(a, src.bits)); ++changed; continue;
                case Op::SExt: makeConst(f, v, (u64)signExtend(a, src.bits)); ++changed; continue;
                case Op::Bitcast: case Op::IntToPtr: case Op::PtrToInt: makeConst(f, v, a); ++changed; continue;
                case Op::FPExt:
                    if (src.bits == 32 && in.type.bits == 64) { makeConst(f, v, doubleToBits((double)bitsToFloat((u32)a))); ++changed; }
                    continue;
                case Op::FPTrunc:
                    if (src.bits == 64 && in.type.bits == 32) { makeConst(f, v, floatToBits((float)bitsToDouble(a))); ++changed; }
                    continue;
                case Op::SIToFP:
                    if (in.type.bits == 64) makeConst(f, v, doubleToBits((double)signExtend(a, src.bits)));
                    else if (in.type.bits == 32) makeConst(f, v, floatToBits((float)signExtend(a, src.bits)));
                    else continue;
                    ++changed;
                    continue;
                case Op::UIToFP:
                    if (in.type.bits == 64) makeConst(f, v, doubleToBits((double)truncBits(a, src.bits)));
                    else if (in.type.bits == 32) makeConst(f, v, floatToBits((float)truncBits(a, src.bits)));
                    else continue;
                    ++changed;
                    continue;
                default: continue;
                }
            }
            if (in.args.size() == 1 && (in.op == Op::Not || in.op == Op::Neg || in.op == Op::FNeg || in.op == Op::FAbs)) {
                if (isConst(f, in.args[0], a) && evalConst(in.op, in.type, a, 0, out)) {
                    makeConst(f, v, out);
                    ++changed;
                }
                continue;
            }
            if (in.args.size() != 2) continue;
            if (!isConst(f, in.args[0], a) || !isConst(f, in.args[1], c)) continue;
            Type opType = ir::isComparison(in.op) ? f.inst(in.args[0]).type : in.type;
            if (evalConst(in.op, opType, a, c, out)) {
                makeConst(f, v, out);
                ++changed;
            }
        }
    }
    return changed;
}

// Pushes a negation inwards so it lands on the comparisons, where it reads as
// the opposite test rather than as a bang in front of a parenthesised chain.
int simplifyBoolNot(ir::Function& f) {
    int changed = 0;
    for (int round = 0; round < 8; ++round) {
        int before = changed;
        for (auto& b : f.blocks()) {
            for (ValueId v : b.insts) {
                ir::Inst& in = f.inst(v);
                if (in.dead || in.op != Op::Not || in.type.bits != 1 || in.args.size() != 1) continue;
                ValueId a = in.args[0];
                const ir::Inst& src = f.inst(a);
                if (src.dead) continue;
                if (ir::isComparison(src.op) && ir::invertComparison(src.op) != src.op) {
                    in.op = ir::invertComparison(src.op);
                    in.args = src.args;
                    ++changed;
                    continue;
                }
                if (src.op == Op::Not && src.args.size() == 1 && src.type.bits == 1) {
                    f.replaceAllUses(v, src.args[0]);
                    in.dead = true;
                    ++changed;
                    continue;
                }
                if ((src.op == Op::And || src.op == Op::Or) && src.type.bits == 1 &&
                    src.args.size() == 2) {
                    ValueId sa = src.args[0], sb = src.args[1];
                    auto negate = [&](ValueId x) {
                        ir::Inst n;
                        n.op = Op::Not;
                        n.type = ir::kI1;
                        n.args.assign(1, x);
                        n.addr = in.addr;
                        n.block = in.block;
                        return f.insertBefore(v, std::move(n));
                    };
                    ValueId na = negate(sa);
                    ValueId nb = negate(sb);
                    ir::Inst& self = f.inst(v);
                    self.op = f.inst(a).op == Op::And ? Op::Or : Op::And;
                    self.args = {na, nb};
                    ++changed;
                    continue;
                }
            }
        }
        if (changed == before) break;
    }
    return changed;
}

int algebraicSimplify(ir::Function& f) {
    int changed = 0;
    for (auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            ir::Inst& in = f.inst(v);
            if (in.dead) continue;
            // Canonicalise: constants on the right for commutative operations.
            if (ir::isCommutative(in.op) && in.args.size() == 2) {
                u64 dummy;
                if (isConst(f, in.args[0], dummy) && !isConst(f, in.args[1], dummy)) {
                    std::swap(in.args[0], in.args[1]);
                    ++changed;
                }
            }
            if (in.args.size() == 2) {
                ValueId x = in.args[0], y = in.args[1];
                switch (in.op) {
                case Op::Add: case Op::Sub: case Op::Or: case Op::Xor:
                case Op::Shl: case Op::LShr: case Op::AShr: case Op::Rol: case Op::Ror:
                    if (isConstEq(f, y, 0)) { replaceWith(f, v, x); ++changed; continue; }
                    break;
                case Op::Mul:
                    if (isConstEq(f, y, 1)) { replaceWith(f, v, x); ++changed; continue; }
                    if (isConstEq(f, y, 0)) { makeConst(f, v, 0); ++changed; continue; }
                    break;
                case Op::UDiv: case Op::SDiv:
                    if (isConstEq(f, y, 1)) { replaceWith(f, v, x); ++changed; continue; }
                    break;
                case Op::And: {
                    u64 c;
                    if (isConstEq(f, y, 0)) { makeConst(f, v, 0); ++changed; continue; }
                    if (isConst(f, y, c) && c == maskBits(in.type.bits)) { replaceWith(f, v, x); ++changed; continue; }
                    if (x == y) { replaceWith(f, v, x); ++changed; continue; }
                    break;
                }
                default:
                    break;
                }
                if (in.op == Op::Or) {
                    u64 c;
                    if (isConst(f, y, c) && c == maskBits(in.type.bits)) { makeConst(f, v, maskBits(in.type.bits)); ++changed; continue; }
                    if (x == y) { replaceWith(f, v, x); ++changed; continue; }
                }
                if (in.op == Op::Xor && x == y) { makeConst(f, v, 0); ++changed; continue; }
                // "cmp ^ true" is a negation; invert the comparison instead.
                if (in.op == Op::Xor && in.type.bits == 1 && isConstEq(f, y, 1)) {
                    ir::Inst& src = f.inst(x);
                    if (!src.dead && ir::isComparison(src.op) && ir::invertComparison(src.op) != src.op) {
                        bool onlyUse = true;
                        for (const auto& bb : f.blocks())
                            for (ValueId u : bb.insts) {
                                if (u == v) continue;
                                for (ValueId aa : f.inst(u).args)
                                    if (aa == x) onlyUse = false;
                            }
                        if (onlyUse) {
                            src.op = ir::invertComparison(src.op);
                            replaceWith(f, v, x);
                            ++changed;
                            continue;
                        }
                    }
                }
                // A shift feeding arithmetic is a multiply in disguise. Turning
                // it back lets the chain a compiler built out of lea and shl
                // fold into the single multiply the source wrote.
                if ((in.op == Op::Add || in.op == Op::Sub || in.op == Op::Mul) && in.type.bits >= 16) {
                    for (int side = 0; side < 2; ++side) {
                        ValueId operand = in.args[side];
                        ir::Inst& sh = f.inst(operand);
                        if (sh.dead || sh.op != Op::Shl || sh.args.size() != 2) continue;
                        u64 k;
                        if (!isConst(f, sh.args[1], k) || k == 0 || k >= 32) continue;
                        // Only when nothing else reads it, so a genuine bit
                        // manipulation is left alone.
                        int users = 0;
                        for (const auto& bb : f.blocks())
                            for (ValueId u : bb.insts)
                                for (ValueId aa : f.inst(u).args)
                                    if (aa == operand) ++users;
                        if (users != 1) continue;
                        ir::Inst nc;
                        nc.op = Op::Const;
                        nc.type = sh.type;
                        nc.imm = truncBits(1ull << k, sh.type.bits);
                        nc.addr = sh.addr;
                        sh.args[1] = f.insertBefore(operand, std::move(nc));
                        sh.op = Op::Mul;
                        ++changed;
                    }
                }
                // (x * c1) * c2 is one multiply.
                if (in.op == Op::Mul) {
                    u64 c2;
                    if (isConst(f, y, c2)) {
                        ir::Inst& lhs = f.inst(x);
                        u64 c1;
                        if (!lhs.dead && lhs.op == Op::Mul && lhs.args.size() == 2 &&
                            isConst(f, lhs.args[1], c1)) {
                            ir::Inst nc;
                            nc.op = Op::Const;
                            nc.type = in.type;
                            nc.imm = truncBits(c1 * c2, in.type.bits);
                            nc.addr = in.addr;
                            ValueId nv = f.insertBefore(v, std::move(nc));
                            in.args[0] = lhs.args[0];
                            in.args[1] = nv;
                            ++changed;
                            continue;
                        }
                    }
                }
                // (x * c) + x is x * (c + 1), and the same the other way round.
                if (in.op == Op::Add) {
                    auto fold = [&](ValueId base, ValueId mulSide) -> bool {
                        const ir::Inst& m = f.inst(mulSide);
                        if (m.dead || m.op != Op::Mul || m.args.size() != 2 || m.args[0] != base) return false;
                        u64 k;
                        if (!isConst(f, m.args[1], k)) return false;
                        ir::Inst nc;
                        nc.op = Op::Const;
                        nc.type = in.type;
                        nc.imm = truncBits(k + 1, in.type.bits);
                        nc.addr = in.addr;
                        ValueId nv = f.insertBefore(v, std::move(nc));
                        in.op = Op::Mul;
                        in.args[0] = base;
                        in.args[1] = nv;
                        return true;
                    };
                    if (fold(x, y) || fold(y, x)) { ++changed; continue; }
                }
                // x + x * k is a single multiply, which is how a compiler
                // writes it with lea and how the source wrote it.
                if (in.op == Op::Add && f.inst(x).op != Op::Const) {
                    auto foldSelfMul = [&](ValueId base, ValueId mulSide) -> bool {
                        const ir::Inst& m = f.inst(mulSide);
                        if (m.dead || m.op != Op::Mul || m.args.size() != 2) return false;
                        if (m.args[0] != base) return false;
                        u64 k;
                        if (!isConst(f, m.args[1], k)) return false;
                        ir::Inst nc;
                        nc.op = Op::Const;
                        nc.type = in.type;
                        nc.imm = truncBits(k + 1, in.type.bits);
                        nc.addr = in.addr;
                        ValueId nv = f.insertBefore(v, std::move(nc));
                        in.op = Op::Mul;
                        in.args[0] = base;
                        in.args[1] = nv;
                        return true;
                    };
                    if (foldSelfMul(x, y) || foldSelfMul(y, x)) { ++changed; continue; }
                }
                // x + x is a doubling, which is how the source wrote it.
                if (in.op == Op::Add && x == y && f.inst(x).op != Op::Const) {
                    ir::Inst two;
                    two.op = Op::Const;
                    two.type = in.type;
                    two.imm = 2;
                    two.addr = in.addr;
                    in.op = Op::Mul;
                    in.args[1] = f.insertBefore(v, std::move(two));
                    ++changed;
                    continue;
                }
                if (in.op == Op::Sub && x == y) { makeConst(f, v, 0); ++changed; continue; }
                // x - c  ->  x + (-c) keeps additive chains in one shape.
                if (in.op == Op::Sub) {
                    u64 c;
                    if (isConst(f, y, c) && signExtend(c, in.type.bits) < 0) {
                        in.op = Op::Add;
                        ir::Inst nc;
                        nc.op = Op::Const;
                        nc.type = in.type;
                        nc.imm = truncBits(0 - c, in.type.bits);
                        nc.addr = in.addr;
                        in.args[1] = f.insertBefore(v, std::move(nc));
                        ++changed;
                        continue;
                    }
                }
                // (x + c1) + c2  ->  x + (c1 + c2)
                if (in.op == Op::Add) {
                    u64 c2;
                    if (isConst(f, y, c2)) {
                        const ir::Inst& lhs = f.inst(x);
                        u64 c1;
                        if (!lhs.dead && lhs.op == Op::Add && lhs.args.size() == 2 && isConst(f, lhs.args[1], c1)) {
                            ir::Inst nc;
                            nc.op = Op::Const;
                            nc.type = in.type;
                            nc.imm = truncBits(c1 + c2, in.type.bits);
                            nc.addr = in.addr;
                            ValueId nv = f.insertBefore(v, std::move(nc));
                            in.args[0] = lhs.args[0];
                            in.args[1] = nv;
                            ++changed;
                            continue;
                        }
                    }
                }
                // Comparison against a constant that cannot hold.
                if (ir::isComparison(in.op)) {
                    Type ot = f.inst(x).type;
                    u64 c;
                    if (x == y && !ot.isFloat()) {
                        bool res = in.op == Op::CmpEq || in.op == Op::CmpUle || in.op == Op::CmpUge ||
                                   in.op == Op::CmpSle || in.op == Op::CmpSge;
                        makeConst(f, v, res ? 1 : 0);
                        ++changed;
                        continue;
                    }
                    if (isConst(f, y, c) && !ot.isFloat()) {
                        if (in.op == Op::CmpUlt && c == 0) { makeConst(f, v, 0); ++changed; continue; }
                        if (in.op == Op::CmpUge && c == 0) { makeConst(f, v, 1); ++changed; continue; }
                        // "x >= k+1" is how a compiler writes "x > k".
                        unsigned bits = ot.bits;
                        i64 sc = signExtend(c, bits);
                        auto retarget = [&](Op newOp, i64 newC) {
                            ir::Inst nc;
                            nc.op = Op::Const;
                            nc.type = ot;
                            nc.imm = truncBits((u64)newC, bits);
                            nc.addr = in.addr;
                            in.args[1] = f.insertBefore(v, std::move(nc));
                            in.op = newOp;
                            ++changed;
                        };
                        if (in.op == Op::CmpSge && sc != INT64_MIN) { retarget(Op::CmpSgt, sc - 1); continue; }
                        if (in.op == Op::CmpSlt && sc != INT64_MIN) { retarget(Op::CmpSle, sc - 1); continue; }
                        if (in.op == Op::CmpUge && c > 0) { retarget(Op::CmpUgt, (i64)(c - 1)); continue; }
                        if (in.op == Op::CmpUlt && c > 0) { retarget(Op::CmpUle, (i64)(c - 1)); continue; }
                    }
                }
            }
            // select with a constant condition, or identical arms.
            if (in.op == Op::Select && in.args.size() == 3) {
                u64 c;
                if (isConst(f, in.args[0], c)) {
                    replaceWith(f, v, c ? in.args[1] : in.args[2]);
                    ++changed;
                    continue;
                }
                if (in.args[1] == in.args[2]) {
                    replaceWith(f, v, in.args[1]);
                    ++changed;
                    continue;
                }
            }
            // Cast chains.
            if (in.op == Op::Trunc && in.args.size() == 1) {
                const ir::Inst& src = f.inst(in.args[0]);
                if ((src.op == Op::ZExt || src.op == Op::SExt) && !src.args.empty()) {
                    Type inner = f.inst(src.args[0]).type;
                    if (inner.bits == in.type.bits) { replaceWith(f, v, src.args[0]); ++changed; continue; }
                    if (inner.bits > in.type.bits) { in.args[0] = src.args[0]; ++changed; continue; }
                }
                if (src.op == Op::Trunc && !src.args.empty()) { in.args[0] = src.args[0]; ++changed; continue; }
            }
            if ((in.op == Op::ZExt || in.op == Op::SExt) && in.args.size() == 1) {
                const ir::Inst& src = f.inst(in.args[0]);
                if (src.op == in.op && !src.args.empty()) { in.args[0] = src.args[0]; ++changed; continue; }
            }
            if (in.op == Op::Bitcast && in.args.size() == 1) {
                if (f.inst(in.args[0]).type == in.type) { replaceWith(f, v, in.args[0]); ++changed; continue; }
                const ir::Inst& src = f.inst(in.args[0]);
                if (src.op == Op::Bitcast && !src.args.empty() && f.inst(src.args[0]).type == in.type) {
                    replaceWith(f, v, src.args[0]);
                    ++changed;
                    continue;
                }
            }
        }
    }
    if (changed) f.removeDeadInsts();
    return changed;
}

int simplifyBranches(ir::Function& f) {
    int changed = 0;
    for (auto& b : f.blocks()) {
        if (b.insts.empty()) continue;
        ValueId t = b.insts.back();
        ir::Inst& in = f.inst(t);
        if (in.op == Op::Branch && in.args.size() == 1) {
            u64 c;
            if (isConst(f, in.args[0], c)) {
                int keep = c ? b.succs[0] : b.succs[1];
                in.op = Op::Jump;
                in.args.clear();
                b.succs = {keep};
                ++changed;
                continue;
            }
            // Both edges lead to the same block.
            if (b.succs.size() == 2 && b.succs[0] == b.succs[1]) {
                in.op = Op::Jump;
                in.args.clear();
                b.succs = {b.succs[0]};
                ++changed;
            }
        }
    }
    if (changed) {
        f.recomputePreds();
        // Phi arguments must follow the new predecessor lists.
        f.pruneUnreachableBlocks();
        f.recomputePreds();
    }
    return changed;
}

int deadCodeElimination(ir::Function& f) {
    std::unordered_set<ValueId> live;
    std::vector<ValueId> work;
    auto markLive = [&](ValueId v) {
        if (v != kNoValue && live.insert(v).second) work.push_back(v);
    };
    for (const auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            bool essential = in.isTerminator() || ir::hasSideEffects(in.op);
            if (in.op == Op::Intrinsic && in.aux == 0) essential = false;
            if (in.op == Op::Call) essential = true;
            if (essential) markLive(v);
        }
    }
    while (!work.empty()) {
        ValueId v = work.back();
        work.pop_back();
        for (ValueId a : f.inst(v).args) markLive(a);
        if (f.inst(v).call && f.inst(v).call->indirectTarget != kNoValue) markLive(f.inst(v).call->indirectTarget);
    }
    int removed = 0;
    for (auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            if (live.count(v)) continue;
            f.inst(v).dead = true;
            ++removed;
        }
    }
    if (removed) f.removeDeadInsts();
    return removed;
}

namespace {
struct ExprKey {
    Op op;
    u16 bits;
    u8 kind;
    u64 imm;
    u32 locKey;   // distinguishes EntryValue of different locations
    u32 aux;      // distinguishes Arg indices and access sizes
    std::vector<ValueId> args;
    bool operator==(const ExprKey& o) const {
        return op == o.op && bits == o.bits && kind == o.kind && imm == o.imm && locKey == o.locKey &&
               aux == o.aux && args == o.args;
    }
};
struct ExprHash {
    size_t operator()(const ExprKey& k) const {
        size_t h = (size_t)k.op * 1000003 + k.bits * 31 + k.kind + (size_t)k.imm * 2654435761u;
        h = h * 1000003 + k.locKey;
        h = h * 1000003 + k.aux;
        for (ValueId a : k.args) h = h * 1000003 + a;
        return h;
    }
};

bool pureForCse(Op op) {
    switch (op) {
    case Op::Load: case Op::Store: case Op::Call: case Op::Intrinsic:
    case Op::Phi: case Op::ReadLoc: case Op::WriteLoc: case Op::Undef:
        return false;
    default:
        return !ir::isTerminator(op);
    }
}
} // namespace

int commonSubexpressionElimination(ir::Function& f) {
    // Dominator-scoped value numbering: an expression may reuse an earlier
    // identical one only if that one dominates it.
    Digraph g = f.cfg();
    DomTree dom = DomTree::build(g);
    std::unordered_map<ExprKey, std::vector<ValueId>, ExprHash> table;
    int changed = 0;
    for (int b : dom.rpo()) {
        for (ValueId v : f.block(b).insts) {
            const ir::Inst& in = f.inst(v);
            if (in.dead || !pureForCse(in.op)) continue;
            ExprKey k;
            k.op = in.op;
            k.bits = in.type.bits;
            k.kind = (u8)in.type.kind;
            k.imm = in.imm;
            k.locKey = in.loc.valid() ? in.loc.key() : 0;
            k.aux = in.aux;
            k.args = in.args;
            auto& bucket = table[k];
            ValueId found = kNoValue;
            for (ValueId cand : bucket) {
                if (f.inst(cand).dead) continue;
                if (dom.dominates(f.inst(cand).block, b)) { found = cand; break; }
            }
            if (found != kNoValue) {
                replaceWith(f, v, found);
                ++changed;
            } else {
                bucket.push_back(v);
            }
        }
    }
    if (changed) f.removeDeadInsts();
    return changed;
}

// Forwards a store to a later load of the same frame address in the same
// block when nothing in between can write memory.
int forwardStackLoads(ir::Function& f) {
    int changed = 0;
    for (auto& b : f.blocks()) {
        std::map<i64, ValueId> stored; // frame offset -> stored value
        std::map<i64, unsigned> size;
        for (ValueId v : b.insts) {
            ir::Inst& in = f.inst(v);
            if (in.dead) continue;
            if (in.op == Op::Store) {
                const ir::Inst& a = f.inst(in.args[0]);
                if (a.op == Op::FrameAddr) {
                    stored[(i64)a.imm] = in.args[1];
                    size[(i64)a.imm] = f.inst(in.args[1]).type.bytes();
                } else {
                    stored.clear();
                    size.clear();
                }
                continue;
            }
            if (in.op == Op::Load) {
                const ir::Inst& a = f.inst(in.args[0]);
                if (a.op != Op::FrameAddr) continue;
                auto it = stored.find((i64)a.imm);
                if (it == stored.end()) continue;
                if (size[(i64)a.imm] != in.type.bytes()) continue;
                if (f.inst(it->second).type != in.type) continue;
                replaceWith(f, v, it->second);
                ++changed;
                continue;
            }
            if (in.op == Op::Call || (in.op == Op::Intrinsic && in.aux)) {
                stored.clear();
                size.clear();
            }
        }
    }
    if (changed) f.removeDeadInsts();
    return changed;
}

// Two loads of the same address and type may share a value when no store,
// call or side-effecting intrinsic can execute between them on any path.
int redundantLoadElimination(ir::Function& f) {
    int nb = f.blockCount();
    if (nb == 0) return 0;
    Digraph g = f.cfg();
    DomTree dom = DomTree::build(g);

    // Blocks that contain anything able to write memory.
    std::vector<char> writes(nb, 0);
    for (const auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.dead) continue;
            if (in.op == Op::Store || in.op == Op::Call || (in.op == Op::Intrinsic && in.aux)) {
                writes[b.id] = 1;
                break;
            }
        }
    }
    // Which blocks can reach which, for the "between" test.
    std::vector<std::vector<bool>> reaches(nb);
    for (int i = 0; i < nb; ++i) reaches[i] = reachableFrom(g, i);

    auto writeBetween = [&](int defBlock, size_t defPos, int useBlock, size_t usePos) {
        if (defBlock == useBlock) {
            const auto& list = f.block(defBlock).insts;
            for (size_t i = defPos + 1; i < usePos && i < list.size(); ++i) {
                const ir::Inst& in = f.inst(list[i]);
                if (in.dead) continue;
                if (in.op == Op::Store || in.op == Op::Call || (in.op == Op::Intrinsic && in.aux)) return true;
            }
            // A block inside a loop can come back around to itself.
            for (int s : f.block(defBlock).succs)
                if (reaches[s][defBlock]) return true;
            return false;
        }
        // The tail of the defining block after the load.
        {
            const auto& list = f.block(defBlock).insts;
            for (size_t i = defPos + 1; i < list.size(); ++i) {
                const ir::Inst& in = f.inst(list[i]);
                if (in.dead) continue;
                if (in.op == Op::Store || in.op == Op::Call || (in.op == Op::Intrinsic && in.aux)) return true;
            }
        }
        // The head of the using block before the second load.
        {
            const auto& list = f.block(useBlock).insts;
            for (size_t i = 0; i < usePos && i < list.size(); ++i) {
                const ir::Inst& in = f.inst(list[i]);
                if (in.dead) continue;
                if (in.op == Op::Store || in.op == Op::Call || (in.op == Op::Intrinsic && in.aux)) return true;
            }
        }
        // Every block that lies on a path from one to the other.
        for (int m = 0; m < nb; ++m) {
            if (m == defBlock || m == useBlock) continue;
            if (!reaches[defBlock][m] || !reaches[m][useBlock]) continue;
            if (writes[m]) return true;
        }
        return false;
    };

    struct LoadRec {
        ValueId value;
        int block;
        size_t pos;
    };
    std::map<std::pair<ValueId, u32>, std::vector<LoadRec>> byAddress;
    int changed = 0;
    for (int b : dom.rpo()) {
        const auto& list = f.block(b).insts;
        for (size_t i = 0; i < list.size(); ++i) {
            ValueId v = list[i];
            const ir::Inst& in = f.inst(v);
            if (in.dead || in.op != Op::Load) continue;
            auto key = std::make_pair(in.args[0], (u32)in.type.bits | ((u32)in.type.kind << 16));
            auto& recs = byAddress[key];
            ValueId found = kNoValue;
            for (const auto& r : recs) {
                if (f.inst(r.value).dead) continue;
                if (!dom.dominates(r.block, b)) continue;
                if (r.block == b && r.pos >= i) continue;
                if (writeBetween(r.block, r.pos, b, i)) continue;
                found = r.value;
                break;
            }
            if (found != kNoValue) {
                replaceWith(f, v, found);
                ++changed;
            } else {
                recs.push_back({v, b, i});
            }
        }
    }
    if (changed) f.removeDeadInsts();
    return changed;
}

int deadFrameStoreElimination(ir::Function& f) {
    // A frame offset qualifies when every use of its address is a direct load
    // or store, so nothing else can reach it.
    std::map<i64, bool> escaped;
    std::map<i64, unsigned> loads;
    std::map<i64, std::vector<ValueId>> stores;
    auto uses = f.buildUses();

    for (const auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.dead || in.op != Op::FrameAddr) continue;
            i64 off = (i64)in.imm;
            escaped.emplace(off, false);
            auto it = uses.find(v);
            if (it == uses.end()) continue;
            for (ValueId u : it->second) {
                const ir::Inst& ui = f.inst(u);
                if (ui.dead) continue;
                if (ui.op == Op::Load && ui.args[0] == v) ++loads[off];
                else if (ui.op == Op::Store && ui.args[0] == v && ui.args[1] != v) stores[off].push_back(u);
                else escaped[off] = true;
            }
        }
    }
    int removed = 0;
    for (auto& [off, list] : stores) {
        if (escaped[off]) continue;
        if (loads.count(off) && loads[off] > 0) continue;
        for (ValueId v : list) {
            f.inst(v).dead = true;
            ++removed;
        }
    }
    if (removed) f.removeDeadInsts();
    return removed;
}

// --- demanded bits ---------------------------------------------------------

int narrowByDemandedBits(ir::Function& f) {
    // Backward analysis: how many low bits of each value are ever observed.
    std::unordered_map<ValueId, u64> demanded;
    auto demand = [&](ValueId v, u64 mask) {
        if (v == kNoValue) return false;
        u64& d = demanded[v];
        u64 nd = d | mask;
        if (nd == d) return false;
        d = nd;
        return true;
    };
    auto fullMask = [&](ValueId v) { return maskBits(f.inst(v).type.bits); };

    bool changed = true;
    int guard = 0;
    while (changed && guard++ < 64) {
        changed = false;
        for (int bi = f.blockCount() - 1; bi >= 0; --bi) {
            const auto& b = f.block(bi);
            for (size_t i = b.insts.size(); i-- > 0;) {
                ValueId v = b.insts[i];
                const ir::Inst& in = f.inst(v);
                if (in.dead) continue;
                u64 out = in.definesValue() ? demanded[v] : 0;
                // Anything with a side effect, or a terminator, observes
                // everything its operands hold.
                bool opaque = ir::hasSideEffects(in.op) || in.isTerminator() || in.op == Op::Call ||
                              in.op == Op::Intrinsic || in.op == Op::Store;
                if (opaque) {
                    for (ValueId a : in.args) changed |= demand(a, fullMask(a));
                    continue;
                }
                switch (in.op) {
                case Op::And: case Op::Or: case Op::Xor: case Op::Add: case Op::Sub: case Op::Mul:
                case Op::Neg: case Op::Not: case Op::Phi: case Op::Select: {
                    // Bitwise operations only need the demanded bits; the
                    // arithmetic ones additionally need everything below.
                    u64 m = out;
                    if (in.op == Op::Add || in.op == Op::Sub || in.op == Op::Mul || in.op == Op::Neg) {
                        // Carries only travel upwards, so all bits at or below
                        // the highest demanded one are needed.
                        if (m) {
                            unsigned hi = 63;
                            while (hi && !((m >> hi) & 1)) --hi;
                            m = maskBits(hi + 1);
                        }
                    }
                    size_t start = in.op == Op::Select ? 1 : 0;
                    if (in.op == Op::Select) changed |= demand(in.args[0], 1);
                    for (size_t k = start; k < in.args.size(); ++k) changed |= demand(in.args[k], m);
                    break;
                }
                case Op::Shl: {
                    u64 c;
                    if (in.args.size() == 2 && isConst(f, in.args[1], c)) {
                        unsigned s = (unsigned)(c & (in.type.bits - 1));
                        changed |= demand(in.args[0], out >> s);
                    } else if (in.args.size() == 2) {
                        changed |= demand(in.args[0], fullMask(in.args[0]));
                    }
                    if (in.args.size() == 2) changed |= demand(in.args[1], fullMask(in.args[1]));
                    break;
                }
                case Op::LShr: case Op::AShr: {
                    u64 c;
                    if (in.args.size() == 2 && isConst(f, in.args[1], c)) {
                        unsigned s = (unsigned)(c & (in.type.bits - 1));
                        u64 m = (out << s) & maskBits(in.type.bits);
                        if (in.op == Op::AShr) m |= 1ull << (in.type.bits - 1);
                        changed |= demand(in.args[0], m);
                    } else if (in.args.size() == 2) {
                        changed |= demand(in.args[0], fullMask(in.args[0]));
                    }
                    if (in.args.size() == 2) changed |= demand(in.args[1], fullMask(in.args[1]));
                    break;
                }
                case Op::Trunc:
                    changed |= demand(in.args[0], out & maskBits(in.type.bits));
                    break;
                case Op::ZExt:
                    changed |= demand(in.args[0], out & maskBits(f.inst(in.args[0]).type.bits));
                    break;
                case Op::SExt: {
                    unsigned sb = f.inst(in.args[0]).type.bits;
                    u64 m = out & maskBits(sb);
                    if (out >> (sb - 1)) m |= 1ull << (sb - 1); // the sign bit is observed
                    changed |= demand(in.args[0], m);
                    break;
                }
                default:
                    for (ValueId a : in.args) changed |= demand(a, fullMask(a));
                    break;
                }
            }
        }
    }

    // Narrow values whose upper bits are never observed.
    //
    // A value may only shrink if every one of its users is happy with the
    // narrow form, so the rewrite is applied to a closed set: candidates are
    // dropped until nothing in the set has a user outside it that would see
    // the missing bits.
    auto widthFor = [](u64 mask) -> unsigned {
        if (mask == 0) return 8;
        unsigned hi = 63;
        while (hi && !((mask >> hi) & 1)) --hi;
        unsigned need = hi + 1;
        if (need <= 8) return 8;
        if (need <= 16) return 16;
        if (need <= 32) return 32;
        return 64;
    };
    auto narrowable = [](Op op) {
        switch (op) {
        case Op::Add: case Op::Sub: case Op::Mul: case Op::And: case Op::Or: case Op::Xor:
        case Op::Phi: case Op::Select: case Op::Const: case Op::ZExt:
            return true;
        default:
            return false;
        }
    };

    std::unordered_map<ValueId, unsigned> target;
    for (const auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.dead || !in.type.isInt() || in.type.bits <= 8) continue;
            if (!narrowable(in.op)) continue;
            auto it = demanded.find(v);
            if (it == demanded.end()) continue;
            unsigned w = widthFor(it->second);
            if (w < in.type.bits) target[v] = w;
        }
    }
    auto uses = f.buildUses();
    // A user outside the set observes the whole value, so its operands cannot
    // shrink; keep discarding until the set is stable.
    bool shrank = true;
    while (shrank) {
        shrank = false;
        for (auto it = target.begin(); it != target.end();) {
            ValueId v = it->first;
            unsigned w = it->second;
            bool ok = true;
            auto ui = uses.find(v);
            if (ui != uses.end()) {
                for (ValueId u : ui->second) {
                    const ir::Inst& in = f.inst(u);
                    if (in.dead) continue;
                    if (in.op == Op::Trunc && in.type.bits <= w) continue;
                    auto tu = target.find(u);
                    if (tu != target.end() && tu->second >= w && in.type.bits == f.inst(v).type.bits) continue;
                    ok = false;
                    break;
                }
            } else {
                ok = false; // no users: dead code elimination handles it
            }
            if (!ok) {
                it = target.erase(it);
                shrank = true;
            } else {
                ++it;
            }
        }
    }

    int narrowed = 0;
    for (auto& [v, w] : target) {
        ir::Inst& in = f.inst(v);
        Type nt = Type::i((u16)w);
        if (in.op == Op::Const) {
            in.type = nt;
            in.imm = truncBits(in.imm, w);
        } else if (in.op == Op::ZExt) {
            // The extension is invisible at this width.
            Type src = f.inst(in.args[0]).type;
            if (src.bits == w) {
                replaceWith(f, v, in.args[0]);
                ++narrowed;
                continue;
            }
            if (src.bits > w) continue;
            in.type = nt;
        } else {
            in.type = nt;
        }
        // Operands that did not shrink need an explicit truncation.
        size_t first = in.op == Op::Select ? 1 : 0;
        if (in.op != Op::ZExt) {
            for (size_t k = first; k < in.args.size(); ++k) {
                ValueId a = in.args[k];
                if (f.inst(a).type.bits == w) continue;
                if (f.inst(a).type.bits < w) { in.type = f.inst(a).type; break; }
                ir::Inst tr;
                tr.op = Op::Trunc;
                tr.type = nt;
                tr.args = {a};
                tr.addr = in.addr;
                ValueId t = in.op == Op::Phi ? f.add(f.inst(a).block, std::move(tr)) : f.insertBefore(v, std::move(tr));
                if (in.op == Op::Phi) {
                    // Keep the truncation before the predecessor's terminator.
                    auto& list = f.block(f.inst(a).block).insts;
                    list.pop_back();
                    list.insert(list.end() - 1, t);
                }
                in.args[k] = t;
            }
        }
        ++narrowed;
    }
    // Users expecting the old width now need an extension back; the only ones
    // left by construction are truncations, which become redundant.
    for (auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            ir::Inst& in = f.inst(v);
            if (in.dead || in.op != Op::Trunc || in.args.empty()) continue;
            if (f.inst(in.args[0]).type.bits == in.type.bits) replaceWith(f, v, in.args[0]);
            else if (f.inst(in.args[0]).type.bits < in.type.bits) {
                in.op = Op::ZExt; // the value already lost those bits
            }
        }
    }
    if (narrowed) f.removeDeadInsts();
    return narrowed;
}

Stats optimize(ir::Function& f, int maxRounds) {
    Stats st;
    for (int round = 0; round < maxRounds; ++round) {
        ++st.rounds;
        int before = st.total();
        st.constantsFolded += constantFold(f);
        st.algebraicSimplifications += algebraicSimplify(f);
        st.algebraicSimplifications += simplifyBoolNot(f);
        st.branchesSimplified += simplifyBranches(f);
        st.phisRemoved += ssa::simplifyPhis(f);
        st.loadsForwarded += forwardStackLoads(f);
        st.expressionsShared += commonSubexpressionElimination(f);
        st.loadsShared += redundantLoadElimination(f);
        st.deadStores += deadFrameStoreElimination(f);
        st.castsRemoved += narrowByDemandedBits(f);
        st.instructionsRemoved += deadCodeElimination(f);
        if (st.total() == before) break;
    }
    return st;
}

// ---------------------------------------------------------------------------

int rematerializeCheapValues(ir::Function& f) {
    auto isCheap = [&](const ir::Inst& in) {
        switch (in.op) {
        case Op::SExt: case Op::ZExt: case Op::Trunc: case Op::Bitcast:
        case Op::IntToPtr: case Op::PtrToInt:
            return in.args.size() == 1;
        case Op::FrameAddr: case Op::GlobalAddr:
            return true;
        default:
            break;
        }
        // A comparison of two already-named values is cheap to repeat and
        // reads better inline than as a flag variable.
        if (ir::isComparison(in.op) && in.args.size() == 2) return true;
        switch (in.op) {
        default:
            return false;
        }
    };
    int changed = 0;
    // Work off a snapshot: the clones are cheap themselves and must not be
    // rematerialised again.
    std::vector<ValueId> candidates;
    for (const auto& b : f.blocks())
        for (ValueId v : b.insts)
            if (isCheap(f.inst(v))) candidates.push_back(v);

    auto uses = f.buildUses();
    for (ValueId v : candidates) {
        auto it = uses.find(v);
        if (it == uses.end() || it->second.size() < 2) continue;
        // Distinct users only; a user naming the value twice still needs one copy.
        std::vector<ValueId> users;
        for (ValueId u : it->second)
            if (users.empty() || users.back() != u) users.push_back(u);
        bool first = true;
        for (ValueId u : users) {
            ir::Inst& ui = f.inst(u);
            if (ui.op == Op::Phi) continue;   // belongs on the edge, not here
            if (first) { first = false; continue; }  // one user keeps the original
            const ir::Inst& src = f.inst(v);
            ir::Inst copy;
            copy.op = src.op;
            copy.type = src.type;
            copy.args = src.args;
            copy.imm = src.imm;
            copy.aux = src.aux;
            copy.loc = src.loc;
            copy.addr = src.addr;
            copy.block = ui.block;
            ValueId clone = f.insertBefore(u, std::move(copy));
            for (auto& a : f.inst(u).args)
                if (a == v) a = clone;
            ++changed;
        }
    }
    return changed;
}

} // namespace dc::opt
