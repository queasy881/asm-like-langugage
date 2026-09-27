#include "core/interpreter.h"

#include "opt/passes.h"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace dc {

using ir::Op;
using ir::ValueId;
using ir::kNoValue;

bool InterpMemory::read(u64 addr, unsigned bytes, u64& out) const {
    out = 0;
    for (unsigned i = 0; i < bytes; ++i) {
        auto it = written.find(addr + i);
        u8 byte;
        if (it != written.end()) {
            byte = it->second;
        } else if (image && image->read(addr + i, &byte, 1)) {
            // from the image
        } else if (addr + i >= stackLo && addr + i < stackHi) {
            byte = 0;
        } else {
            return false;
        }
        out |= (u64)byte << (i * 8);
    }
    return true;
}

void InterpMemory::write(u64 addr, unsigned bytes, u64 value) {
    for (unsigned i = 0; i < bytes; ++i) written[addr + i] = (u8)(value >> (i * 8));
    writeLog.push_back({addr, truncBits(value, bytes * 8)});
}

namespace {

double asF64(u64 b) {
    double d;
    std::memcpy(&d, &b, 8);
    return d;
}
float asF32(u64 b) {
    float d;
    u32 x = (u32)b;
    std::memcpy(&d, &x, 4);
    return d;
}
u64 fromF64(double d) {
    u64 b;
    std::memcpy(&b, &d, 8);
    return b;
}
u64 fromF32(float d) {
    u32 b;
    std::memcpy(&b, &d, 4);
    return b;
}

} // namespace

InterpResult interpret(const ir::Function& f, InterpMemory& mem, const InterpOptions& opt) {
    InterpResult res;
    if (f.blockCount() == 0) {
        res.error = "empty function";
        return res;
    }
    std::unordered_map<ValueId, u64> vals;
    auto get = [&](ValueId v) -> u64 {
        auto it = vals.find(v);
        return it == vals.end() ? 0 : it->second;
    };

    int block = 0, prevBlock = -1;
    u64 steps = 0;
    while (true) {
        if (++res.blocksVisited > 200000) {
            res.error = "block limit exceeded";
            return res;
        }
        const ir::Block& b = f.block(block);
        // Phis of the block read the values from the incoming edge together.
        std::vector<std::pair<ValueId, u64>> phiResults;
        size_t slot = 0;
        if (prevBlock >= 0) {
            auto it = std::find(b.preds.begin(), b.preds.end(), prevBlock);
            if (it == b.preds.end()) {
                res.error = strfmt("block %d entered from %d which is not a predecessor", block, prevBlock);
                return res;
            }
            slot = (size_t)(it - b.preds.begin());
        }
        for (ValueId v : b.insts) {
            if (f.inst(v).op != Op::Phi) break;
            const ir::Inst& in = f.inst(v);
            if (slot >= in.args.size()) {
                res.error = "phi argument missing";
                return res;
            }
            phiResults.push_back({v, get(in.args[slot])});
        }
        for (auto& [v, val] : phiResults) vals[v] = val;

        int nextBlock = -1;
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.op == Op::Phi) continue;
            if (++steps > opt.maxSteps) {
                res.error = "step limit exceeded";
                res.steps = steps;
                return res;
            }
            unsigned bits = in.type.bits;
            auto a = [&](size_t i) { return get(in.args[i]); };
            auto argBits = [&](size_t i) { return f.inst(in.args[i]).type.bits; };
            u64 out = 0;
            switch (in.op) {
            case Op::Const: out = in.imm; break;
            case Op::Undef:
                if (opt.trapOnUndef) {
                    res.error = "undefined value read";
                    return res;
                }
                out = 0;
                break;
            case Op::Arg:
                out = 0;
                if (opt.argValue) opt.argValue(in.aux, in.type, out);
                break;
            case Op::EntryValue:
                out = 0;
                if (opt.entryValue) opt.entryValue(in.loc, out);
                break;
            case Op::GlobalAddr: out = in.imm; break;
            case Op::FrameAddr: out = opt.stackBase + (u64)(i64)in.imm; break;
            case Op::Load: {
                if (!mem.read(a(0), in.type.bytes(), out)) {
                    res.error = strfmt("unmapped load at %s", hex(a(0)).c_str());
                    return res;
                }
                break;
            }
            case Op::Store:
                mem.write(a(0), f.inst(in.args[1]).type.bytes(), a(1));
                continue;
            case Op::Select: out = a(0) & 1 ? a(1) : a(2); break;
            case Op::Trunc: out = truncBits(a(0), bits); break;
            case Op::ZExt: out = truncBits(a(0), argBits(0)); break;
            case Op::SExt: out = truncBits((u64)signExtend(a(0), argBits(0)), bits); break;
            case Op::Bitcast: case Op::IntToPtr: case Op::PtrToInt: out = truncBits(a(0), bits ? bits : 64); break;
            case Op::FPExt: out = fromF64((double)asF32(a(0))); break;
            case Op::FPTrunc: out = fromF32((float)asF64(a(0))); break;
            case Op::SIToFP: {
                i64 x = signExtend(a(0), argBits(0));
                out = bits == 32 ? fromF32((float)x) : fromF64((double)x);
                break;
            }
            case Op::UIToFP: {
                u64 x = truncBits(a(0), argBits(0));
                out = bits == 32 ? fromF32((float)x) : fromF64((double)x);
                break;
            }
            case Op::FPToSI: case Op::FPToUI: {
                double d = argBits(0) == 32 ? (double)asF32(a(0)) : asF64(a(0));
                if (!std::isfinite(d)) { out = 0; break; }
                out = in.op == Op::FPToSI ? truncBits((u64)(i64)d, bits) : truncBits((u64)d, bits);
                break;
            }
            case Op::FAdd: case Op::FSub: case Op::FMul: case Op::FDiv:
            case Op::FMin: case Op::FMax: {
                if (bits == 32) {
                    float x = asF32(a(0)), y = asF32(a(1)), r = 0;
                    switch (in.op) {
                    case Op::FAdd: r = x + y; break;
                    case Op::FSub: r = x - y; break;
                    case Op::FMul: r = x * y; break;
                    case Op::FDiv: r = x / y; break;
                    case Op::FMin: r = y < x ? y : x; break;
                    default: r = y > x ? y : x; break;
                    }
                    out = fromF32(r);
                } else {
                    double x = asF64(a(0)), y = asF64(a(1)), r = 0;
                    switch (in.op) {
                    case Op::FAdd: r = x + y; break;
                    case Op::FSub: r = x - y; break;
                    case Op::FMul: r = x * y; break;
                    case Op::FDiv: r = x / y; break;
                    case Op::FMin: r = y < x ? y : x; break;
                    default: r = y > x ? y : x; break;
                    }
                    out = fromF64(r);
                }
                break;
            }
            case Op::FNeg: out = bits == 32 ? fromF32(-asF32(a(0))) : fromF64(-asF64(a(0))); break;
            case Op::FAbs: out = bits == 32 ? fromF32(std::fabs(asF32(a(0)))) : fromF64(std::fabs(asF64(a(0)))); break;
            case Op::FSqrt: out = bits == 32 ? fromF32(std::sqrt(asF32(a(0)))) : fromF64(std::sqrt(asF64(a(0)))); break;
            case Op::FCmpEq: case Op::FCmpNe: case Op::FCmpLt: case Op::FCmpLe:
            case Op::FCmpGt: case Op::FCmpGe: case Op::FCmpUno: {
                unsigned fb = argBits(0);
                double x = fb == 32 ? (double)asF32(a(0)) : asF64(a(0));
                double y = fb == 32 ? (double)asF32(a(1)) : asF64(a(1));
                bool uno = std::isnan(x) || std::isnan(y);
                switch (in.op) {
                case Op::FCmpEq: out = !uno && x == y; break;
                case Op::FCmpNe: out = uno || x != y; break;
                case Op::FCmpLt: out = !uno && x < y; break;
                case Op::FCmpLe: out = !uno && x <= y; break;
                case Op::FCmpGt: out = !uno && x > y; break;
                case Op::FCmpGe: out = !uno && x >= y; break;
                default: out = uno; break;
                }
                break;
            }
            case Op::MulHiU: {
                unsigned w = argBits(0);
                if (w <= 32) out = truncBits(((u64)truncBits(a(0), w) * truncBits(a(1), w)) >> w, bits);
                else out = (u64)(((unsigned __int128)a(0) * a(1)) >> 64);
                break;
            }
            case Op::MulHiS: {
                unsigned w = argBits(0);
                if (w <= 32) out = truncBits((u64)((signExtend(a(0), w) * signExtend(a(1), w)) >> w), bits);
                else out = (u64)(((__int128)(i64)a(0) * (i64)a(1)) >> 64);
                break;
            }
            case Op::Call: {
                std::vector<u64> args;
                size_t start = in.aux ? 1 : 0;
                for (size_t i = start; i < in.args.size(); ++i) args.push_back(a(i));
                u64 ret = 0;
                if (!opt.onCall || !opt.onCall(*in.call, args, ret)) {
                    res.error = "call not handled: " + (in.call ? in.call->name : std::string("<indirect>"));
                    return res;
                }
                out = ret;
                break;
            }
            case Op::Intrinsic: {
                const std::string& n = in.text;
                if (n == "byte_swap") {
                    u64 x = a(0);
                    unsigned nb = argBits(0) / 8;
                    out = 0;
                    for (unsigned i = 0; i < nb; ++i) out |= ((x >> (i * 8)) & 0xFF) << ((nb - 1 - i) * 8);
                } else if (n == "popcount") {
                    out = (u64)__builtin_popcountll(truncBits(a(0), argBits(0)));
                } else if (n == "count_trailing_zeros") {
                    u64 x = truncBits(a(0), argBits(0));
                    out = x ? (u64)__builtin_ctzll(x) : argBits(0);
                } else if (n == "count_leading_zeros") {
                    u64 x = truncBits(a(0), argBits(0));
                    out = x ? (u64)(__builtin_clzll(x) - (64 - argBits(0))) : argBits(0);
                } else if (n == "bit_scan_reverse") {
                    u64 x = truncBits(a(0), argBits(0));
                    out = x ? (u64)(63 - __builtin_clzll(x)) : 0;
                } else if (n == "parity8") {
                    out = (__builtin_popcount((unsigned)(a(0) & 0xFF)) & 1) ? 0 : 1;
                } else if (n == "rotate_carry_left" || n == "rotate_carry_right") {
                    out = 0;
                } else if (n.rfind("aux_carry", 0) == 0) {
                    out = 0;
                } else if (in.type.isVoid()) {
                    continue;
                } else {
                    res.error = "unsupported intrinsic: " + n;
                    return res;
                }
                break;
            }
            case Op::Jump:
                nextBlock = b.succs.empty() ? -1 : b.succs[0];
                break;
            case Op::Branch:
                if (b.succs.size() != 2) {
                    res.error = "branch without two successors";
                    return res;
                }
                nextBlock = (a(0) & 1) ? b.succs[0] : b.succs[1];
                break;
            case Op::Switch: {
                i64 idx = (i64)truncBits(a(0), argBits(0));
                nextBlock = b.defaultSucc;
                for (size_t i = 0; i < b.succs.size(); ++i) {
                    if (i >= b.caseValues.size()) break;
                    for (i64 c : b.caseValues[i])
                        if (c == idx) nextBlock = b.succs[i];
                }
                if (nextBlock < 0) {
                    res.error = "switch index out of range with no default";
                    return res;
                }
                break;
            }
            case Op::Return:
                res.ok = true;
                res.returned = true;
                res.steps = steps;
                if (!in.args.empty()) {
                    res.hasValue = true;
                    res.value = truncBits(a(0), f.inst(in.args[0]).type.bits);
                }
                return res;
            case Op::Unreachable:
                res.error = "reached an unreachable terminator";
                res.steps = steps;
                return res;
            default: {
                if (in.args.size() == 2) {
                    ir::Type ot = ir::isComparison(in.op) ? f.inst(in.args[0]).type : in.type;
                    if (!opt::evalConst(in.op, ot, a(0), a(1), out)) {
                        res.error = strfmt("undefined result for %s", ir::opName(in.op));
                        return res;
                    }
                } else if (in.args.size() == 1) {
                    if (!opt::evalConst(in.op, in.type, a(0), 0, out)) {
                        res.error = strfmt("undefined result for %s", ir::opName(in.op));
                        return res;
                    }
                } else {
                    res.error = strfmt("cannot interpret %s", ir::opName(in.op));
                    return res;
                }
                break;
            }
            }
            if (in.definesValue()) vals[v] = truncBits(out, bits >= 64 ? 64 : bits);
            if (in.isTerminator()) break;
        }
        if (nextBlock < 0) {
            res.error = "fell off the end of a block";
            return res;
        }
        prevBlock = block;
        block = nextBlock;
    }
}

} // namespace dc
