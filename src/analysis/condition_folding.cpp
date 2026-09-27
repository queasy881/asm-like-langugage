#include "analysis/condition_folding.h"

#include "analysis/cfg_edit.h"

#include <algorithm>
#include <vector>

namespace dc {
namespace {

using ir::Op;
using ir::ValueId;
using ir::kNoValue;

// An instruction whose result depends only on its operands and cannot fault.
// A load can fault, which is exactly why `p && p->x` must not be folded into
// one unconditional expression.
bool pureForFolding(Op op) {
    switch (op) {
    case Op::Store: case Op::Call: case Op::Intrinsic: case Op::WriteLoc: case Op::ReadLoc:
    case Op::Load: case Op::Phi: case Op::Undef:
    case Op::Jump: case Op::Branch: case Op::Switch: case Op::Return: case Op::Unreachable:
        return false;
    case Op::UDiv: case Op::SDiv: case Op::URem: case Op::SRem:
        return false;   // a zero divisor traps
    default:
        return true;
    }
}

// A block that exists only to test a second condition: one predecessor, no
// side effects, and nothing defined in it that anything outside can see.
bool conditionOnly(const ir::Function& f, int id, int pred,
                   const std::unordered_map<ValueId, std::vector<ValueId>>& uses) {
    const ir::Block& b = f.block(id);
    if (b.preds.size() != 1 || b.preds[0] != pred) return false;
    if (b.insts.empty()) return false;
    const ir::Inst& term = f.inst(b.insts.back());
    if (term.op != Op::Branch || term.args.empty()) return false;
    if (b.insts.size() > 12) return false;   // long enough to be real work
    for (size_t i = 0; i + 1 < b.insts.size(); ++i) {
        const ir::Inst& in = f.inst(b.insts[i]);
        if (!pureForFolding(in.op)) return false;
        auto it = uses.find(b.insts[i]);
        if (it == uses.end()) continue;
        for (ValueId u : it->second)
            if (f.inst(u).block != id) return false;
    }
    return true;
}

} // namespace

int foldShortCircuits(ir::Function& f) {
    int folded = 0;
    for (int round = 0; round < 16; ++round) {
        auto uses = f.buildUses();
        bool progress = false;
        for (int a = 0; a < f.blockCount() && !progress; ++a) {
            const ir::Block& ab = f.block(a);
            if (ab.insts.empty() || ab.succs.size() != 2) continue;
            if (f.inst(ab.insts.back()).op != Op::Branch) continue;
            int t = ab.succs[0], fl = ab.succs[1];

            // Which side holds the second test, and how the two combine.
            for (int side = 0; side < 2 && !progress; ++side) {
                int b = side == 0 ? t : fl;
                int other = side == 0 ? fl : t;
                if (b == a || b == other) continue;
                if (!conditionOnly(f, b, a, uses)) continue;
                const ir::Block& bb = f.block(b);
                if (bb.succs.size() != 2) continue;
                int x = bb.succs[0], y = bb.succs[1];
                bool negate;
                int keep;      // the successor the combined branch keeps
                if (x == other) { negate = side == 0; keep = y; }
                else if (y == other) { negate = side != 0; keep = x; }
                else continue;
                if (keep == a || keep == b) continue;

                ValueId c1 = f.inst(ab.insts.back()).args[0];
                ValueId c2 = f.inst(bb.insts.back()).args[0];
                if (f.inst(c1).type.bits != 1 || f.inst(c2).type.bits != 1) continue;

                PhiSnapshot snap = snapshotPhis(f);
                std::vector<ValueId> savedASuccInsts = f.block(a).insts;
                std::vector<int> savedASuccs = f.block(a).succs;
                std::vector<int> savedBSuccs = f.block(b).succs;
                std::vector<ValueId> savedBInsts = f.block(b).insts;
                std::vector<ValueId> savedTermArgs = f.inst(ab.insts.back()).args;

                // The second test moves up in front of the branch it feeds.
                ValueId anchor = f.block(a).insts.back();
                std::vector<ValueId> moved(f.block(b).insts.begin(), f.block(b).insts.end() - 1);
                std::vector<ValueId>& alist = f.block(a).insts;
                alist.insert(alist.end() - 1, moved.begin(), moved.end());
                for (ValueId v : moved) f.inst(v).block = a;
                f.block(b).insts.assign(1, f.block(b).insts.back());
                (void)anchor;

                ValueId cond2 = c2;
                if (negate) {
                    ir::Inst n;
                    n.op = Op::Not;
                    n.type = ir::kI1;
                    n.args.assign(1, c2);
                    n.addr = f.inst(c2).addr;
                    n.block = a;
                    cond2 = f.insertBefore(f.block(a).insts.back(), std::move(n));
                }
                ir::Inst comb;
                comb.op = side == 0 ? Op::And : Op::Or;
                comb.type = ir::kI1;
                comb.args = {c1, cond2};
                comb.addr = f.inst(c1).addr;
                comb.block = a;
                ValueId cc = f.insertBefore(f.block(a).insts.back(), std::move(comb));

                f.inst(f.block(a).insts.back()).args.assign(1, cc);
                f.block(a).succs = side == 0 ? std::vector<int>{keep, other}
                                             : std::vector<int>{other, keep};
                f.block(b).succs.clear();
                f.recomputePreds();

                if (!replayPhis(f, snap, {b}, a)) {
                    f.block(a).insts = savedASuccInsts;
                    f.block(a).succs = savedASuccs;
                    f.block(b).insts = savedBInsts;
                    f.block(b).succs = savedBSuccs;
                    for (ValueId v : moved) f.inst(v).block = b;
                    f.inst(f.block(a).insts.back()).args = savedTermArgs;
                    f.recomputePreds();
                    restorePhis(f, snap);
                    continue;
                }
                ++folded;
                progress = true;
            }
        }
        if (!progress) break;
        f.pruneUnreachableBlocks();
    }
    if (folded) f.pruneUnreachableBlocks();
    return folded;
}

} // namespace dc
