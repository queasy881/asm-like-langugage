#include "analysis/switch_recovery.h"

#include <algorithm>
#include <map>
#include <set>
#include <vector>

namespace dc {
namespace {

using ir::Op;
using ir::ValueId;
using ir::kNoValue;

// The widest leaf range still worth spelling out as case labels. Anything
// larger is the default arm.
constexpr u64 kMaxLeafValues = 64;
// Below this many arms an if / else chain reads better than a switch.
constexpr size_t kMinCases = 4;
constexpr size_t kMinTargets = 3;

struct Cmp {
    bool valid = false;
    Op op = Op::CmpEq;
    ValueId x = kNoValue;
    i64 c = 0;
};

Op swapped(Op op) {
    switch (op) {
    case Op::CmpSlt: return Op::CmpSgt;
    case Op::CmpSle: return Op::CmpSge;
    case Op::CmpSgt: return Op::CmpSlt;
    case Op::CmpSge: return Op::CmpSle;
    case Op::CmpUlt: return Op::CmpUgt;
    case Op::CmpUle: return Op::CmpUge;
    case Op::CmpUgt: return Op::CmpUlt;
    case Op::CmpUge: return Op::CmpUle;
    default: return op;   // equality is symmetric
    }
}

bool isCompare(Op op) {
    switch (op) {
    case Op::CmpEq: case Op::CmpNe:
    case Op::CmpSlt: case Op::CmpSle: case Op::CmpSgt: case Op::CmpSge:
    case Op::CmpUlt: case Op::CmpUle: case Op::CmpUgt: case Op::CmpUge:
        return true;
    default:
        return false;
    }
}

bool isUnsigned(Op op) {
    switch (op) {
    case Op::CmpUlt: case Op::CmpUle: case Op::CmpUgt: case Op::CmpUge: return true;
    default: return false;
    }
}

Cmp parseCompare(const ir::Function& f, ValueId v) {
    Cmp r;
    if (v == kNoValue || !f.valid(v)) return r;
    const ir::Inst& in = f.inst(v);
    if (!isCompare(in.op) || in.args.size() != 2) return r;
    const ir::Inst& a = f.inst(in.args[0]);
    const ir::Inst& b = f.inst(in.args[1]);
    if (b.op == Op::Const && a.op != Op::Const) {
        r.op = in.op;
        r.x = in.args[0];
        r.c = (i64)signExtend(b.imm, b.type.bits ? b.type.bits : 64);
    } else if (a.op == Op::Const && b.op != Op::Const) {
        r.op = swapped(in.op);
        r.x = in.args[1];
        r.c = (i64)signExtend(a.imm, a.type.bits ? a.type.bits : 64);
    } else {
        return r;
    }
    r.valid = true;
    return r;
}

// Values with no operands can be moved to the switch head if the block that
// held them goes away, so a use elsewhere is not a reason to refuse.
bool relocatable(Op op) {
    return op == Op::Const || op == Op::FrameAddr || op == Op::GlobalAddr || op == Op::Undef;
}

bool dispatchImpure(Op op) {
    switch (op) {
    case Op::Store: case Op::Call: case Op::Intrinsic: case Op::WriteLoc:
    case Op::Load:  // a load is pure but may fault; keep dispatch blocks trivial
        return true;
    default:
        return false;
    }
}

struct Recovery {
    ir::Function& f;
    const std::unordered_map<ValueId, std::vector<ValueId>>& uses;
    ValueId root = kNoValue;
    std::set<int> tree;              // dispatch blocks folded into the switch
    std::map<i64, int> caseOf;       // case value -> target block
    int defaultTarget = -1;
    bool failed = false;

    bool dispatchBlock(int id) const {
        const ir::Block& b = f.block(id);
        if (b.insts.empty()) return false;
        const ir::Inst& term = f.inst(b.insts.back());
        if (term.op != Op::Branch || term.args.empty()) return false;
        for (size_t i = 0; i + 1 < b.insts.size(); ++i) {
            const ir::Inst& in = f.inst(b.insts[i]);
            if (in.op == Op::Phi) return false;
            if (dispatchImpure(in.op)) return false;
            if (relocatable(in.op)) continue;
            auto it = uses.find(b.insts[i]);
            if (it == uses.end()) continue;
            for (ValueId u : it->second)
                if (f.inst(u).block != id) return false;
        }
        return true;
    }

    // A compiler often leaves an empty landing pad in front of the arm it
    // shares between several tests. Looking through it is what lets both
    // sides of a chain agree on one default.
    int resolve(int target) const {
        for (int guard = 0; guard < 8; ++guard) {
            const ir::Block& b = f.block(target);
            if (b.insts.size() != 1 || b.succs.size() != 1) break;
            if (f.inst(b.insts[0]).op != Op::Jump) break;
            const ir::Block& nb = f.block(b.succs[0]);
            if (!nb.insts.empty() && f.inst(nb.insts[0]).op == Op::Phi) break;
            target = b.succs[0];
        }
        return target;
    }

    struct Leaf { i64 lo, hi; int target; };
    std::vector<Leaf> leaves;

    void leaf(int rawTarget, i64 lo, i64 hi) {
        if (lo > hi) return;
        leaves.push_back({lo, hi, resolve(rawTarget)});
    }

    // The same block is often the arm for one value and the fallback for a
    // whole span. Narrow claims win, so the ranges are resolved smallest
    // first rather than in the order the walk happened to reach them.
    void settle() {
        // Unsigned arithmetic, because the full domain overflows a signed
        // subtraction; it wraps to zero here, which reads as "widest".
        auto span = [](const Leaf& l) { return (u64)l.hi - (u64)l.lo + 1; };
        std::stable_sort(leaves.begin(), leaves.end(), [&](const Leaf& a, const Leaf& b) {
            u64 sa = span(a), sb = span(b);
            if (sa == 0) return false;
            if (sb == 0) return true;
            return sa < sb;
        });
        for (const Leaf& l : leaves) {
            u64 n = span(l);
            if (n != 0 && n <= kMaxLeafValues) {
                for (i64 v = l.lo; ; ++v) {
                    caseOf.emplace(v, l.target);
                    if (v == l.hi) break;
                }
                continue;
            }
            if (defaultTarget == -1) defaultTarget = l.target;
            else if (defaultTarget != l.target) failed = true;
        }
    }

    void walk(int id, i64 lo, i64 hi, int depth) {
        if (failed || lo > hi || depth > 32) { if (depth > 32) failed = true; return; }
        // The block the switch starts at keeps whatever work it was already
        // doing; only the blocks folded away have to be pure comparisons
        // reached from nowhere else.
        bool usable = !tree.count(id) &&
                      (tree.empty() ? f.block(id).insts.size() > 0 &&
                                          f.inst(f.block(id).insts.back()).op == Op::Branch
                                    : dispatchBlock(id) && f.block(id).preds.size() == 1);
        Cmp cmp;
        if (usable) {
            const ir::Block& b = f.block(id);
            cmp = parseCompare(f, f.inst(b.insts.back()).args[0]);
            if (!cmp.valid || cmp.x != root) usable = false;
            // An unsigned test only agrees with the signed range below when
            // everything in play is non-negative.
            if (usable && isUnsigned(cmp.op) && (lo < 0 || cmp.c < 0)) usable = false;
        }
        if (!usable) { leaf(id, lo, hi); return; }

        tree.insert(id);
        const ir::Block& b = f.block(id);
        int tSucc = b.succs.size() > 0 ? b.succs[0] : -1;
        int fSucc = b.succs.size() > 1 ? b.succs[1] : -1;
        if (tSucc < 0 || fSucc < 0) { failed = true; return; }

        i64 c = cmp.c;
        auto below = [&](i64 top) { return std::pair<i64, i64>{lo, std::min(hi, top)}; };
        auto above = [&](i64 bot) { return std::pair<i64, i64>{std::max(lo, bot), hi}; };
        std::pair<i64, i64> tr{lo, hi}, fr{lo, hi};
        switch (cmp.op) {
        case Op::CmpEq: tr = {std::max(lo, c), std::min(hi, c)}; break;
        case Op::CmpNe: fr = {std::max(lo, c), std::min(hi, c)}; break;
        case Op::CmpSlt: case Op::CmpUlt:
            tr = below(c == INT64_MIN ? c : c - 1); fr = above(c); break;
        case Op::CmpSle: case Op::CmpUle:
            tr = below(c); fr = above(c == INT64_MAX ? c : c + 1); break;
        case Op::CmpSgt: case Op::CmpUgt:
            tr = above(c == INT64_MAX ? c : c + 1); fr = below(c); break;
        case Op::CmpSge: case Op::CmpUge:
            tr = above(c); fr = below(c == INT64_MIN ? c : c - 1); break;
        default: failed = true; return;
        }
        // The equality arms carve one value out of the range; the other side
        // keeps the whole range and simply finds that value already claimed.
        walk(tSucc, tr.first, tr.second, depth + 1);
        walk(fSucc, fr.first, fr.second, depth + 1);
    }
};

// Phi arguments are positional against the predecessor list, so any change to
// that list has to move them with it. This snapshots the old lists, and is
// replayed once the new ones are in place.
struct PhiSnapshot {
    std::map<int, std::vector<int>> preds;
    std::map<ValueId, std::vector<ValueId>> args;
};

PhiSnapshot snapshotPhis(const ir::Function& f) {
    PhiSnapshot snap;
    for (const auto& b : f.blocks()) {
        snap.preds[b.id] = b.preds;
        for (ValueId v : b.insts) {
            if (f.inst(v).op != Op::Phi) break;
            snap.args[v] = f.inst(v).args;
        }
    }
    return snap;
}

// `folded` names predecessors that went away because the switch absorbed
// them; the switch head speaks for all of them now. Returns false when the
// values they carried disagree, which would make the merge lose information.
bool replayPhis(ir::Function& f, const PhiSnapshot& snap, const std::set<int>& folded, int head) {
    for (auto& b : f.blocks()) {
        auto pit = snap.preds.find(b.id);
        if (pit == snap.preds.end()) continue;
        const std::vector<int>& oldPreds = pit->second;
        if (oldPreds == b.preds) continue;
        for (ValueId v : b.insts) {
            ir::Inst& in = f.inst(v);
            if (in.op != Op::Phi) break;
            auto ait = snap.args.find(v);
            if (ait == snap.args.end()) return false;
            const std::vector<ValueId>& oldArgs = ait->second;
            if (oldArgs.size() != oldPreds.size()) return false;
            std::vector<ValueId> args;
            for (int p : b.preds) {
                ValueId pick = kNoValue;
                bool many = false;
                for (size_t i = 0; i < oldPreds.size(); ++i) {
                    bool match = oldPreds[i] == p ||
                                 (p == head && folded.count(oldPreds[i]));
                    if (!match) continue;
                    if (pick == kNoValue) pick = oldArgs[i];
                    else if (pick != oldArgs[i]) many = true;
                }
                if (many) return false;
                if (pick == kNoValue) return false;
                args.push_back(pick);
            }
            in.args = std::move(args);
        }
    }
    return true;
}

} // namespace

int recoverSwitches(ir::Function& f) {
    int recovered = 0;
    for (int round = 0; round < 4; ++round) {
        auto uses = f.buildUses();
        bool progress = false;
        for (int id = 0; id < f.blockCount(); ++id) {
            const ir::Block& hb = f.block(id);
            if (hb.insts.empty()) continue;
            const ir::Inst& term = f.inst(hb.insts.back());
            if (term.op != Op::Branch || term.args.empty()) continue;
            Cmp head = parseCompare(f, term.args[0]);
            if (!head.valid) continue;

            Recovery r{f, uses};
            r.root = head.x;
            unsigned bits = f.inst(head.x).type.bits;
            if (!bits || bits > 64) continue;
            i64 lo = bits == 64 ? INT64_MIN : -((i64)1 << (bits - 1));
            i64 hi = bits == 64 ? INT64_MAX : ((i64)1 << (bits - 1)) - 1;
            r.walk(id, lo, hi, 0);
            r.settle();
            if (r.failed || r.defaultTarget < 0) continue;
            if (r.tree.size() < 2 || r.caseOf.size() < kMinCases) continue;

            std::set<int> targets;
            for (auto& [v, t] : r.caseOf) targets.insert(t);
            targets.insert(r.defaultTarget);
            if (targets.size() < kMinTargets) continue;
            // A target inside the tree would mean a loop through the
            // dispatch, which this shape cannot express.
            bool bad = false;
            for (int t : targets) if (r.tree.count(t)) bad = true;
            if (bad) continue;

            // Build the new successor list: the default arm last, so the
            // case labels line up with the order they are emitted in.
            std::vector<int> succs;
            for (auto& [v, t] : r.caseOf)
                if (t != r.defaultTarget &&
                    std::find(succs.begin(), succs.end(), t) == succs.end())
                    succs.push_back(t);
            succs.push_back(r.defaultTarget);

            std::set<int> gone = r.tree;
            gone.erase(id);

            std::vector<std::vector<i64>> labels(succs.size());
            for (auto& [v, t] : r.caseOf) {
                if (t == r.defaultTarget) continue;
                auto it = std::find(succs.begin(), succs.end(), t);
                labels[(size_t)(it - succs.begin())].push_back(v);
            }

            // Operand-free values defined in a folded block move up to the
            // head, so the uses that outlive the block still reach them.
            {
                ValueId anchor = f.block(id).insts.back();
                for (int t : gone) {
                    std::vector<ValueId> keep;
                    for (ValueId v : f.block(t).insts) {
                        const ir::Inst& in = f.inst(v);
                        if (!relocatable(in.op)) continue;
                        auto it = uses.find(v);
                        bool escapes = false;
                        if (it != uses.end())
                            for (ValueId u : it->second)
                                if (!gone.count(f.inst(u).block)) escapes = true;
                        if (escapes) keep.push_back(v);
                    }
                    for (ValueId v : keep) {
                        ir::Inst& src = f.inst(v);
                        ir::Inst copy;
                        copy.op = src.op;
                        copy.type = src.type;
                        copy.imm = src.imm;
                        copy.aux = src.aux;
                        copy.loc = src.loc;
                        copy.addr = src.addr;
                        copy.block = id;
                        ValueId moved = f.insertBefore(anchor, std::move(copy));
                        f.replaceAllUses(v, moved);
                    }
                }
            }

            PhiSnapshot snap = snapshotPhis(f);
            std::vector<int> savedSuccs = f.block(id).succs;
            std::vector<std::vector<i64>> savedLabels = f.block(id).caseValues;
            int savedDefault = f.block(id).defaultSucc;
            Op savedOp = f.inst(f.block(id).insts.back()).op;
            std::vector<ValueId> savedArgs = f.inst(f.block(id).insts.back()).args;
            std::map<int, std::vector<int>> savedTreeSuccs;
            for (int t : gone) savedTreeSuccs[t] = f.block(t).succs;

            ir::Inst& tinst = f.inst(f.block(id).insts.back());
            tinst.op = Op::Switch;
            tinst.args.assign(1, head.x);
            ir::Block& head_b = f.block(id);
            head_b.succs = succs;
            head_b.caseValues = std::move(labels);
            head_b.defaultSucc = r.defaultTarget;
            for (int t : gone) f.block(t).succs.clear();
            f.recomputePreds();

            if (!replayPhis(f, snap, gone, id)) {
                // Put everything back; this shape cannot be merged safely.
                for (auto& [t, ss] : savedTreeSuccs) f.block(t).succs = ss;
                ir::Block& hb2 = f.block(id);
                hb2.succs = savedSuccs;
                hb2.caseValues = savedLabels;
                hb2.defaultSucc = savedDefault;
                ir::Inst& t2 = f.inst(hb2.insts.back());
                t2.op = savedOp;
                t2.args = savedArgs;
                f.recomputePreds();
                for (auto& [v, a] : snap.args) f.inst(v).args = a;
                continue;
            }
            ++recovered;
            progress = true;
            break;   // predecessor lists moved; restart the scan
        }
        if (!progress) break;
        f.pruneUnreachableBlocks();
    }
    if (recovered) f.pruneUnreachableBlocks();
    return recovered;
}

} // namespace dc
