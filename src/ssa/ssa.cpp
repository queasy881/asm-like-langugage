#include "ssa/ssa.h"

#include "analysis/graph.h"

#include <algorithm>
#include <set>

namespace dc::ssa {

using ir::Op;
using ir::ValueId;
using ir::kNoValue;

namespace {

// Per-block summary of a variable's accesses, used both for phi placement and
// for the liveness that prunes them.
struct BlockVarInfo {
    std::vector<bool> defs;      // variable defined somewhere in the block
    std::vector<bool> upward;    // read before any definition in the block
    std::vector<bool> liveIn;
    std::vector<bool> liveOut;
};

} // namespace

SsaInfo construct(ir::Function& f) {
    SsaInfo info;
    int nb = f.blockCount();
    if (nb == 0) return info;

    // 1. Collect the variables.
    for (const auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.op != Op::ReadLoc && in.op != Op::WriteLoc) continue;
            u32 key = in.loc.key();
            auto it = info.varOfKey.find(key);
            if (it == info.varOfKey.end()) {
                Variable var;
                var.loc = in.loc;
                var.type = in.op == Op::ReadLoc ? in.type : f.inst(in.args[0]).type;
                info.varOfKey[key] = (int)info.variables.size();
                info.variables.push_back(var);
            } else {
                // Widths agree by construction; keep the widest just in case.
                Variable& var = info.variables[it->second];
                ir::Type t = in.op == Op::ReadLoc ? in.type : f.inst(in.args[0]).type;
                if (t.bits > var.type.bits) var.type = t;
            }
        }
    }
    int nv = (int)info.variables.size();
    if (nv == 0) return info;

    // 2. Per-block definition and upward-exposed-use sets.
    BlockVarInfo bvi;
    bvi.defs.assign((size_t)nb * nv, false);
    bvi.upward.assign((size_t)nb * nv, false);
    bvi.liveIn.assign((size_t)nb * nv, false);
    bvi.liveOut.assign((size_t)nb * nv, false);
    auto idx = [&](int b, int v) { return (size_t)b * nv + v; };

    for (const auto& b : f.blocks()) {
        std::vector<bool> defined(nv, false);
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.op == Op::ReadLoc) {
                int vi = info.indexOf(in.loc);
                if (vi >= 0 && !defined[vi]) bvi.upward[idx(b.id, vi)] = true;
            } else if (in.op == Op::WriteLoc) {
                int vi = info.indexOf(in.loc);
                if (vi >= 0) {
                    defined[vi] = true;
                    bvi.defs[idx(b.id, vi)] = true;
                }
            }
        }
    }

    // 3. Liveness, so phis are only placed where the value is really needed.
    bool changed = true;
    while (changed) {
        changed = false;
        for (int b = nb - 1; b >= 0; --b) {
            for (int v = 0; v < nv; ++v) {
                bool out = false;
                for (int s : f.block(b).succs)
                    if (bvi.liveIn[idx(s, v)]) { out = true; break; }
                bool in = bvi.upward[idx(b, v)] || (out && !bvi.defs[idx(b, v)]);
                if (out != bvi.liveOut[idx(b, v)] || in != bvi.liveIn[idx(b, v)]) {
                    bvi.liveOut[idx(b, v)] = out;
                    bvi.liveIn[idx(b, v)] = in;
                    changed = true;
                }
            }
        }
    }

    // 4. Dominance frontiers.
    Digraph g = f.cfg();
    DomTree dom = DomTree::build(g);
    auto df = dom.frontiers(g);

    // 5. Phi placement (Cytron), filtered by liveness.
    std::vector<std::vector<ValueId>> phiOf(nb, std::vector<ValueId>(nv, kNoValue));
    for (int v = 0; v < nv; ++v) {
        std::vector<int> work;
        std::vector<bool> onWork(nb, false);
        for (int b = 0; b < nb; ++b)
            if (bvi.defs[idx(b, v)]) { work.push_back(b); onWork[b] = true; }
        std::vector<bool> hasPhi(nb, false);
        while (!work.empty()) {
            int b = work.back();
            work.pop_back();
            for (int y : df[b]) {
                if (hasPhi[y]) continue;
                hasPhi[y] = true;
                if (!bvi.liveIn[idx(y, v)]) {
                    ++info.phisPruned;
                } else {
                    ir::Inst phi;
                    phi.op = Op::Phi;
                    phi.type = info.variables[v].type;
                    phi.loc = info.variables[v].loc;
                    phi.args.assign(f.block(y).preds.size(), kNoValue);
                    phi.addr = f.block(y).addr;
                    ValueId p = f.add(y, std::move(phi));
                    // Move it to the top of the block.
                    auto& list = f.block(y).insts;
                    list.pop_back();
                    size_t pos = 0;
                    while (pos < list.size() && f.inst(list[pos]).op == Op::Phi) ++pos;
                    list.insert(list.begin() + pos, p);
                    phiOf[y][v] = p;
                    ++info.phisInserted;
                }
                if (!bvi.defs[idx(y, v)] && !onWork[y]) {
                    onWork[y] = true;
                    work.push_back(y);
                }
            }
        }
    }

    // 6. Entry definitions for variables live on entry.
    for (int v = 0; v < nv; ++v) {
        if (!bvi.liveIn[idx(0, v)]) continue;
        ir::Inst ev;
        ev.op = Op::EntryValue;
        ev.type = info.variables[v].type;
        ev.loc = info.variables[v].loc;
        ev.addr = f.entryAddr();
        ValueId e = f.add(0, std::move(ev));
        auto& list = f.block(0).insts;
        list.pop_back();
        size_t pos = 0;
        while (pos < list.size() && f.inst(list[pos]).op == Op::Phi) ++pos;
        list.insert(list.begin() + pos, e);
        info.variables[v].entryValue = e;
        info.variables[v].liveOnEntry = true;
    }

    // 7. Renaming over the dominator tree.
    std::vector<std::vector<ValueId>> stacks(nv);
    for (int v = 0; v < nv; ++v)
        if (info.variables[v].entryValue != kNoValue) stacks[v].push_back(info.variables[v].entryValue);

    struct Frame {
        int block;
        size_t childIndex;
        std::vector<std::pair<int, size_t>> pushed; // variable -> stack depth before
    };
    std::vector<Frame> stack;
    auto currentOf = [&](int v) -> ValueId { return stacks[v].empty() ? kNoValue : stacks[v].back(); };

    auto processBlock = [&](int b, Frame& fr) {
        // Phis define their variable.
        for (ValueId v : f.block(b).insts) {
            const ir::Inst& in = f.inst(v);
            if (in.op != Op::Phi) break;
            int vi = info.indexOf(in.loc);
            if (vi < 0) continue;
            fr.pushed.push_back({vi, stacks[vi].size()});
            stacks[vi].push_back(v);
        }
        for (ValueId v : f.block(b).insts) {
            ir::Inst& in = f.inst(v);
            if (in.op == Op::ReadLoc) {
                int vi = info.indexOf(in.loc);
                ValueId cur = vi >= 0 ? currentOf(vi) : kNoValue;
                if (cur == kNoValue) {
                    // Reading a location with no reaching definition: the
                    // value is genuinely undefined.
                    in.op = Op::Undef;
                    in.loc = ir::Loc{};
                    in.args.clear();
                } else {
                    f.replaceAllUses(v, cur);
                    in.dead = true;
                }
            } else if (in.op == Op::WriteLoc) {
                int vi = info.indexOf(in.loc);
                if (vi >= 0) {
                    fr.pushed.push_back({vi, stacks[vi].size()});
                    stacks[vi].push_back(in.args[0]);
                }
                in.dead = true;
            }
        }
        // Fill in the phi arguments of the successors. A variable with no
        // reaching definition on this edge needs an explicit undefined value,
        // created here and inserted once the successor scan is done.
        std::vector<std::pair<ValueId, size_t>> pendingUndef; // phi -> slot
        std::vector<int> undefVars;
        for (int s : f.block(b).succs) {
            const auto& preds = f.block(s).preds;
            size_t slot = (size_t)(std::find(preds.begin(), preds.end(), b) - preds.begin());
            if (slot >= preds.size()) continue;
            for (ValueId v : f.block(s).insts) {
                ir::Inst& in = f.inst(v);
                if (in.op != Op::Phi) break;
                int vi = info.indexOf(in.loc);
                if (vi < 0 || slot >= in.args.size()) continue;
                ValueId cur = currentOf(vi);
                if (cur == kNoValue) {
                    pendingUndef.push_back({v, slot});
                    undefVars.push_back(vi);
                    continue;
                }
                in.args[slot] = cur;
            }
        }
        for (size_t i = 0; i < pendingUndef.size(); ++i) {
            ir::Inst u;
            u.op = Op::Undef;
            u.type = info.variables[undefVars[i]].type;
            ValueId uv = f.add(b, std::move(u));
            auto& list = f.block(b).insts;
            list.pop_back();
            size_t pos = 0;
            while (pos < list.size() && f.inst(list[pos]).op == Op::Phi) ++pos;
            list.insert(list.begin() + pos, uv);
            f.inst(pendingUndef[i].first).args[pendingUndef[i].second] = uv;
        }
    };

    stack.push_back({dom.root(), 0, {}});
    {
        Frame& fr = stack.back();
        processBlock(dom.root(), fr);
    }
    while (!stack.empty()) {
        Frame& fr = stack.back();
        const auto& kids = dom.children(fr.block);
        if (fr.childIndex < kids.size()) {
            int child = kids[fr.childIndex++];
            stack.push_back({child, 0, {}});
            processBlock(child, stack.back());
        } else {
            for (auto it = fr.pushed.rbegin(); it != fr.pushed.rend(); ++it)
                stacks[it->first].resize(it->second);
            stack.pop_back();
        }
    }

    f.removeDeadInsts();
    simplifyPhis(f);
    return info;
}

int simplifyPhis(ir::Function& f) {
    int removed = 0;
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto& b : f.blocks()) {
            for (ValueId v : b.insts) {
                ir::Inst& in = f.inst(v);
                if (in.op != Op::Phi || in.dead) continue;
                ValueId same = kNoValue;
                bool trivial = true;
                for (ValueId a : in.args) {
                    if (a == v || a == kNoValue) continue;
                    if (same == kNoValue) same = a;
                    else if (same != a) { trivial = false; break; }
                }
                if (!trivial) continue;
                if (same == kNoValue) {
                    in.op = Op::Undef;
                    in.args.clear();
                    in.loc = ir::Loc{};
                    continue;
                }
                f.replaceAllUses(v, same);
                in.dead = true;
                ++removed;
                changed = true;
            }
        }
        if (changed) f.removeDeadInsts();
    }
    return removed;
}

std::vector<std::string> verify(const ir::Function& f) {
    std::vector<std::string> errs;
    auto err = [&](std::string s) {
        if (errs.size() < 32) errs.push_back(std::move(s));
    };
    Digraph g = f.cfg();
    DomTree dom = DomTree::build(g);

    // Position of each value inside its block, for intra-block ordering checks.
    std::unordered_map<ValueId, int> pos;
    for (const auto& b : f.blocks())
        for (size_t i = 0; i < b.insts.size(); ++i) pos[b.insts[i]] = (int)i;

    for (const auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.op == Op::ReadLoc || in.op == Op::WriteLoc)
                err(strfmt("%s: location access left after SSA construction", ir::valueName(v).c_str()));
            if (in.op == Op::Phi) {
                if (in.args.size() != b.preds.size()) {
                    err(strfmt("%s: phi has %zu args, block %d has %zu preds", ir::valueName(v).c_str(),
                               in.args.size(), b.id, b.preds.size()));
                    continue;
                }
                for (size_t i = 0; i < in.args.size(); ++i) {
                    ValueId a = in.args[i];
                    if (a == kNoValue) {
                        err(strfmt("%s: phi argument %zu is unset", ir::valueName(v).c_str(), i));
                        continue;
                    }
                    int defBlock = f.inst(a).block;
                    if (!dom.dominates(defBlock, b.preds[i]))
                        err(strfmt("%s: phi argument %s from block %d is not available there",
                                   ir::valueName(v).c_str(), ir::valueName(a).c_str(), b.preds[i]));
                }
                continue;
            }
            for (ValueId a : in.args) {
                if (a == kNoValue) continue;
                int defBlock = f.inst(a).block;
                if (defBlock == b.id) {
                    if (pos.count(a) && pos[a] >= pos[v])
                        err(strfmt("%s: uses %s before it is defined", ir::valueName(v).c_str(), ir::valueName(a).c_str()));
                } else if (!dom.dominates(defBlock, b.id)) {
                    err(strfmt("%s: uses %s whose definition does not dominate block %d",
                               ir::valueName(v).c_str(), ir::valueName(a).c_str(), b.id));
                }
            }
        }
    }
    return errs;
}

} // namespace dc::ssa
