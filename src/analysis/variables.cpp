#include "analysis/variables.h"

#include "analysis/graph.h"

#include <algorithm>
#include <functional>
#include <set>

namespace dc {

using ir::Op;
using ir::ValueId;
using ir::kNoValue;

namespace {

// Union-find over the values a phi forces to share storage.
struct Coalescer {
    std::unordered_map<ValueId, ValueId> parent;
    ValueId find(ValueId v) {
        auto it = parent.find(v);
        if (it == parent.end()) {
            parent[v] = v;
            return v;
        }
        while (parent[v] != v) {
            parent[v] = parent[parent[v]];
            v = parent[v];
        }
        return v;
    }
    void unite(ValueId a, ValueId b) {
        a = find(a);
        b = find(b);
        if (a != b) parent[b] = a;
    }
};

bool isCheapLeaf(const ir::Inst& in) {
    return in.op == Op::Const || in.op == Op::GlobalAddr || in.op == Op::FrameAddr || in.op == Op::Undef ||
           in.op == Op::Arg;
}

bool mayWriteMemory(const ir::Inst& in) {
    return in.op == Op::Store || in.op == Op::Call || (in.op == Op::Intrinsic && in.aux);
}

// Live ranges over SSA values, at instruction granularity.
//
// A range is half open: it starts just after the defining instruction and
// ends at the last instruction that reads it. Two values whose ranges only
// touch - the second defined exactly where the first is last read - do not
// interfere, which is what lets a loop variable and its next value share one
// name instead of needing a copy.
struct Liveness {
    struct Range {
        int start = 0;   // index just after the definition, or 0 when live-in
        int end = 0;     // index of the last use, or the block length
    };
    std::vector<std::unordered_map<ValueId, Range>> ranges; // per block

    bool interfere(ValueId a, ValueId b) const {
        for (const auto& blockRanges : ranges) {
            auto ia = blockRanges.find(a);
            if (ia == blockRanges.end()) continue;
            auto ib = blockRanges.find(b);
            if (ib == blockRanges.end()) continue;
            // Open intervals: (start, end].
            if (ia->second.start < ib->second.end && ib->second.start < ia->second.end) return true;
        }
        return false;
    }
};

Liveness computeLiveness(const ir::Function& f) {
    int n = f.blockCount();
    std::vector<std::set<ValueId>> liveIn(n), liveOut(n);

    // Standard backward liveness. A phi argument is live out of the matching
    // predecessor, not live in to the block holding the phi.
    bool changed = true;
    int guard = 0;
    while (changed && guard++ < 64) {
        changed = false;
        for (int b = n - 1; b >= 0; --b) {
            std::set<ValueId> out;
            for (int s : f.block(b).succs) {
                for (ValueId v : liveIn[s]) out.insert(v);
                // Values the successor's phis read on this edge.
                const auto& preds = f.block(s).preds;
                size_t slot = (size_t)(std::find(preds.begin(), preds.end(), b) - preds.begin());
                for (ValueId v : f.block(s).insts) {
                    const ir::Inst& in = f.inst(v);
                    if (in.op != Op::Phi) break;
                    if (slot < in.args.size() && in.args[slot] != kNoValue) out.insert(in.args[slot]);
                }
            }
            std::set<ValueId> in = out;
            const auto& list = f.block(b).insts;
            for (size_t i = list.size(); i-- > 0;) {
                ValueId v = list[i];
                const ir::Inst& inst = f.inst(v);
                in.erase(v);
                if (inst.op == Op::Phi) continue; // its arguments belong to the edges
                for (ValueId a : inst.args)
                    if (a != kNoValue) in.insert(a);
            }
            if (in != liveIn[b] || out != liveOut[b]) {
                liveIn[b] = std::move(in);
                liveOut[b] = std::move(out);
                changed = true;
            }
        }
    }

    Liveness lv;
    lv.ranges.resize(n);
    for (int b = 0; b < n; ++b) {
        const auto& list = f.block(b).insts;
        int len = (int)list.size();
        std::unordered_map<ValueId, int> defIndex;
        for (int i = 0; i < len; ++i) defIndex[list[i]] = i;

        auto& out = lv.ranges[b];
        auto note = [&](ValueId v, int start, int end) {
            auto it = out.find(v);
            if (it == out.end()) out[v] = {start, end};
            else {
                it->second.start = std::min(it->second.start, start);
                it->second.end = std::max(it->second.end, end);
            }
        };
        for (ValueId v : liveIn[b]) note(v, 0, 0);
        for (int i = 0; i < len; ++i) {
            const ir::Inst& inst = f.inst(list[i]);
            if (inst.op != Op::Phi)
                for (ValueId a : inst.args)
                    if (a != kNoValue) note(a, defIndex.count(a) ? defIndex[a] : 0, i);
            if (!inst.type.isVoid()) note(list[i], i, i);
        }
        for (ValueId v : liveOut[b]) note(v, defIndex.count(v) ? defIndex[v] : 0, len);
    }
    return lv;
}

} // namespace

VariableMap recoverVariables(ir::Function& f, const types::TypeResult& types, const StackFrame& frame) {
    (void)frame;
    VariableMap map;

    auto uses = f.buildUses();
    // Position of each value in its block, for interference checks.
    std::unordered_map<ValueId, int> pos;
    for (const auto& b : f.blocks())
        for (size_t i = 0; i < b.insts.size(); ++i) pos[b.insts[i]] = (int)i;

    // 2. Coalesce the values that must share a variable.
    //
    // A phi and one of its arguments may share storage only when their live
    // ranges do not overlap. Merging without that check turns a loop counter
    // and an accumulator into one variable when they happen to start from the
    // same constant; refusing to merge at all leaves a copy statement at the
    // bottom of every loop. Live ranges are tracked per instruction, so the
    // usual case - where the argument is defined exactly where the phi's
    // value is last read - coalesces cleanly.
    Liveness live = computeLiveness(f);

    Coalescer co;
    // Members of each web so far, so interference is checked against all of
    // them rather than just the representative.
    std::unordered_map<ValueId, std::vector<ValueId>> web;
    auto membersOf = [&](ValueId r) -> std::vector<ValueId>& {
        auto& w = web[r];
        if (w.empty()) w.push_back(r);
        return w;
    };

    for (const auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.op != Op::Phi) continue;
            for (ValueId a : in.args) {
                if (a == kNoValue || a == v) continue;
                if (isCheapLeaf(f.inst(a))) continue;
                ValueId rv = co.find(v), ra = co.find(a);
                if (rv == ra) continue;
                if (f.inst(v).type != f.inst(a).type) continue;
                bool conflict = false;
                for (ValueId x : membersOf(rv)) {
                    for (ValueId y : membersOf(ra))
                        if (live.interfere(x, y)) { conflict = true; break; }
                    if (conflict) break;
                }
                if (conflict) continue;
                auto& dst = membersOf(rv);
                auto& src = membersOf(ra);
                std::vector<ValueId> merged = dst;
                merged.insert(merged.end(), src.begin(), src.end());
                co.unite(v, a);
                web[co.find(v)] = std::move(merged);
            }
        }
    }


    // 3. Decide what can stay an expression rather than becoming a variable.
    //
    // Inlining moves a computation down to its use, so it is only sound when
    // nothing in between changes what that computation reads. Checking memory
    // writes is not enough: the variables the expression reads must not be
    // reassigned either, which happens constantly once a pointer and its
    // increment share a name.
    auto variableOfValue = [&](ValueId v) -> int {
        ValueId root = co.find(v);
        return (int)root;  // web identity is enough for the comparison below
    };
    for (const auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.type.isVoid() || in.op == Op::Phi || in.op == Op::Arg) continue;
            auto it = uses.find(v);
            size_t useCount = it == uses.end() ? 0 : it->second.size();
            if (isCheapLeaf(in)) {
                map.inlined.insert(v);
                continue;
            }
            if (useCount != 1) continue;
            ValueId user = it->second[0];
            const ir::Inst& ui = f.inst(user);
            if (ui.op == Op::Phi) continue;      // a phi argument needs storage
            if (ui.block != in.block) continue;  // keep it where it was computed
            if (mayWriteMemory(in)) continue;    // calls and stores stay statements
            if (in.op == Op::Intrinsic) continue;

            // Values the expression reads, following anything already inlined.
            std::set<ValueId> reads;
            std::function<void(ValueId, int)> gather = [&](ValueId x, int depth) {
                if (depth > 32) return;
                for (ValueId a : f.inst(x).args) {
                    if (a == kNoValue) continue;
                    reads.insert(a);
                    if (map.inlined.count(a)) gather(a, depth + 1);
                }
            };
            gather(v, 0);
            std::set<int> readWebs;
            for (ValueId r : reads) readWebs.insert(variableOfValue(r));

            bool blocked = false;
            const auto& list = f.block(in.block).insts;
            for (int i = pos[v] + 1; i < pos[user] && !blocked; ++i) {
                const ir::Inst& mid = f.inst(list[i]);
                if (in.op == Op::Load && mayWriteMemory(mid)) blocked = true;
                if (mid.type.isVoid()) continue;
                // A value written here shares a name with something we read.
                if (readWebs.count(variableOfValue(list[i]))) blocked = true;
            }
            if (blocked) continue;
            map.inlined.insert(v);
        }
    }

    // 4. Create a variable per remaining class.
    std::unordered_map<ValueId, int> classToVar;
    auto ensureVar = [&](ValueId v) -> int {
        ValueId root = co.find(v);
        auto it = classToVar.find(root);
        if (it != classToVar.end()) return it->second;
        Variable var;
        var.id = (int)map.variables.size();
        var.type = types.of(v);
        classToVar[root] = var.id;
        map.variables.push_back(std::move(var));
        return map.variables.back().id;
    };

    for (auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.type.isVoid()) continue;
            if (map.isInlined(v)) continue;
            int id = ensureVar(v);
            map.variables[id].values.push_back(v);
            map.ofValue[v] = id;
            if (in.op == Op::Arg) {
                map.variables[id].isParam = true;
                map.variables[id].paramIndex = (int)in.aux;
            }
            // Prefer the most confident type the class saw.
            types::TypeRef t = types.of(v);
            if (t && (!map.variables[id].type || map.variables[id].type->kind == types::Kind::Unknown))
                map.variables[id].type = t;
        }
    }
    // A phi argument that got inlined still needs its variable, because the
    // phi reads it on the edge.
    for (auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.op != Op::Phi) continue;
            for (ValueId a : in.args) {
                if (a == kNoValue || !map.isInlined(a)) continue;
                if (isCheapLeaf(f.inst(a))) continue;
                map.inlined.erase(a);
                int id = ensureVar(a);
                map.variables[id].values.push_back(a);
                map.ofValue[a] = id;
            }
        }
    }

    // 5. Usage counts and single-assignment detection.
    for (auto& var : map.variables) {
        var.singleAssignment = var.values.size() == 1 && !var.isParam;
        for (ValueId v : var.values) {
            auto it = uses.find(v);
            var.uses += it == uses.end() ? 0 : (unsigned)it->second.size();
        }
    }

    // 6. Naming. The value that reaches a return is `result`; a pointer that a
    //    loop advances is `p`; a one-bit value is `flag`; parameters keep
    //    their positional names; everything else is numbered.
    std::unordered_set<int> returned;
    for (const auto& b : f.blocks()) {
        if (b.insts.empty()) continue;
        const ir::Inst& term = f.inst(b.insts.back());
        if (term.op == Op::Return && !term.args.empty()) {
            auto it = map.ofValue.find(term.args[0]);
            if (it != map.ofValue.end()) returned.insert(it->second);
        }
    }
    std::unordered_set<int> advancedPointers;
    for (const auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.op != Op::Phi) continue;
            auto it = map.ofValue.find(v);
            if (it == map.ofValue.end()) continue;
            types::TypeRef t = map.variables[it->second].type;
            if (!t || !t->isPointer()) continue;
            // A pointer phi whose other argument adds to it walks memory.
            for (ValueId a : in.args) {
                if (a == kNoValue) continue;
                const ir::Inst& ai = f.inst(a);
                if (ai.op == Op::Add) advancedPointers.insert(it->second);
            }
        }
    }

    int nextTemp = 1;
    int nextPointer = 0;
    int nextFlag = 0;
    bool usedResult = false;
    for (auto& var : map.variables) {
        if (var.isParam) {
            var.name = strfmt("arg%d", var.paramIndex + 1);
            continue;
        }
        if (returned.count(var.id) && !usedResult) {
            var.name = "result";
            var.isReturnValue = true;
            usedResult = true;
            continue;
        }
        if (advancedPointers.count(var.id)) {
            var.name = nextPointer == 0 ? "p" : strfmt("p%d", nextPointer + 1);
            ++nextPointer;
            continue;
        }
        if (var.type && var.type->kind == types::Kind::Bool) {
            var.name = nextFlag == 0 ? "flag" : strfmt("flag%d", nextFlag + 1);
            ++nextFlag;
            continue;
        }
        var.name = strfmt("var%d", nextTemp++);
    }
    return map;
}

} // namespace dc
