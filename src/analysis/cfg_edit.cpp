#include "analysis/cfg_edit.h"

#include <algorithm>

namespace dc {

using ir::Op;
using ir::ValueId;
using ir::kNoValue;

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

bool replayPhis(ir::Function& f, const PhiSnapshot& snap, const std::set<int>& folded, int into) {
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
                    bool match = oldPreds[i] == p || (p == into && folded.count(oldPreds[i]));
                    if (!match) continue;
                    if (pick == kNoValue) pick = oldArgs[i];
                    else if (pick != oldArgs[i]) many = true;
                }
                if (many || pick == kNoValue) return false;
                args.push_back(pick);
            }
            in.args = std::move(args);
        }
    }
    return true;
}

void restorePhis(ir::Function& f, const PhiSnapshot& snap) {
    for (const auto& [v, a] : snap.args)
        if (f.valid(v)) f.inst(v).args = a;
}

} // namespace dc
