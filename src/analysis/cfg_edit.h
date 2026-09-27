#pragma once
#include "ir/ir.h"

#include <map>
#include <set>
#include <vector>

namespace dc {

// Phi arguments are positional against the predecessor list, so any change to
// that list has to move them with it. A pass snapshots the old lists, rewires
// the edges, recomputes predecessors, and then replays.
struct PhiSnapshot {
    std::map<int, std::vector<int>> preds;
    std::map<ir::ValueId, std::vector<ir::ValueId>> args;
};

PhiSnapshot snapshotPhis(const ir::Function& f);

// `folded` names predecessors that went away because `into` absorbed them.
// Returns false when the values they carried disagree, which would make the
// merge lose information; the caller must then undo its rewiring.
bool replayPhis(ir::Function& f, const PhiSnapshot& snap, const std::set<int>& folded, int into);

// Restores every phi argument list recorded in the snapshot.
void restorePhis(ir::Function& f, const PhiSnapshot& snap);

} // namespace dc
