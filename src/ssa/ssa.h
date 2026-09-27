// SSA construction over IR locations.
//
// Pruned placement: a phi is only created where the variable is actually live
// at the block entry, which keeps the phi count close to the minimum that the
// program's data flow requires.
#pragma once

#include "ir/ir.h"

#include <unordered_map>

namespace dc::ssa {

struct Variable {
    ir::Loc loc;
    ir::Type type;
    ir::ValueId entryValue = ir::kNoValue; // definition on entry, if live-in
    bool liveOnEntry = false;
};

struct SsaInfo {
    std::vector<Variable> variables;
    std::unordered_map<u32, int> varOfKey; // Loc::key() -> index
    int phisInserted = 0;
    int phisPruned = 0;   // phis the liveness filter avoided creating

    int indexOf(ir::Loc l) const {
        auto it = varOfKey.find(l.key());
        return it == varOfKey.end() ? -1 : it->second;
    }
};

// Converts ReadLoc/WriteLoc into values and phis. The function is left in SSA
// form with no location accesses remaining.
SsaInfo construct(ir::Function& f);

// Checks the SSA invariants: every use dominated by its definition, phi
// argument count matching predecessors, no location accesses left.
std::vector<std::string> verify(const ir::Function& f);

// Removes phis whose arguments are all the same value (or the phi itself),
// repeatedly. Returns the number removed.
int simplifyPhis(ir::Function& f);

} // namespace dc::ssa
