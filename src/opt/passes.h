// IR optimisation passes.
//
// These exist to make the eventual C readable, not to make it fast, so every
// pass is required to preserve semantics exactly. In particular nothing here
// assumes absence of overflow, reorders memory, or drops a side effect.
#pragma once

#include "ir/ir.h"

namespace dc::opt {

struct Stats {
    int constantsFolded = 0;
    int copiesPropagated = 0;
    int instructionsRemoved = 0;
    int expressionsShared = 0;
    int algebraicSimplifications = 0;
    int branchesSimplified = 0;
    int castsRemoved = 0;
    int valuesNarrowed = 0;
    int loadsForwarded = 0;
    int phisRemoved = 0;
    int rounds = 0;

    std::string print() const;
    int total() const {
        return constantsFolded + copiesPropagated + instructionsRemoved + expressionsShared +
               algebraicSimplifications + branchesSimplified + castsRemoved + valuesNarrowed +
               loadsForwarded + phisRemoved;
    }
};

// Individual passes. Each returns the number of changes it made.
int constantFold(ir::Function& f);
int algebraicSimplify(ir::Function& f);
int deadCodeElimination(ir::Function& f);
int commonSubexpressionElimination(ir::Function& f);
int simplifyBranches(ir::Function& f);
int forwardStackLoads(ir::Function& f);
// Rewrites values whose upper bits are never observed to their natural width,
// which is what removes the casts left over from sub-register writes.
int narrowByDemandedBits(ir::Function& f);

// Runs the passes to a fixed point.
Stats optimize(ir::Function& f, int maxRounds = 12);

// Evaluates a binary or unary operation on constants. Returns false when the
// operation has no defined constant result (division by zero, for example).
bool evalConst(ir::Op op, ir::Type type, u64 a, u64 b, u64& out);

} // namespace dc::opt
