#pragma once
#include "ir/ir.h"

namespace dc {

// Rebuilds short-circuit conditions. A compiler turns `a && b` into two
// branches, and structuring those faithfully needs a goto for every arm that
// rejoins. Folding the chain back into one condition is what recovers the
// if / else if the source was written with. Returns how many were folded.
int foldShortCircuits(ir::Function& f);

} // namespace dc
