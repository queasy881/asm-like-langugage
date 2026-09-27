#pragma once
#include "ir/ir.h"

namespace dc {

// Rebuilds switch statements from the comparison trees compilers emit for
// sparse case labels. Without this a twenty-arm switch decompiles as twenty
// nested if / else levels, which is faithful to the machine code and useless
// to a reader. Returns the number of switches recovered.
int recoverSwitches(ir::Function& f);

} // namespace dc
