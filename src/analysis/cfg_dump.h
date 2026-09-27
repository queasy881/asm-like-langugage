// Human-readable dumps of discovered functions and their CFGs.
#pragma once

#include "analysis/program.h"

#include <string>

namespace dc {

std::string dumpFunctionList(const Program& prog);
std::string dumpFunctionBlocks(const Function& f, bool withInstructions);
std::string dumpCfg(const Program& prog, const Function& f);

} // namespace dc
