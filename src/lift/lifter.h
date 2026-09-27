// x86 / x64 -> IR lifter.
//
// Lifts one discovered machine function into pre-SSA IR. Unsupported
// instructions are never silently dropped: they become an Intrinsic that
// clobbers what the instruction writes and a note on the function, so later
// stages know the IR is incomplete there.
#pragma once

#include "analysis/calling_convention.h"
#include "analysis/program.h"
#include "ir/ir.h"
#include "lift/machine_state.h"

#include <functional>
#include <memory>

namespace dc::lift {

// What the lifter knows about a callee. Filled in by the pipeline, which
// analyses callees before their callers so argument counts are exact.
struct CalleeSignature {
    bool known = false;
    CallConv conv = CallConv::Unknown;
    std::vector<ir::Type> paramTypes;   // in argument order
    ir::Type returnType = ir::Type::voidTy();
    bool variadic = false;
    bool noReturn = false;
    unsigned stackBytesCleaned = 0;     // callee-cleanup conventions
    std::string name;
};

// Resolves the signature of a call target. `imp` is set for imports.
using SignatureResolver = std::function<bool(u64 target, const pe::Import* imp, CalleeSignature& out)>;

struct LiftOptions {
    bool commentInstructions = true; // annotate IR with the source mnemonic
    CallConv convention = CallConv::Unknown; // of the function being lifted
    SignatureResolver resolveCallee;
    // Return type of the function being lifted. Void with returnTypeKnown
    // set means it returns nothing, so no return register is read.
    ir::Type returnType;
    bool returnTypeKnown = false;
    unsigned stackBytesCleaned = 0;
};

struct LiftResult {
    std::unique_ptr<ir::Function> func;
    std::vector<std::string> unsupported; // distinct unsupported mnemonics
    // Machine block id -> IR block id.
    std::vector<int> blockMap;
};

// Lifts `f` (already discovered by Program) into IR.
LiftResult liftFunction(Program& prog, const Function& f, const LiftOptions& opt = {});

// Exposed for tests: the width every register family is accessed at.
std::array<u8, (size_t)x86::Family::Count> electRegisterWidths(const Function& f, bool is64);

} // namespace dc::lift
