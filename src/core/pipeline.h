// The decompiler pipeline: machine function -> IR -> SSA -> ... -> C.
//
// Every stage's output is retained so the CLI can show it.
#pragma once

#include "analysis/arguments.h"
#include "analysis/program.h"
#include "analysis/stack_frame.h"
#include "ir/ir.h"
#include "lift/lifter.h"
#include "opt/passes.h"
#include "ssa/ssa.h"

#include <memory>

namespace dc {

struct PipelineOptions {
    bool optimize = true;
    bool verifyStages = false;   // run the verifiers and record failures
};

// The state of one function as it moves through the pipeline.
struct FunctionResult {
    const Function* machine = nullptr;
    std::unique_ptr<ir::Function> ir;
    StackFrame frame;
    ssa::SsaInfo ssa;
    opt::Stats optStats;
    CallConv convention = CallConv::Unknown;
    Signature signature;
    std::vector<std::string> unsupported;
    std::vector<std::string> problems;
    bool ssaBuilt = false;
};

class Pipeline {
public:
    Pipeline(Program& prog, PipelineOptions opt = {});

    // Recovers every function's signature first, so each function is lifted
    // with exact knowledge of what its callees consume and return.
    void buildSignatures();
    const SignatureDatabase& signatures() const { return sigs_; }

    // Runs every stage up to SSA for one function.
    std::unique_ptr<FunctionResult> runToSsa(const Function& f);
    // ... and then the optimisation passes.
    std::unique_ptr<FunctionResult> runToOptimized(const Function& f);

private:
    Program& prog_;
    PipelineOptions opt_;
    SignatureDatabase sigs_;
    bool sigsBuilt_ = false;
};

} // namespace dc
