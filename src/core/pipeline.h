// The decompiler pipeline: machine function -> IR -> SSA -> ... -> C.
//
// Every stage's output is retained so the CLI can show it.
#pragma once

#include "analysis/arguments.h"
#include "analysis/program.h"
#include "analysis/stack_frame.h"
#include "ir/ir.h"
#include "lift/lifter.h"
#include "analysis/variables.h"
#include "ast/build.h"
#include "cgen/cwriter.h"
#include "opt/passes.h"
#include "types/struct_recovery.h"
#include "types/type_system.h"
#include "winapi/data_analysis.h"
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
    types::TypeResult types;
    VariableMap variables;
    std::vector<const types::Type*> structs;
    types::Confidence confidence = types::Confidence::Medium;
    std::vector<std::string> confidenceReasons;
    std::unique_ptr<ast::Function> ast;
    std::string code;
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

    // Turns the entry values that match parameter locations into Arg nodes and
    // fills in ir::Function::params, so nothing downstream sees a register or
    // a stack slot where a parameter belongs.
    static void bindParameters(FunctionResult& r, unsigned ptrBytes, bool is64);

    // Runs type inference, struct recovery and variable recovery.
    std::unique_ptr<FunctionResult> runToVariables(const Function& f);

    // The whole way: structuring, AST and C.
    std::unique_ptr<FunctionResult> decompile(const Function& f);

    types::TypeTable& typeTable() { return types_; }
    const winapi::DataAnalysis& data();

private:
    Program& prog_;
    PipelineOptions opt_;
    SignatureDatabase sigs_;
    bool sigsBuilt_ = false;
    types::TypeTable types_;
    winapi::DataAnalysis data_;
    bool dataScanned_ = false;
};

} // namespace dc
