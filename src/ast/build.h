// Builds the high-level AST from optimised SSA.
//
// Expressions are reconstructed by inlining every value the variable pass
// marked as an expression, so the output reads as arithmetic rather than a
// sequence of temporaries. Memory accesses become member, index or
// dereference expressions according to the recovered types.
#pragma once

#include "analysis/arguments.h"
#include "analysis/program.h"
#include "analysis/variables.h"
#include "ast/ast.h"
#include "structure/structurer.h"
#include "types/infer.h"
#include "winapi/data_analysis.h"

namespace dc::ast {

struct BuildInputs {
    Program* prog = nullptr;
    ir::Function* ir = nullptr;
    const VariableMap* variables = nullptr;
    const types::TypeResult* types = nullptr;
    const Signature* signature = nullptr;
    const StackFrame* frame = nullptr;
    types::TypeTable* typeTable = nullptr;
    const winapi::DataAnalysis* data = nullptr;
    const SignatureDatabase* signatures = nullptr;
    types::Confidence confidence = types::Confidence::Medium;
    std::vector<std::string> notes;
};

std::unique_ptr<Function> buildFunction(const BuildInputs& in);

} // namespace dc::ast
