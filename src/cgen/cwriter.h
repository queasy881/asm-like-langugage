// C backend: prints the AST as C.
//
// A dedicated printer rather than string surgery, so precedence, associativity
// and formatting are decided in one place and parentheses appear only where
// the grammar needs them.
#pragma once

#include "ast/ast.h"
#include "types/type_system.h"

#include <string>

namespace dc::cgen {

struct WriterOptions {
    unsigned indentWidth = 4;
    bool braceOnNewLine = true;      // Allman, as in the target output
    bool annotateAddresses = false;  // put the source address on each statement
    bool emitConfidence = true;
};

std::string writeFunction(const ast::Function& fn, const WriterOptions& opt = {});
// Declarations for the structures a function refers to.
std::string writeStructs(const std::vector<const types::Type*>& structs);
// The preamble of Windows type aliases the output relies on.
std::string writePreamble();

} // namespace dc::cgen
