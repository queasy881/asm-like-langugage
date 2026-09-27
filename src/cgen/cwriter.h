// C backend: prints the AST as C.
//
// A dedicated printer rather than string surgery, so precedence, associativity
// and formatting are decided in one place and parentheses appear only where
// the grammar needs them.
#pragma once

#include "ast/ast.h"
#include "types/type_system.h"

#include <set>
#include <string>
#include <vector>

namespace dc::cgen {

struct WriterOptions {
    unsigned indentWidth = 4;
    bool braceOnNewLine = true;      // Allman, as in the target output
    bool annotateAddresses = false;  // put the source address on each statement
    bool emitConfidence = true;
    // Prefix added to the recovered functions' own names, so a generated file
    // can be compiled next to the original without colliding with it.
    std::string symbolPrefix;
    // Names that belong to this file, and so take the prefix. Calls to
    // anything else - library routines, imports - are left alone.
    std::set<std::string> localFunctions;
};

std::string writeFunction(const ast::Function& fn, const WriterOptions& opt = {});
// The function's signature, for a forward declaration.
std::string writeDeclaration(const ast::Function& fn, const WriterOptions& opt = {});
// A complete compilable file: preamble, structures, declarations, bodies.
std::string writeProgram(const std::vector<const ast::Function*>& functions,
                         const std::vector<const types::Type*>& structs,
                         const WriterOptions& opt = {});
// Declarations for the structures a function refers to.
std::string writeStructs(const std::vector<const types::Type*>& structs);
// The preamble of Windows type aliases the output relies on.
std::string writePreamble();

} // namespace dc::cgen
