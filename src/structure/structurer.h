// Control-flow structuring: CFG -> structured statements.
//
// Regions are recovered from the dominator and post-dominator trees. Loops
// come from the natural loops of the CFG and are emitted as while, do-while
// or for; conditional regions become if / else if; jump tables become switch.
// A goto is only produced where a region genuinely cannot be expressed
// otherwise, and the count is reported so the output stays honest.
#pragma once

#include "analysis/graph.h"
#include "ast/ast.h"
#include "ir/ir.h"

namespace dc::structure {

// The statements of each block, supplied by the AST builder. Keeping this
// behind an interface lets the structurer work purely on the graph.
class BlockEmitter {
public:
    virtual ~BlockEmitter() = default;
    // Statements for the body of a block, excluding its terminator.
    virtual std::vector<ast::StmtPtr> statements(int block) = 0;
    // The condition of a conditional branch.
    virtual ast::ExprPtr condition(int block) = 0;
    // The value a switch dispatches on.
    virtual ast::ExprPtr switchValue(int block) = 0;
    // The returned expression, or null for a bare return.
    virtual ast::ExprPtr returnValue(int block) = 0;
    // Copies that must happen on the edge from -> to, from phi resolution.
    virtual std::vector<ast::StmtPtr> edgeCopies(int from, int to) = 0;
    // A label for a block, used when a goto is unavoidable.
    virtual std::string labelFor(int block) = 0;
};

struct StructureResult {
    ast::StmtPtr body;
    int gotoCount = 0;
    int labelCount = 0;
    bool irreducible = false;
    std::vector<std::string> notes;
};

struct StructurerOptions {
    bool recoverForLoops = true;
    bool mergeElseIf = true;
};

StructureResult structureFunction(const ir::Function& f, BlockEmitter& emitter,
                                  const StructurerOptions& opt = {});

} // namespace dc::structure
