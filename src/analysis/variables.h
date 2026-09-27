// Variable recovery: turning SSA values into the variables the output declares.
//
// Two jobs. First, decide which values need a name at all - a value used once
// in the block that computed it becomes part of an expression instead, which
// is what keeps the output from having one variable per SSA value. Second,
// coalesce the values that must share storage (the members of a phi web) into
// a single variable, and give it a name that says something.
#pragma once

#include "analysis/stack_frame.h"
#include "ir/ir.h"
#include "types/infer.h"

#include <unordered_map>
#include <unordered_set>

namespace dc {

struct Variable {
    int id = -1;
    std::string name;
    types::TypeRef type = nullptr;
    std::vector<ir::ValueId> values;   // SSA values coalesced into this variable
    bool isParam = false;
    int paramIndex = -1;
    bool singleAssignment = false;     // eligible for const
    bool isReturnValue = false;
    unsigned uses = 0;
};

struct VariableMap {
    std::vector<Variable> variables;
    std::unordered_map<ir::ValueId, int> ofValue;
    // Values that are expressions, inlined at their single use.
    std::unordered_set<ir::ValueId> inlined;

    const Variable* forValue(ir::ValueId v) const {
        auto it = ofValue.find(v);
        return it == ofValue.end() ? nullptr : &variables[it->second];
    }
    bool isInlined(ir::ValueId v) const { return inlined.count(v) > 0; }
};

// Builds the variable map. `types` supplies each value's recovered type.
VariableMap recoverVariables(ir::Function& f, const types::TypeResult& types, const StackFrame& frame);

} // namespace dc
