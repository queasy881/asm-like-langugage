// Structure recovery.
//
// A pointer that is dereferenced at several fixed offsets is a pointer to a
// structure, and the offsets are its fields. Gaps the accesses imply are kept
// as explicitly unaccessed members so the layout stays exact, and the struct
// is packed so a compiler cannot move anything.
#pragma once

#include "analysis/variables.h"
#include "types/infer.h"
#include "types/type_system.h"

namespace dc::types {

struct StructRecoveryOptions {
    // Below this many distinct fields a pointer stays a plain pointer.
    unsigned minFields = 2;
    // An access beyond this offset is treated as an array walk, not a field.
    i64 maxOffset = 1 << 16;
};

// Builds structures for the pointer roots of one function and points the
// corresponding values at them. Returns the structures it created.
std::vector<const Type*> recoverStructs(ir::Function& f, TypeTable& table, TypeResult& types,
                                        const std::string& functionName, unsigned ptrBits,
                                        const StructRecoveryOptions& opt = {});

} // namespace dc::types
