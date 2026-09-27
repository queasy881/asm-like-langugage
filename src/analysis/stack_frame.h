// Stack frame recovery.
//
// Frame offsets are measured from the stack pointer on entry, so offset 0 is
// the return address, positive offsets are the caller's frame (incoming stack
// arguments) and negative offsets are this function's own frame.
//
// Slots that are only ever read and written directly - never had their address
// taken - are promoted to SSA variables so they stop looking like memory.
#pragma once

#include "analysis/calling_convention.h"
#include "ir/ir.h"

#include <map>

namespace dc {

enum class SlotKind : u8 {
    Local,          // this function's own storage
    IncomingArg,    // argument passed on the stack by the caller
    ReturnAddress,
    SavedRegister,  // a callee-saved register spilled in the prologue
    OutgoingArg,    // space the function writes for its own calls
};
const char* slotKindName(SlotKind k);

struct FrameSlot {
    i64 offset = 0;
    unsigned size = 0;
    SlotKind kind = SlotKind::Local;
    bool escaped = false;        // its address was taken
    bool mixedSize = false;      // accessed at more than one width
    bool promoted = false;
    unsigned slotId = 0;         // Loc index once promoted
    unsigned loads = 0, stores = 0;
    ir::Type type;               // width of the accesses
    std::string name;
};

struct StackFrame {
    std::vector<FrameSlot> slots;   // sorted by offset
    i64 minOffset = 0;              // lowest touched offset
    i64 stackArgStart = 0;
    i64 lowestSp = 0;               // most negative stack pointer value
    bool anyEscaped = false;
    unsigned promotedCount = 0;

    const FrameSlot* at(i64 offset) const;
    FrameSlot* at(i64 offset);
    std::string print() const;
};

// Discovers the slots referenced by FrameAddr instructions.
StackFrame analyzeStackFrame(const ir::Function& f, const ConventionInfo& ci, unsigned ptrBytes);

// Rewrites loads and stores of promotable slots into location accesses, which
// SSA construction then turns into ordinary values.
void promoteStackSlots(ir::Function& f, StackFrame& frame);

} // namespace dc
