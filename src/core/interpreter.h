// A small interpreter for the IR.
//
// It exists for testing: running the same function before and after the
// optimisation passes, with the same inputs, must produce the same result and
// the same memory writes. That catches semantic mistakes which a structural
// verifier cannot see.
#pragma once

#include "ir/ir.h"
#include "pe/pe_image.h"

#include <functional>
#include <map>
#include <unordered_map>

namespace dc {

struct InterpMemory {
    const pe::Image* image = nullptr;   // backing store for globals
    std::map<u64, u8> written;          // sparse overlay
    // Addresses in this range read as zero when never written, which models
    // an ordinary uninitialised stack.
    u64 stackLo = 0, stackHi = 0;
    std::vector<std::pair<u64, u64>> writeLog; // address, value (for comparison)

    bool read(u64 addr, unsigned bytes, u64& out) const;
    void write(u64 addr, unsigned bytes, u64 value);
};

struct InterpOptions {
    u64 stackBase = 0x7FF000000000ull;  // value of the stack pointer on entry
    u64 maxSteps = 2000000;
    bool trapOnUndef = false;
    // Called for every Call instruction. Return false to trap.
    std::function<bool(const ir::CallInfo&, const std::vector<u64>&, u64&)> onCall;
    // Initial value for a location read on entry (registers, flags).
    std::function<bool(ir::Loc, u64&)> entryValue;
};

struct InterpResult {
    bool ok = false;
    bool returned = false;
    u64 value = 0;              // the returned value, as a bit pattern
    bool hasValue = false;
    std::string error;
    u64 steps = 0;
    int blocksVisited = 0;
};

InterpResult interpret(const ir::Function& f, InterpMemory& mem, const InterpOptions& opt = {});

} // namespace dc
