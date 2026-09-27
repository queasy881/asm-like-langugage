// Decoder abstraction. The rest of the decompiler depends only on this
// interface and on dc::x86::Instruction; the Capstone backend lives entirely
// in capstone_backend.cpp and can be swapped without touching analysis code.
#pragma once

#include "arch/x86/x86.h"

#include <memory>
#include <span>

namespace dc {

class Disassembler {
public:
    virtual ~Disassembler() = default;
    // Decodes one instruction at `address` from `bytes`. Returns false if
    // the bytes do not form a valid instruction.
    virtual bool decode(std::span<const u8> bytes, u64 address, x86::Instruction& out) = 0;
    virtual bool is64() const = 0;
};

// Creates the default x86/x64 decoder (Capstone based).
std::unique_ptr<Disassembler> createX86Disassembler(bool is64);

} // namespace dc
