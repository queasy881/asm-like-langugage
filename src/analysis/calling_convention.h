// Windows calling conventions for x86 and x64.
#pragma once

#include "arch/x86/x86.h"

namespace dc {

enum class CallConv : u8 {
    Unknown,
    Win64,      // the single x64 convention
    Cdecl,      // x86: caller cleans
    Stdcall,    // x86: callee cleans
    Fastcall,   // x86: ECX, EDX then stack, callee cleans
    Thiscall,   // x86: ECX = this, rest on stack, callee cleans
};
const char* callConvName(CallConv c);

struct ConventionInfo {
    std::vector<x86::Family> intArgRegs;   // in argument order
    std::vector<int> floatArgRegs;         // XMM indices, in argument order
    bool positionalFloatRegs = false;      // x64: arg N uses RCX[N] or XMM[N]
    bool shadowSpace = false;              // x64: 32 bytes reserved by the caller
    i64 stackArgStart = 0;                 // frame offset of the first stack argument
    x86::Family intReturn = x86::Family::F_RAX;
    x86::Family intReturnHigh = x86::Family::F_RDX; // 64-bit returns on x86
    bool calleeCleansStack = false;
    std::vector<x86::Family> calleeSaved;
    std::vector<x86::Family> volatileRegs;
};

ConventionInfo conventionInfo(CallConv cc, bool is64);
CallConv defaultConvention(bool is64);
bool isCalleeSaved(CallConv cc, bool is64, x86::Family f);

} // namespace dc
