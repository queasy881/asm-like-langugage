#include "analysis/calling_convention.h"

#include <algorithm>

namespace dc {

using namespace x86;

const char* callConvName(CallConv c) {
    switch (c) {
    case CallConv::Win64: return "__fastcall";   // the x64 ABI; printed without a keyword
    case CallConv::Cdecl: return "__cdecl";
    case CallConv::Stdcall: return "__stdcall";
    case CallConv::Fastcall: return "__fastcall";
    case CallConv::Thiscall: return "__thiscall";
    case CallConv::LocalRegs: return "";
    default: return "";
    }
}

CallConv defaultConvention(bool is64) { return is64 ? CallConv::Win64 : CallConv::Cdecl; }

ConventionInfo conventionInfo(CallConv cc, bool is64) {
    ConventionInfo ci;
    if (is64) {
        ci.intArgRegs = {Family::F_RCX, Family::F_RDX, Family::F_R8, Family::F_R9};
        ci.floatArgRegs = {0, 1, 2, 3};
        ci.positionalFloatRegs = true;
        ci.shadowSpace = true;
        ci.stackArgStart = 0x28; // return address + 32 bytes of shadow space
        ci.intReturn = Family::F_RAX;
        ci.calleeSaved = {Family::F_RBX, Family::F_RBP, Family::F_RDI, Family::F_RSI,
                          Family::F_R12, Family::F_R13, Family::F_R14, Family::F_R15};
        for (int i = 6; i <= 15; ++i) ci.calleeSaved.push_back(xmmFamily(i));
        ci.volatileRegs = {Family::F_RAX, Family::F_RCX, Family::F_RDX, Family::F_R8,
                           Family::F_R9, Family::F_R10, Family::F_R11};
        for (int i = 0; i <= 5; ++i) ci.volatileRegs.push_back(xmmFamily(i));
        return ci;
    }
    ci.stackArgStart = 4; // return address only
    ci.intReturn = Family::F_RAX;
    ci.intReturnHigh = Family::F_RDX;
    ci.calleeSaved = {Family::F_RBX, Family::F_RBP, Family::F_RSI, Family::F_RDI};
    ci.volatileRegs = {Family::F_RAX, Family::F_RCX, Family::F_RDX};
    for (int i = 0; i <= 7; ++i) ci.volatileRegs.push_back(xmmFamily(i));
    switch (cc) {
    case CallConv::LocalRegs:
        // What GCC gives a static function it can see every call of: the
        // first three integer arguments in eax, edx and ecx, the rest on the
        // stack, and the caller still cleans up.
        ci.intArgRegs = {Family::F_RAX, Family::F_RDX, Family::F_RCX};
        ci.floatArgRegs = {0, 1, 2, 3};
        break;
    case CallConv::Fastcall:
        ci.intArgRegs = {Family::F_RCX, Family::F_RDX};
        ci.calleeCleansStack = true;
        break;
    case CallConv::Thiscall:
        ci.intArgRegs = {Family::F_RCX};
        ci.calleeCleansStack = true;
        break;
    case CallConv::Stdcall:
        ci.calleeCleansStack = true;
        break;
    default:
        break;
    }
    return ci;
}

bool isCalleeSaved(CallConv cc, bool is64, Family f) {
    ConventionInfo ci = conventionInfo(cc, is64);
    return std::find(ci.calleeSaved.begin(), ci.calleeSaved.end(), f) != ci.calleeSaved.end();
}

} // namespace dc
