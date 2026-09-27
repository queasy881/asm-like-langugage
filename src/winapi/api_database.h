// Known signatures for Windows APIs and the C runtime.
//
// Knowing an import's exact arity and parameter types is what turns a call
// into readable C, and it seeds type inference for the values flowing into it.
#pragma once

#include "analysis/calling_convention.h"
#include "ir/ir.h"

#include <string>
#include <vector>

namespace dc::winapi {

// The C-level type of a parameter. These map to IR types given a pointer
// width, and to Windows type spellings in the C backend.
enum class ApiType : u8 {
    Void, Bool, Char, Byte, Short, Word, Int, Dword, Long, Ulong,
    Int64, Uint64, Float, Double, Size, Ssize,
    Ptr,        // void*
    ConstPtr,   // const void*
    CStr,       // char*
    WStr,       // wchar_t*
    Handle,
    Hwnd,
    Hmodule,
    FnPtr,
    Struct,     // pointer to a structure
};

const char* apiTypeName(ApiType t);
ir::Type apiTypeToIr(ApiType t, unsigned ptrBytes);
bool apiTypeIsPointer(ApiType t);

struct ApiParam {
    ApiType type = ApiType::Ptr;
    const char* name = nullptr;
    bool out = false;   // the callee writes through this pointer
};

struct ApiSignature {
    const char* name = nullptr;
    const char* library = nullptr;
    ApiType ret = ApiType::Void;
    std::vector<ApiParam> params;
    bool variadic = false;
    bool noReturn = false;
    bool stdcallOnX86 = true;  // Win32 APIs are __stdcall on x86; CRT is __cdecl

    std::vector<ir::Type> paramTypes(unsigned ptrBytes) const;
    ir::Type returnIrType(unsigned ptrBytes) const;
    CallConv convention(bool is64) const {
        if (is64) return CallConv::Win64;
        return stdcallOnX86 ? CallConv::Stdcall : CallConv::Cdecl;
    }
};

// Looks up an import by name. Handles the A/W suffix pair and the leading
// underscore or @n decoration used on x86.
const ApiSignature* lookup(const std::string& name, bool is64);

// Every known signature, for tests and for listing.
const std::vector<ApiSignature>& all();

// A short description of what an API does, when one is known.
const char* describe(const std::string& name);

} // namespace dc::winapi
