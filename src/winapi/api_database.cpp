#include "winapi/api_database.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <unordered_map>

namespace dc::winapi {

namespace {

std::vector<ApiSignature> buildTable() {
    std::vector<ApiSignature> t;
    auto add = [&](const char* name, const char* lib, ApiType ret, std::vector<ApiParam> params,
                   bool variadic, bool noReturn, bool stdcallOnX86) {
        ApiSignature s;
        s.name = name;
        s.library = lib;
        s.ret = ret;
        s.params = std::move(params);
        s.variadic = variadic;
        s.noReturn = noReturn;
        s.stdcallOnX86 = stdcallOnX86;
        t.push_back(std::move(s));
    };
    add("CreateFileA", "kernel32", ApiType::Handle, {{ApiType::WStr, "path"}, {ApiType::Dword, "access"}, {ApiType::Dword, "shareMode"}, {ApiType::Ptr, "security"}, {ApiType::Dword, "creation"}, {ApiType::Dword, "flags"}, {ApiType::Handle, "templateFile"}}, false, false, true);
    add("CreateFileW", "kernel32", ApiType::Handle, {{ApiType::WStr, "path"}, {ApiType::Dword, "access"}, {ApiType::Dword, "shareMode"}, {ApiType::Ptr, "security"}, {ApiType::Dword, "creation"}, {ApiType::Dword, "flags"}, {ApiType::Handle, "templateFile"}}, false, false, true);
    add("ReadFile", "kernel32", ApiType::Bool, {{ApiType::Handle, "file"}, {ApiType::Ptr, "buffer"}, {ApiType::Dword, "bytesToRead"}, {ApiType::Ptr, "bytesRead", true}, {ApiType::Ptr, "overlapped"}}, false, false, true);
    add("WriteFile", "kernel32", ApiType::Bool, {{ApiType::Handle, "file"}, {ApiType::ConstPtr, "buffer"}, {ApiType::Dword, "bytesToWrite"}, {ApiType::Ptr, "bytesWritten", true}, {ApiType::Ptr, "overlapped"}}, false, false, true);
    add("CloseHandle", "kernel32", ApiType::Bool, {{ApiType::Handle, "object"}}, false, false, true);
    add("SetFilePointer", "kernel32", ApiType::Dword, {{ApiType::Handle, "file"}, {ApiType::Long, "distance"}, {ApiType::Ptr, "distanceHigh", true}, {ApiType::Dword, "method"}}, false, false, true);
    add("SetFilePointerEx", "kernel32", ApiType::Bool, {{ApiType::Handle, "file"}, {ApiType::Int64, "distance"}, {ApiType::Ptr, "newPointer", true}, {ApiType::Dword, "method"}}, false, false, true);
    add("GetFileSize", "kernel32", ApiType::Dword, {{ApiType::Handle, "file"}, {ApiType::Ptr, "sizeHigh", true}}, false, false, true);
    add("GetFileSizeEx", "kernel32", ApiType::Bool, {{ApiType::Handle, "file"}, {ApiType::Ptr, "size", true}}, false, false, true);
    add("DeleteFileA", "kernel32", ApiType::Bool, {{ApiType::CStr, "path"}}, false, false, true);
    add("DeleteFileW", "kernel32", ApiType::Bool, {{ApiType::WStr, "path"}}, false, false, true);
    add("FlushFileBuffers", "kernel32", ApiType::Bool, {{ApiType::Handle, "file"}}, false, false, true);
    add("CreateDirectoryW", "kernel32", ApiType::Bool, {{ApiType::WStr, "path"}, {ApiType::Ptr, "security"}}, false, false, true);
    add("GetFileAttributesW", "kernel32", ApiType::Dword, {{ApiType::WStr, "path"}}, false, false, true);
    add("VirtualAlloc", "kernel32", ApiType::Ptr, {{ApiType::Ptr, "address"}, {ApiType::Size, "size"}, {ApiType::Dword, "allocationType"}, {ApiType::Dword, "protect"}}, false, false, true);
    add("VirtualFree", "kernel32", ApiType::Bool, {{ApiType::Ptr, "address"}, {ApiType::Size, "size"}, {ApiType::Dword, "freeType"}}, false, false, true);
    add("VirtualProtect", "kernel32", ApiType::Bool, {{ApiType::Ptr, "address"}, {ApiType::Size, "size"}, {ApiType::Dword, "newProtect"}, {ApiType::Ptr, "oldProtect", true}}, false, false, true);
    add("VirtualQuery", "kernel32", ApiType::Size, {{ApiType::ConstPtr, "address"}, {ApiType::Ptr, "buffer", true}, {ApiType::Size, "length"}}, false, false, true);
    add("HeapAlloc", "kernel32", ApiType::Ptr, {{ApiType::Handle, "heap"}, {ApiType::Dword, "flags"}, {ApiType::Size, "bytes"}}, false, false, true);
    add("HeapFree", "kernel32", ApiType::Bool, {{ApiType::Handle, "heap"}, {ApiType::Dword, "flags"}, {ApiType::Ptr, "mem"}}, false, false, true);
    add("HeapReAlloc", "kernel32", ApiType::Ptr, {{ApiType::Handle, "heap"}, {ApiType::Dword, "flags"}, {ApiType::Ptr, "mem"}, {ApiType::Size, "bytes"}}, false, false, true);
    add("GetProcessHeap", "kernel32", ApiType::Handle, {}, false, false, true);
    add("RtlMoveMemory", "kernel32", ApiType::Void, {{ApiType::Ptr, "dest"}, {ApiType::ConstPtr, "src"}, {ApiType::Size, "length"}}, false, false, true);
    add("LoadLibraryA", "kernel32", ApiType::Hmodule, {{ApiType::CStr, "name"}}, false, false, true);
    add("LoadLibraryW", "kernel32", ApiType::Hmodule, {{ApiType::WStr, "name"}}, false, false, true);
    add("LoadLibraryExW", "kernel32", ApiType::Hmodule, {{ApiType::WStr, "name"}, {ApiType::Handle, "file"}, {ApiType::Dword, "flags"}}, false, false, true);
    add("FreeLibrary", "kernel32", ApiType::Bool, {{ApiType::Hmodule, "module"}}, false, false, true);
    add("GetProcAddress", "kernel32", ApiType::FnPtr, {{ApiType::Hmodule, "module"}, {ApiType::CStr, "name"}}, false, false, true);
    add("GetModuleHandleA", "kernel32", ApiType::Hmodule, {{ApiType::CStr, "name"}}, false, false, true);
    add("GetModuleHandleW", "kernel32", ApiType::Hmodule, {{ApiType::WStr, "name"}}, false, false, true);
    add("GetModuleFileNameW", "kernel32", ApiType::Dword, {{ApiType::Hmodule, "module"}, {ApiType::WStr, "filename", true}, {ApiType::Dword, "size"}}, false, false, true);
    add("CreateProcessA", "kernel32", ApiType::Bool, {{ApiType::CStr, "applicationName"}, {ApiType::CStr, "commandLine"}, {ApiType::Ptr, "processAttributes"}, {ApiType::Ptr, "threadAttributes"}, {ApiType::Bool, "inheritHandles"}, {ApiType::Dword, "creationFlags"}, {ApiType::Ptr, "environment"}, {ApiType::CStr, "currentDirectory"}, {ApiType::Ptr, "startupInfo"}, {ApiType::Ptr, "processInformation", true}}, false, false, true);
    add("CreateProcessW", "kernel32", ApiType::Bool, {{ApiType::WStr, "applicationName"}, {ApiType::WStr, "commandLine"}, {ApiType::Ptr, "processAttributes"}, {ApiType::Ptr, "threadAttributes"}, {ApiType::Bool, "inheritHandles"}, {ApiType::Dword, "creationFlags"}, {ApiType::Ptr, "environment"}, {ApiType::WStr, "currentDirectory"}, {ApiType::Ptr, "startupInfo"}, {ApiType::Ptr, "processInformation", true}}, false, false, true);
    add("CreateThread", "kernel32", ApiType::Handle, {{ApiType::Ptr, "security"}, {ApiType::Size, "stackSize"}, {ApiType::FnPtr, "startAddress"}, {ApiType::Ptr, "parameter"}, {ApiType::Dword, "creationFlags"}, {ApiType::Ptr, "threadId", true}}, false, false, true);
    add("ExitProcess", "kernel32", ApiType::Void, {{ApiType::Uint64, "code"}}, false, true, true);
    add("ExitThread", "kernel32", ApiType::Void, {{ApiType::Dword, "code"}}, false, true, true);
    add("TerminateProcess", "kernel32", ApiType::Bool, {{ApiType::Handle, "process"}, {ApiType::Uint64, "exitCode"}}, false, false, true);
    add("WaitForSingleObject", "kernel32", ApiType::Dword, {{ApiType::Handle, "object"}, {ApiType::Dword, "milliseconds"}}, false, false, true);
    add("WaitForMultipleObjects", "kernel32", ApiType::Dword, {{ApiType::Dword, "count"}, {ApiType::Ptr, "handles"}, {ApiType::Bool, "waitAll"}, {ApiType::Dword, "milliseconds"}}, false, false, true);
    add("Sleep", "kernel32", ApiType::Void, {{ApiType::Dword, "milliseconds"}}, false, false, true);
    add("GetCurrentProcess", "kernel32", ApiType::Handle, {}, false, false, true);
    add("GetCurrentThread", "kernel32", ApiType::Handle, {}, false, false, true);
    add("GetCurrentProcessId", "kernel32", ApiType::Dword, {}, false, false, true);
    add("GetCurrentThreadId", "kernel32", ApiType::Dword, {}, false, false, true);
    add("InitializeCriticalSection", "kernel32", ApiType::Void, {{ApiType::Ptr, "criticalSection"}}, false, false, true);
    add("InitializeCriticalSectionAndSpinCount", "kernel32", ApiType::Bool, {{ApiType::Ptr, "criticalSection"}, {ApiType::Dword, "spinCount"}}, false, false, true);
    add("DeleteCriticalSection", "kernel32", ApiType::Void, {{ApiType::Ptr, "criticalSection"}}, false, false, true);
    add("EnterCriticalSection", "kernel32", ApiType::Void, {{ApiType::Ptr, "criticalSection"}}, false, false, true);
    add("LeaveCriticalSection", "kernel32", ApiType::Void, {{ApiType::Ptr, "criticalSection"}}, false, false, true);
    add("TryEnterCriticalSection", "kernel32", ApiType::Bool, {{ApiType::Ptr, "criticalSection"}}, false, false, true);
    add("CreateEventW", "kernel32", ApiType::Handle, {{ApiType::Ptr, "security"}, {ApiType::Bool, "manualReset"}, {ApiType::Bool, "initialState"}, {ApiType::WStr, "name"}}, false, false, true);
    add("SetEvent", "kernel32", ApiType::Bool, {{ApiType::Handle, "event"}}, false, false, true);
    add("ResetEvent", "kernel32", ApiType::Bool, {{ApiType::Handle, "event"}}, false, false, true);
    add("CreateMutexW", "kernel32", ApiType::Handle, {{ApiType::Ptr, "security"}, {ApiType::Bool, "initialOwner"}, {ApiType::WStr, "name"}}, false, false, true);
    add("ReleaseMutex", "kernel32", ApiType::Bool, {{ApiType::Handle, "mutex"}}, false, false, true);
    add("InterlockedIncrement", "kernel32", ApiType::Long, {{ApiType::Ptr, "addend"}}, false, false, true);
    add("InterlockedDecrement", "kernel32", ApiType::Long, {{ApiType::Ptr, "addend"}}, false, false, true);
    add("InterlockedExchange", "kernel32", ApiType::Long, {{ApiType::Ptr, "target"}, {ApiType::Long, "value"}}, false, false, true);
    add("InterlockedCompareExchange", "kernel32", ApiType::Long, {{ApiType::Ptr, "destination"}, {ApiType::Long, "exchange"}, {ApiType::Long, "comparand"}}, false, false, true);
    add("TlsAlloc", "kernel32", ApiType::Dword, {}, false, false, true);
    add("TlsGetValue", "kernel32", ApiType::Ptr, {{ApiType::Dword, "index"}}, false, false, true);
    add("TlsSetValue", "kernel32", ApiType::Bool, {{ApiType::Dword, "index"}, {ApiType::Ptr, "value"}}, false, false, true);
    add("TlsFree", "kernel32", ApiType::Bool, {{ApiType::Dword, "index"}}, false, false, true);
    add("GetLastError", "kernel32", ApiType::Dword, {}, false, false, true);
    add("SetLastError", "kernel32", ApiType::Void, {{ApiType::Dword, "code"}}, false, false, true);
    add("GetTickCount", "kernel32", ApiType::Dword, {}, false, false, true);
    add("GetTickCount64", "kernel32", ApiType::Uint64, {}, false, false, true);
    add("QueryPerformanceCounter", "kernel32", ApiType::Bool, {{ApiType::Ptr, "count", true}}, false, false, true);
    add("QueryPerformanceFrequency", "kernel32", ApiType::Bool, {{ApiType::Ptr, "frequency", true}}, false, false, true);
    add("GetSystemTimeAsFileTime", "kernel32", ApiType::Void, {{ApiType::Ptr, "fileTime", true}}, false, false, true);
    add("OutputDebugStringA", "kernel32", ApiType::Void, {{ApiType::CStr, "text"}}, false, false, true);
    add("OutputDebugStringW", "kernel32", ApiType::Void, {{ApiType::WStr, "text"}}, false, false, true);
    add("GetStdHandle", "kernel32", ApiType::Handle, {{ApiType::Dword, "stdHandle"}}, false, false, true);
    add("MultiByteToWideChar", "kernel32", ApiType::Int, {{ApiType::Uint64, "codePage"}, {ApiType::Dword, "flags"}, {ApiType::CStr, "multiByteStr"}, {ApiType::Int, "multiByte"}, {ApiType::WStr, "wideCharStr", true}, {ApiType::Int, "wideChar"}}, false, false, true);
    add("WideCharToMultiByte", "kernel32", ApiType::Int, {{ApiType::Uint64, "codePage"}, {ApiType::Dword, "flags"}, {ApiType::WStr, "wideCharStr"}, {ApiType::Int, "wideChar"}, {ApiType::CStr, "multiByteStr", true}, {ApiType::Int, "multiByte"}, {ApiType::CStr, "defaultChar"}, {ApiType::Ptr, "usedDefaultChar", true}}, false, false, true);
    add("IsDebuggerPresent", "kernel32", ApiType::Bool, {}, false, false, true);
    add("RaiseException", "kernel32", ApiType::Void, {{ApiType::Dword, "code"}, {ApiType::Dword, "flags"}, {ApiType::Dword, "numberOfArguments"}, {ApiType::ConstPtr, "arguments"}}, false, true, true);
    add("SetUnhandledExceptionFilter", "kernel32", ApiType::FnPtr, {{ApiType::FnPtr, "filter"}}, false, false, true);
    add("UnhandledExceptionFilter", "kernel32", ApiType::Long, {{ApiType::Ptr, "exceptionInfo"}}, false, false, true);
    add("GetSystemInfo", "kernel32", ApiType::Void, {{ApiType::Ptr, "systemInfo", true}}, false, false, true);
    add("FormatMessageW", "kernel32", ApiType::Dword, {{ApiType::Dword, "flags"}, {ApiType::ConstPtr, "source"}, {ApiType::Dword, "messageId"}, {ApiType::Dword, "languageId"}, {ApiType::WStr, "buffer", true}, {ApiType::Dword, "size"}, {ApiType::Ptr, "arguments"}}, false, false, true);
    add("RegOpenKeyExA", "advapi32", ApiType::Long, {{ApiType::Handle, "key"}, {ApiType::CStr, "subKey"}, {ApiType::Dword, "options"}, {ApiType::Dword, "desired"}, {ApiType::Ptr, "result", true}}, false, false, true);
    add("RegOpenKeyExW", "advapi32", ApiType::Long, {{ApiType::Handle, "key"}, {ApiType::WStr, "subKey"}, {ApiType::Dword, "options"}, {ApiType::Dword, "desired"}, {ApiType::Ptr, "result", true}}, false, false, true);
    add("RegQueryValueExW", "advapi32", ApiType::Long, {{ApiType::Handle, "key"}, {ApiType::WStr, "valueName"}, {ApiType::Ptr, "reserved"}, {ApiType::Ptr, "type", true}, {ApiType::Ptr, "data", true}, {ApiType::Ptr, "dataSize", true}}, false, false, true);
    add("RegSetValueExW", "advapi32", ApiType::Long, {{ApiType::Handle, "key"}, {ApiType::WStr, "valueName"}, {ApiType::Dword, "reserved"}, {ApiType::Dword, "type"}, {ApiType::ConstPtr, "data"}, {ApiType::Dword, "dataSize"}}, false, false, true);
    add("RegCloseKey", "advapi32", ApiType::Long, {{ApiType::Handle, "key"}}, false, false, true);
    add("RegCreateKeyExW", "advapi32", ApiType::Long, {{ApiType::Handle, "key"}, {ApiType::WStr, "subKey"}, {ApiType::Dword, "reserved"}, {ApiType::WStr, "classname"}, {ApiType::Dword, "options"}, {ApiType::Dword, "desired"}, {ApiType::Ptr, "security"}, {ApiType::Ptr, "result", true}, {ApiType::Ptr, "disposition", true}}, false, false, true);
    add("RegDeleteValueW", "advapi32", ApiType::Long, {{ApiType::Handle, "key"}, {ApiType::WStr, "valueName"}}, false, false, true);
    add("MessageBoxA", "user32", ApiType::Int, {{ApiType::Hwnd, "owner"}, {ApiType::CStr, "text"}, {ApiType::CStr, "caption"}, {ApiType::Uint64, "type"}}, false, false, true);
    add("MessageBoxW", "user32", ApiType::Int, {{ApiType::Hwnd, "owner"}, {ApiType::WStr, "text"}, {ApiType::WStr, "caption"}, {ApiType::Uint64, "type"}}, false, false, true);
    add("GetDesktopWindow", "user32", ApiType::Hwnd, {}, false, false, true);
    add("FindWindowW", "user32", ApiType::Hwnd, {{ApiType::WStr, "className"}, {ApiType::WStr, "windowName"}}, false, false, true);
    add("SendMessageW", "user32", ApiType::Int64, {{ApiType::Hwnd, "window"}, {ApiType::Uint64, "message"}, {ApiType::Uint64, "wParam"}, {ApiType::Int64, "lParam"}}, false, false, true);
    add("PostMessageW", "user32", ApiType::Bool, {{ApiType::Hwnd, "window"}, {ApiType::Uint64, "message"}, {ApiType::Uint64, "wParam"}, {ApiType::Int64, "lParam"}}, false, false, true);
    add("malloc", "msvcrt", ApiType::Ptr, {{ApiType::Size, "size"}}, false, false, false);
    add("calloc", "msvcrt", ApiType::Ptr, {{ApiType::Size, "count"}, {ApiType::Size, "size"}}, false, false, false);
    add("realloc", "msvcrt", ApiType::Ptr, {{ApiType::Ptr, "block"}, {ApiType::Size, "size"}}, false, false, false);
    add("free", "msvcrt", ApiType::Void, {{ApiType::Ptr, "block"}}, false, false, false);
    add("memcpy", "msvcrt", ApiType::Ptr, {{ApiType::Ptr, "dest"}, {ApiType::ConstPtr, "src"}, {ApiType::Size, "count"}}, false, false, false);
    add("memmove", "msvcrt", ApiType::Ptr, {{ApiType::Ptr, "dest"}, {ApiType::ConstPtr, "src"}, {ApiType::Size, "count"}}, false, false, false);
    add("memset", "msvcrt", ApiType::Ptr, {{ApiType::Ptr, "dest"}, {ApiType::Int, "value"}, {ApiType::Size, "count"}}, false, false, false);
    add("memcmp", "msvcrt", ApiType::Int, {{ApiType::ConstPtr, "a"}, {ApiType::ConstPtr, "b"}, {ApiType::Size, "count"}}, false, false, false);
    add("memchr", "msvcrt", ApiType::Ptr, {{ApiType::ConstPtr, "buffer"}, {ApiType::Int, "value"}, {ApiType::Size, "count"}}, false, false, false);
    add("strlen", "msvcrt", ApiType::Size, {{ApiType::CStr, "str"}}, false, false, false);
    add("strnlen", "msvcrt", ApiType::Size, {{ApiType::CStr, "str"}, {ApiType::Size, "maxCount"}}, false, false, false);
    add("strcpy", "msvcrt", ApiType::CStr, {{ApiType::CStr, "dest"}, {ApiType::CStr, "src"}}, false, false, false);
    add("strncpy", "msvcrt", ApiType::CStr, {{ApiType::CStr, "dest"}, {ApiType::CStr, "src"}, {ApiType::Size, "count"}}, false, false, false);
    add("strcat", "msvcrt", ApiType::CStr, {{ApiType::CStr, "dest"}, {ApiType::CStr, "src"}}, false, false, false);
    add("strncat", "msvcrt", ApiType::CStr, {{ApiType::CStr, "dest"}, {ApiType::CStr, "src"}, {ApiType::Size, "count"}}, false, false, false);
    add("strcmp", "msvcrt", ApiType::Int, {{ApiType::CStr, "a"}, {ApiType::CStr, "b"}}, false, false, false);
    add("strncmp", "msvcrt", ApiType::Int, {{ApiType::CStr, "a"}, {ApiType::CStr, "b"}, {ApiType::Size, "count"}}, false, false, false);
    add("_stricmp", "msvcrt", ApiType::Int, {{ApiType::CStr, "a"}, {ApiType::CStr, "b"}}, false, false, false);
    add("_strnicmp", "msvcrt", ApiType::Int, {{ApiType::CStr, "a"}, {ApiType::CStr, "b"}, {ApiType::Size, "count"}}, false, false, false);
    add("strchr", "msvcrt", ApiType::CStr, {{ApiType::CStr, "str"}, {ApiType::Int, "ch"}}, false, false, false);
    add("strrchr", "msvcrt", ApiType::CStr, {{ApiType::CStr, "str"}, {ApiType::Int, "ch"}}, false, false, false);
    add("strstr", "msvcrt", ApiType::CStr, {{ApiType::CStr, "haystack"}, {ApiType::CStr, "needle"}}, false, false, false);
    add("strtok", "msvcrt", ApiType::CStr, {{ApiType::CStr, "str"}, {ApiType::CStr, "delimiters"}}, false, false, false);
    add("wcslen", "msvcrt", ApiType::Size, {{ApiType::WStr, "str"}}, false, false, false);
    add("wcscpy", "msvcrt", ApiType::WStr, {{ApiType::WStr, "dest"}, {ApiType::WStr, "src"}}, false, false, false);
    add("wcscmp", "msvcrt", ApiType::Int, {{ApiType::WStr, "a"}, {ApiType::WStr, "b"}}, false, false, false);
    add("sprintf", "msvcrt", ApiType::Int, {{ApiType::CStr, "buffer"}, {ApiType::CStr, "format"}}, true, false, false);
    add("snprintf", "msvcrt", ApiType::Int, {{ApiType::CStr, "buffer"}, {ApiType::Size, "count"}, {ApiType::CStr, "format"}}, true, false, false);
    add("_snprintf", "msvcrt", ApiType::Int, {{ApiType::CStr, "buffer"}, {ApiType::Size, "count"}, {ApiType::CStr, "format"}}, true, false, false);
    add("printf", "msvcrt", ApiType::Int, {{ApiType::CStr, "format"}}, true, false, false);
    add("fprintf", "msvcrt", ApiType::Int, {{ApiType::Ptr, "stream"}, {ApiType::CStr, "format"}}, true, false, false);
    add("vfprintf", "msvcrt", ApiType::Int, {{ApiType::Ptr, "stream"}, {ApiType::CStr, "format"}, {ApiType::Ptr, "args"}}, false, false, false);
    add("vsprintf", "msvcrt", ApiType::Int, {{ApiType::CStr, "buffer"}, {ApiType::CStr, "format"}, {ApiType::Ptr, "args"}}, false, false, false);
    add("vsnprintf", "msvcrt", ApiType::Int, {{ApiType::CStr, "buffer"}, {ApiType::Size, "count"}, {ApiType::CStr, "format"}, {ApiType::Ptr, "args"}}, false, false, false);
    add("sscanf", "msvcrt", ApiType::Int, {{ApiType::CStr, "buffer"}, {ApiType::CStr, "format"}}, true, false, false);
    add("puts", "msvcrt", ApiType::Int, {{ApiType::CStr, "str"}}, false, false, false);
    add("fwrite", "msvcrt", ApiType::Size, {{ApiType::ConstPtr, "buffer"}, {ApiType::Size, "size"}, {ApiType::Size, "count"}, {ApiType::Ptr, "stream"}}, false, false, false);
    add("fread", "msvcrt", ApiType::Size, {{ApiType::Ptr, "buffer"}, {ApiType::Size, "size"}, {ApiType::Size, "count"}, {ApiType::Ptr, "stream"}}, false, false, false);
    add("fopen", "msvcrt", ApiType::Ptr, {{ApiType::CStr, "filename"}, {ApiType::CStr, "mode"}}, false, false, false);
    add("fclose", "msvcrt", ApiType::Int, {{ApiType::Ptr, "stream"}}, false, false, false);
    add("fseek", "msvcrt", ApiType::Int, {{ApiType::Ptr, "stream"}, {ApiType::Long, "offset"}, {ApiType::Int, "origin"}}, false, false, false);
    add("ftell", "msvcrt", ApiType::Long, {{ApiType::Ptr, "stream"}}, false, false, false);
    add("atoi", "msvcrt", ApiType::Int, {{ApiType::CStr, "str"}}, false, false, false);
    add("atol", "msvcrt", ApiType::Long, {{ApiType::CStr, "str"}}, false, false, false);
    add("strtol", "msvcrt", ApiType::Long, {{ApiType::CStr, "str"}, {ApiType::Ptr, "end", true}, {ApiType::Int, "base"}}, false, false, false);
    add("strtoul", "msvcrt", ApiType::Ulong, {{ApiType::CStr, "str"}, {ApiType::Ptr, "end", true}, {ApiType::Int, "base"}}, false, false, false);
    add("strtod", "msvcrt", ApiType::Double, {{ApiType::CStr, "str"}, {ApiType::Ptr, "end", true}}, false, false, false);
    add("qsort", "msvcrt", ApiType::Void, {{ApiType::Ptr, "base"}, {ApiType::Size, "count"}, {ApiType::Size, "size"}, {ApiType::FnPtr, "compare"}}, false, false, false);
    add("bsearch", "msvcrt", ApiType::Ptr, {{ApiType::ConstPtr, "key"}, {ApiType::ConstPtr, "base"}, {ApiType::Size, "count"}, {ApiType::Size, "size"}, {ApiType::FnPtr, "compare"}}, false, false, false);
    add("abort", "msvcrt", ApiType::Void, {}, false, true, false);
    add("exit", "msvcrt", ApiType::Void, {{ApiType::Int, "code"}}, false, true, false);
    add("_exit", "msvcrt", ApiType::Void, {{ApiType::Int, "code"}}, false, true, false);
    add("_amsg_exit", "msvcrt", ApiType::Void, {{ApiType::Int, "code"}}, false, true, false);
    add("_assert", "msvcrt", ApiType::Void, {{ApiType::CStr, "message"}, {ApiType::CStr, "file"}, {ApiType::Uint64, "line"}}, false, true, false);
    add("_wassert", "msvcrt", ApiType::Void, {{ApiType::WStr, "message"}, {ApiType::WStr, "file"}, {ApiType::Uint64, "line"}}, false, true, false);
    add("__iob_func", "msvcrt", ApiType::Ptr, {}, false, false, false);
    add("__acrt_iob_func", "msvcrt", ApiType::Ptr, {{ApiType::Uint64, "index"}}, false, false, false);
    add("_initterm", "msvcrt", ApiType::Void, {{ApiType::Ptr, "first"}, {ApiType::Ptr, "last"}}, false, false, false);
    add("_initterm_e", "msvcrt", ApiType::Int, {{ApiType::Ptr, "first"}, {ApiType::Ptr, "last"}}, false, false, false);
    add("_lock", "msvcrt", ApiType::Void, {{ApiType::Int, "lockNumber"}}, false, false, false);
    add("_unlock", "msvcrt", ApiType::Void, {{ApiType::Int, "lockNumber"}}, false, false, false);
    add("_onexit", "msvcrt", ApiType::FnPtr, {{ApiType::FnPtr, "function"}}, false, false, false);
    add("_errno", "msvcrt", ApiType::Ptr, {}, false, false, false);
    add("signal", "msvcrt", ApiType::FnPtr, {{ApiType::Int, "sig"}, {ApiType::FnPtr, "handler"}}, false, false, false);
    add("longjmp", "msvcrt", ApiType::Void, {{ApiType::Ptr, "env"}, {ApiType::Int, "value"}}, false, true, false);
    add("setjmp", "msvcrt", ApiType::Int, {{ApiType::Ptr, "env"}}, false, false, false);
    add("__umodti3", "msvcrt", ApiType::Uint64, {{ApiType::Uint64, "a"}, {ApiType::Uint64, "b"}}, false, false, false);
    add("__udivti3", "msvcrt", ApiType::Uint64, {{ApiType::Uint64, "a"}, {ApiType::Uint64, "b"}}, false, false, false);
    add("sqrt", "msvcrt", ApiType::Double, {{ApiType::Double, "x"}}, false, false, false);
    add("pow", "msvcrt", ApiType::Double, {{ApiType::Double, "x"}, {ApiType::Double, "y"}}, false, false, false);
    add("fabs", "msvcrt", ApiType::Double, {{ApiType::Double, "x"}}, false, false, false);
    add("floor", "msvcrt", ApiType::Double, {{ApiType::Double, "x"}}, false, false, false);
    add("ceil", "msvcrt", ApiType::Double, {{ApiType::Double, "x"}}, false, false, false);
    add("sin", "msvcrt", ApiType::Double, {{ApiType::Double, "x"}}, false, false, false);
    add("cos", "msvcrt", ApiType::Double, {{ApiType::Double, "x"}}, false, false, false);
    add("log", "msvcrt", ApiType::Double, {{ApiType::Double, "x"}}, false, false, false);
    add("exp", "msvcrt", ApiType::Double, {{ApiType::Double, "x"}}, false, false, false);
    add("sqrtf", "msvcrt", ApiType::Float, {{ApiType::Float, "x"}}, false, false, false);
    add("fmodf", "msvcrt", ApiType::Float, {{ApiType::Float, "x"}, {ApiType::Float, "y"}}, false, false, false);
    add("fmod", "msvcrt", ApiType::Double, {{ApiType::Double, "x"}, {ApiType::Double, "y"}}, false, false, false);
    return t;
}

const std::unordered_map<std::string, const char*>& descriptions() {
    static const std::unordered_map<std::string, const char*> m = {
        {"CreateFileW", "opens or creates a file or device"},
        {"CreateFileA", "opens or creates a file or device"},
        {"ReadFile", "reads from a file or device"},
        {"WriteFile", "writes to a file or device"},
        {"CloseHandle", "closes an open object handle"},
        {"VirtualAlloc", "reserves or commits pages in the virtual address space"},
        {"VirtualFree", "releases or decommits pages"},
        {"VirtualProtect", "changes the protection of committed pages"},
        {"LoadLibraryW", "loads a module into the process"},
        {"GetProcAddress", "looks up an exported function by name"},
        {"CreateProcessW", "creates a new process"},
        {"RegOpenKeyExW", "opens a registry key"},
        {"ExitProcess", "ends the calling process"},
        {"Sleep", "suspends the thread"},
        {"GetLastError", "returns the last error code set by an API"},
    };
    return m;
}

} // namespace

const char* apiTypeName(ApiType t) {
    switch (t) {
    case ApiType::Void: return "void";
    case ApiType::Bool: return "BOOL";
    case ApiType::Char: return "CHAR";
    case ApiType::Byte: return "BYTE";
    case ApiType::Short: return "SHORT";
    case ApiType::Word: return "WORD";
    case ApiType::Int: return "INT";
    case ApiType::Dword: return "DWORD";
    case ApiType::Long: return "LONG";
    case ApiType::Ulong: return "ULONG";
    case ApiType::Int64: return "LONGLONG";
    case ApiType::Uint64: return "ULONGLONG";
    case ApiType::Float: return "float";
    case ApiType::Double: return "double";
    case ApiType::Size: return "SIZE_T";
    case ApiType::Ssize: return "SSIZE_T";
    case ApiType::Ptr: return "void*";
    case ApiType::ConstPtr: return "const void*";
    case ApiType::CStr: return "CHAR*";
    case ApiType::WStr: return "WCHAR*";
    case ApiType::Handle: return "HANDLE";
    case ApiType::Hwnd: return "HWND";
    case ApiType::Hmodule: return "HMODULE";
    case ApiType::FnPtr: return "void*";
    case ApiType::Struct: return "void*";
    }
    return "void*";
}

bool apiTypeIsPointer(ApiType t) {
    switch (t) {
    case ApiType::Ptr: case ApiType::ConstPtr: case ApiType::CStr: case ApiType::WStr:
    case ApiType::Handle: case ApiType::Hwnd: case ApiType::Hmodule: case ApiType::FnPtr:
    case ApiType::Struct:
        return true;
    default:
        return false;
    }
}

ir::Type apiTypeToIr(ApiType t, unsigned ptrBytes) {
    u16 pb = (u16)(ptrBytes * 8);
    if (apiTypeIsPointer(t)) return ir::Type::ptr(pb);
    switch (t) {
    case ApiType::Void: return ir::Type::voidTy();
    case ApiType::Bool: return ir::kI32;
    case ApiType::Char: case ApiType::Byte: return ir::kI8;
    case ApiType::Short: case ApiType::Word: return ir::kI16;
    case ApiType::Int: case ApiType::Dword: case ApiType::Long: case ApiType::Ulong: return ir::kI32;
    case ApiType::Int64: case ApiType::Uint64: return ir::kI64;
    case ApiType::Float: return ir::kF32;
    case ApiType::Double: return ir::kF64;
    case ApiType::Size: case ApiType::Ssize: return ir::Type::i(pb);
    default: return ir::Type::i(pb);
    }
}

std::vector<ir::Type> ApiSignature::paramTypes(unsigned ptrBytes) const {
    std::vector<ir::Type> out;
    out.reserve(params.size());
    for (const auto& p : params) out.push_back(apiTypeToIr(p.type, ptrBytes));
    return out;
}

ir::Type ApiSignature::returnIrType(unsigned ptrBytes) const { return apiTypeToIr(ret, ptrBytes); }

const std::vector<ApiSignature>& all() {
    static const std::vector<ApiSignature> table = buildTable();
    return table;
}

namespace {
const std::unordered_map<std::string, const ApiSignature*>& index() {
    static const std::unordered_map<std::string, const ApiSignature*> m = [] {
        std::unordered_map<std::string, const ApiSignature*> r;
        for (const auto& s : all()) r.emplace(s.name, &s);
        return r;
    }();
    return m;
}

// Strips the decorations x86 import names carry: a leading underscore for
// __cdecl, and "@n" for __stdcall or __fastcall.
std::string undecorate(const std::string& name) {
    std::string n = name;
    size_t at = n.rfind('@');
    if (at != std::string::npos && at > 0) {
        bool digits = at + 1 < n.size();
        for (size_t i = at + 1; i < n.size() && digits; ++i)
            if (!std::isdigit((unsigned char)n[i])) digits = false;
        if (digits) n = n.substr(0, at);
    }
    if (!n.empty() && (n[0] == '_' || n[0] == '@')) {
        std::string stripped = n.substr(1);
        if (index().count(stripped)) return stripped;
    }
    return n;
}
} // namespace

const ApiSignature* lookup(const std::string& name, bool is64) {
    (void)is64;
    const auto& m = index();
    auto it = m.find(name);
    if (it != m.end()) return it->second;
    std::string u = undecorate(name);
    it = m.find(u);
    if (it != m.end()) return it->second;
    // Microsoft's secure and internal variants share the base signature.
    for (const char* suffix : {"_s", "_l"}) {
        if (u.size() > std::strlen(suffix) && u.compare(u.size() - std::strlen(suffix), std::strlen(suffix), suffix) == 0) {
            it = m.find(u.substr(0, u.size() - std::strlen(suffix)));
            if (it != m.end()) return it->second;
        }
    }
    return nullptr;
}

const char* describe(const std::string& name) {
    const auto& d = descriptions();
    auto it = d.find(name);
    if (it != d.end()) return it->second;
    it = d.find(undecorate(name));
    return it == d.end() ? nullptr : it->second;
}

} // namespace dc::winapi
