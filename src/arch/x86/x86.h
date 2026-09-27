// Architecture-specific machine instruction model for x86 / x64.
//
// This is the decompiler's own representation; the disassembler backend
// (Capstone today) translates into it, and nothing above the disassembler
// layer ever sees Capstone types.
#pragma once

#include "support/common.h"

namespace dc::x86 {

enum class Reg : u16 {
    None = 0,
#define X(e, n, f, o, s) e,
#include "arch/x86/registers.def"
#undef X
    Count
};

// Register families: all registers that alias the same physical storage.
enum class Family : u8 {
    None = 0,
    F_RAX, F_RCX, F_RDX, F_RBX, F_RSP, F_RBP, F_RSI, F_RDI,
    F_R8, F_R9, F_R10, F_R11, F_R12, F_R13, F_R14, F_R15,
    F_RIP, F_ES, F_CS, F_SS, F_DS, F_FS, F_GS,
    F_XMM0, F_XMM1, F_XMM2, F_XMM3, F_XMM4, F_XMM5, F_XMM6, F_XMM7,
    F_XMM8, F_XMM9, F_XMM10, F_XMM11, F_XMM12, F_XMM13, F_XMM14, F_XMM15,
    F_ST0, F_ST1, F_ST2, F_ST3, F_ST4, F_ST5, F_ST6, F_ST7,
    F_FLAGS, F_FPSW,
    Count
};

struct RegInfo {
    const char* name;
    Family family;
    u8 offset; // byte offset inside the family's storage (AH = 1)
    u8 size;   // bytes
};

const RegInfo& regInfo(Reg r);
inline const char* regName(Reg r) { return regInfo(r).name; }
inline Family regFamily(Reg r) { return regInfo(r).family; }
inline unsigned regSize(Reg r) { return regInfo(r).size; }
Reg regFromName(std::string_view name); // Reg::None if unknown
const char* familyName(Family f);
bool isGprFamily(Family f);
bool isXmmFamily(Family f);
int gprIndex(Family f);  // 0..15 for RAX..R15, else -1
int xmmIndex(Family f);  // 0..15, else -1
Family gprFamily(int index);
Family xmmFamily(int index);
// The full-width register of a family for the given mode (RAX vs EAX).
Reg fullReg(Family f, bool is64);
// Returns the GPR of the requested size in a family (e.g. F_RCX, 4 -> ECX).
Reg gprOfSize(Family f, unsigned size);

enum class Mnem : u16 {
    Unknown = 0,
#define X(e, n) e,
#include "arch/x86/mnemonics.def"
#undef X
    Count
};

const char* mnemName(Mnem m);
Mnem mnemFromName(std::string_view name);

enum class OpKind : u8 { None, Reg, Imm, Mem };

struct MemOperand {
    Reg segment = Reg::None;
    Reg base = Reg::None;
    Reg index = Reg::None;
    u8 scale = 1;
    i64 disp = 0;
};

struct Operand {
    OpKind kind = OpKind::None;
    u8 size = 0;         // access size in bytes
    Reg reg = Reg::None; // OpKind::Reg
    i64 imm = 0;         // OpKind::Imm (sign-extended to 64 bits)
    MemOperand mem;      // OpKind::Mem

    bool isReg() const { return kind == OpKind::Reg; }
    bool isImm() const { return kind == OpKind::Imm; }
    bool isMem() const { return kind == OpKind::Mem; }
    bool isReg(Reg r) const { return kind == OpKind::Reg && reg == r; }
};

// How an instruction affects control flow.
enum class Flow : u8 {
    Normal,        // falls through
    Jump,          // unconditional direct jump
    IndirectJump,  // jmp reg/mem
    CondJump,      // conditional direct jump (falls through otherwise)
    Call,          // direct call
    IndirectCall,  // call reg/mem
    Return,
    Halt,          // hlt/ud2/int3: does not continue
};

enum Prefix : u8 {
    PrefixNone = 0,
    PrefixRep = 1,
    PrefixRepne = 2,
    PrefixLock = 4,
};

enum class Cond : u8 { O, NO, B, AE, E, NE, BE, A, S, NS, P, NP, L, GE, LE, G, None };
const char* condName(Cond c);
Cond invertCond(Cond c);

struct Instruction {
    u64 address = 0;
    u8 length = 0;
    u8 bytes[15] = {};
    Mnem mnem = Mnem::Unknown;
    u8 numOps = 0;
    u8 prefixes = PrefixNone;
    bool is64 = false; // decoded in 64-bit mode
    Operand ops[4];
    Flow flow = Flow::Normal;
    u64 target = 0;          // direct branch/call target
    std::string mnemonicText; // as printed by the decoder, e.g. "rep stosb"
    std::string operandText;  // e.g. "eax, dword ptr [rcx + 8]"

    u64 next() const { return address + length; }
    const Operand& op(unsigned i) const { return ops[i]; }
    std::string text() const;
    bool isBranch() const { return flow == Flow::Jump || flow == Flow::CondJump || flow == Flow::IndirectJump; }
    bool isCall() const { return flow == Flow::Call || flow == Flow::IndirectCall; }
    bool endsBlock() const { return flow != Flow::Normal && !isCall(); }
    Cond condition() const; // for Jcc/SETcc/CMOVcc
    // RIP-relative absolute address of a memory operand, if any.
    std::optional<u64> ripTarget(unsigned opIndex) const;
};

} // namespace dc::x86
