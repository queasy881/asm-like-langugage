#include "arch/x86/x86.h"

#include <array>
#include <unordered_map>

namespace dc::x86 {

namespace {
const RegInfo kRegInfo[] = {
    {"<none>", Family::None, 0, 0},
#define X(e, n, f, o, s) {n, Family::f, o, s},
#include "arch/x86/registers.def"
#undef X
};

const char* const kMnemNames[] = {
    "<unknown>",
#define X(e, n) n,
#include "arch/x86/mnemonics.def"
#undef X
};

const char* const kFamilyNames[] = {
    "none", "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "es", "cs", "ss", "ds", "fs", "gs",
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
    "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
    "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
    "flags", "fpsw",
};
static_assert(sizeof(kFamilyNames) / sizeof(kFamilyNames[0]) == (size_t)Family::Count);
} // namespace

const RegInfo& regInfo(Reg r) {
    size_t i = (size_t)r;
    if (i >= (size_t)Reg::Count) return kRegInfo[0];
    return kRegInfo[i];
}

Reg regFromName(std::string_view name) {
    static const std::unordered_map<std::string, Reg> map = [] {
        std::unordered_map<std::string, Reg> m;
        for (size_t i = 1; i < (size_t)Reg::Count; ++i) m.emplace(kRegInfo[i].name, (Reg)i);
        m.emplace("st0", Reg::ST0);
        m.emplace("st", Reg::ST0);
        return m;
    }();
    auto it = map.find(std::string(name));
    return it == map.end() ? Reg::None : it->second;
}

const char* familyName(Family f) {
    size_t i = (size_t)f;
    return i < (size_t)Family::Count ? kFamilyNames[i] : "?";
}

bool isGprFamily(Family f) { return f >= Family::F_RAX && f <= Family::F_R15; }
bool isXmmFamily(Family f) { return f >= Family::F_XMM0 && f <= Family::F_XMM15; }
int gprIndex(Family f) { return isGprFamily(f) ? (int)f - (int)Family::F_RAX : -1; }
int xmmIndex(Family f) { return isXmmFamily(f) ? (int)f - (int)Family::F_XMM0 : -1; }
Family gprFamily(int index) { return (Family)((int)Family::F_RAX + index); }
Family xmmFamily(int index) { return (Family)((int)Family::F_XMM0 + index); }

Reg gprOfSize(Family f, unsigned size) {
    for (size_t i = 1; i < (size_t)Reg::Count; ++i)
        if (kRegInfo[i].family == f && kRegInfo[i].size == size && kRegInfo[i].offset == 0) return (Reg)i;
    return Reg::None;
}

Reg fullReg(Family f, bool is64) {
    if (isGprFamily(f)) return gprOfSize(f, is64 ? 8 : 4);
    if (f == Family::F_RIP) return is64 ? Reg::RIP : Reg::EIP;
    if (isXmmFamily(f)) return (Reg)((int)Reg::XMM0 + xmmIndex(f));
    for (size_t i = 1; i < (size_t)Reg::Count; ++i)
        if (kRegInfo[i].family == f) return (Reg)i;
    return Reg::None;
}

const char* mnemName(Mnem m) {
    size_t i = (size_t)m;
    return i < (size_t)Mnem::Count ? kMnemNames[i] : "<bad>";
}

Mnem mnemFromName(std::string_view name) {
    static const std::unordered_map<std::string, Mnem> map = [] {
        std::unordered_map<std::string, Mnem> m;
        for (size_t i = 1; i < (size_t)Mnem::Count; ++i) m.emplace(kMnemNames[i], (Mnem)i);
        // Common alternative spellings.
        m.emplace("jz", Mnem::Je); m.emplace("jnz", Mnem::Jne); m.emplace("jc", Mnem::Jb); m.emplace("jnae", Mnem::Jb);
        m.emplace("jnc", Mnem::Jae); m.emplace("jnb", Mnem::Jae); m.emplace("jna", Mnem::Jbe); m.emplace("jnbe", Mnem::Ja);
        m.emplace("jnge", Mnem::Jl); m.emplace("jnl", Mnem::Jge); m.emplace("jng", Mnem::Jle); m.emplace("jnle", Mnem::Jg);
        m.emplace("jpe", Mnem::Jp); m.emplace("jpo", Mnem::Jnp);
        m.emplace("setz", Mnem::Sete); m.emplace("setnz", Mnem::Setne); m.emplace("setc", Mnem::Setb); m.emplace("setnc", Mnem::Setae);
        m.emplace("setnb", Mnem::Setae); m.emplace("setnae", Mnem::Setb); m.emplace("setna", Mnem::Setbe); m.emplace("setnbe", Mnem::Seta);
        m.emplace("setnge", Mnem::Setl); m.emplace("setnl", Mnem::Setge); m.emplace("setng", Mnem::Setle); m.emplace("setnle", Mnem::Setg);
        m.emplace("cmovz", Mnem::Cmove); m.emplace("cmovnz", Mnem::Cmovne); m.emplace("cmovc", Mnem::Cmovb); m.emplace("cmovnc", Mnem::Cmovae);
        m.emplace("cmovnb", Mnem::Cmovae); m.emplace("cmovnae", Mnem::Cmovb); m.emplace("cmovna", Mnem::Cmovbe); m.emplace("cmovnbe", Mnem::Cmova);
        m.emplace("cmovnge", Mnem::Cmovl); m.emplace("cmovnl", Mnem::Cmovge); m.emplace("cmovng", Mnem::Cmovle); m.emplace("cmovnle", Mnem::Cmovg);
        m.emplace("retn", Mnem::Ret); m.emplace("fwait", Mnem::Fwait);
        m.emplace("movsxd", Mnem::Movsxd);
        return m;
    }();
    auto it = map.find(std::string(name));
    return it == map.end() ? Mnem::Unknown : it->second;
}

const char* condName(Cond c) {
    static const char* const names[] = {"o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g", "none"};
    return names[(int)c];
}

Cond invertCond(Cond c) {
    if (c == Cond::None) return c;
    return (Cond)((int)c ^ 1);
}

Cond Instruction::condition() const {
    auto base = [](Mnem m, Mnem first) { return (Cond)((int)m - (int)first); };
    if (mnem >= Mnem::Jo && mnem <= Mnem::Jg) return base(mnem, Mnem::Jo);
    if (mnem >= Mnem::Seto && mnem <= Mnem::Setg) return base(mnem, Mnem::Seto);
    if (mnem >= Mnem::Cmovo && mnem <= Mnem::Cmovg) return base(mnem, Mnem::Cmovo);
    return Cond::None;
}

std::string Instruction::text() const {
    if (operandText.empty()) return mnemonicText;
    return mnemonicText + " " + operandText;
}

std::optional<u64> Instruction::ripTarget(unsigned i) const {
    if (i >= numOps || !ops[i].isMem()) return std::nullopt;
    const MemOperand& m = ops[i].mem;
    if ((m.base == Reg::RIP || m.base == Reg::EIP) && m.index == Reg::None) return next() + (u64)m.disp;
    return std::nullopt;
}

} // namespace dc::x86
