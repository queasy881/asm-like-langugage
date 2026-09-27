// Capstone-backed implementation of dc::Disassembler.
#include "disasm/disassembler.h"

#include <capstone/capstone.h>

#include <cstring>
#include <mutex>
#include <unordered_map>

namespace dc {
namespace {

using namespace dc::x86;

class CapstoneX86 final : public Disassembler {
public:
    explicit CapstoneX86(bool is64) : is64_(is64) {
        if (cs_open(CS_ARCH_X86, is64 ? CS_MODE_64 : CS_MODE_32, &handle_) != CS_ERR_OK)
            throw DecompError("failed to initialise Capstone");
        cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(handle_, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
        insn_ = cs_malloc(handle_);
        buildRegMap();
    }
    ~CapstoneX86() override {
        if (insn_) cs_free(insn_, 1);
        cs_close(&handle_);
    }

    bool is64() const override { return is64_; }

    bool decode(std::span<const u8> bytes, u64 address, Instruction& out) override {
        if (bytes.empty()) return false;
        const uint8_t* code = bytes.data();
        size_t size = bytes.size();
        uint64_t addr = address;
        if (!cs_disasm_iter(handle_, &code, &size, &addr, insn_)) return false;
        translate(*insn_, out);
        return true;
    }

private:
    Reg mapReg(unsigned csReg) const {
        if (csReg == X86_REG_INVALID) return Reg::None;
        auto it = regMap_.find(csReg);
        return it == regMap_.end() ? Reg::None : it->second;
    }

    void buildRegMap() {
        // Map by register name so we never depend on Capstone's numbering.
        for (unsigned r = 1; r < X86_REG_ENDING; ++r) {
            const char* nm = cs_reg_name(handle_, r);
            if (!nm) continue;
            Reg ours = regFromName(nm);
            if (ours != Reg::None) regMap_[r] = ours;
        }
    }

    void translate(const cs_insn& ci, Instruction& out) {
        out = Instruction{};
        out.address = ci.address;
        out.length = (u8)ci.size;
        std::memcpy(out.bytes, ci.bytes, std::min<size_t>(ci.size, sizeof(out.bytes)));
        out.is64 = is64_;
        out.mnemonicText = ci.mnemonic;
        out.operandText = ci.op_str;

        const cs_x86& x = ci.detail->x86;
        for (int i = 0; i < 4; ++i) {
            switch (x.prefix[i]) {
            case X86_PREFIX_REP: out.prefixes |= PrefixRep; break; // also REPE
            case X86_PREFIX_REPNE: out.prefixes |= PrefixRepne; break;
            case X86_PREFIX_LOCK: out.prefixes |= PrefixLock; break;
            default: break;
            }
        }

        // Base mnemonic without prefixes ("rep stosb" -> "stosb").
        const char* baseName = cs_insn_name(handle_, ci.id);
        std::string name = baseName ? baseName : "";
        out.mnem = mnemFromName(name);

        out.numOps = (u8)std::min<int>(x.op_count, 4);
        for (int i = 0; i < out.numOps; ++i) {
            const cs_x86_op& o = x.operands[i];
            Operand& d = out.ops[i];
            d.size = o.size;
            switch (o.type) {
            case X86_OP_REG:
                d.kind = OpKind::Reg;
                d.reg = mapReg(o.reg);
                if (!d.size) d.size = (u8)regSize(d.reg);
                break;
            case X86_OP_IMM:
                d.kind = OpKind::Imm;
                d.imm = o.imm;
                break;
            case X86_OP_MEM:
                d.kind = OpKind::Mem;
                d.mem.segment = mapReg(o.mem.segment);
                d.mem.base = mapReg(o.mem.base);
                d.mem.index = mapReg(o.mem.index);
                d.mem.scale = (u8)(o.mem.scale ? o.mem.scale : 1);
                d.mem.disp = o.mem.disp;
                break;
            default:
                d.kind = OpKind::None;
                break;
            }
        }

        disambiguate(out, name);
        classifyFlow(out);
    }

    // Capstone uses one id for the SSE and string forms of MOVSD/CMPSD.
    static void disambiguate(Instruction& in, const std::string& name) {
        if (in.mnem == Mnem::Movsd || in.mnem == Mnem::CmpsdStr || name == "cmpsd") {
            bool hasXmm = false;
            for (int i = 0; i < in.numOps; ++i)
                if (in.ops[i].isReg() && isXmmFamily(regFamily(in.ops[i].reg))) hasXmm = true;
            if (name == "movsd") in.mnem = hasXmm ? Mnem::Movsd : Mnem::MovsdStr;
            if (name == "cmpsd") in.mnem = hasXmm ? Mnem::Unknown : Mnem::CmpsdStr; // SSE cmpsd predicate compare
        }
        if (name == "movsd" && in.numOps == 0) in.mnem = Mnem::MovsdStr;
        // Capstone reports 64-bit immediate "mov" as movabs; treat alike.
        if (in.mnem == Mnem::Movabs) in.mnem = Mnem::Mov;
        if (in.mnem == Mnem::Sal) in.mnem = Mnem::Shl;
    }

    static void classifyFlow(Instruction& in) {
        auto directTarget = [&]() -> bool {
            if (in.numOps >= 1 && in.ops[0].isImm()) {
                in.target = (u64)in.ops[0].imm;
                if (!in.is64) in.target &= 0xFFFFFFFFull;
                return true;
            }
            return false;
        };
        switch (in.mnem) {
        case Mnem::Jmp:
            in.flow = directTarget() ? Flow::Jump : Flow::IndirectJump;
            break;
        case Mnem::Call:
            in.flow = directTarget() ? Flow::Call : Flow::IndirectCall;
            break;
        case Mnem::Ret:
        case Mnem::Retf:
            in.flow = Flow::Return;
            break;
        case Mnem::Hlt:
        case Mnem::Ud2:
        case Mnem::Int3:
            in.flow = Flow::Halt;
            break;
        case Mnem::Int:
            // int 0x29 is __fastfail; int 3 in long form.
            if (in.numOps == 1 && in.ops[0].isImm() && (in.ops[0].imm == 0x29 || in.ops[0].imm == 3)) in.flow = Flow::Halt;
            break;
        case Mnem::Jcxz: case Mnem::Jecxz: case Mnem::Jrcxz:
        case Mnem::Loop: case Mnem::Loope: case Mnem::Loopne:
            directTarget();
            in.flow = Flow::CondJump;
            break;
        default:
            if (in.mnem >= Mnem::Jo && in.mnem <= Mnem::Jg) {
                directTarget();
                in.flow = Flow::CondJump;
            }
            break;
        }
    }

    bool is64_;
    csh handle_ = 0;
    cs_insn* insn_ = nullptr;
    std::unordered_map<unsigned, Reg> regMap_;
};

} // namespace

std::unique_ptr<Disassembler> createX86Disassembler(bool is64) {
    return std::make_unique<CapstoneX86>(is64);
}

} // namespace dc
