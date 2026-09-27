#include "analysis/program.h"

#include <algorithm>
#include <cstring>
#include <deque>

namespace dc {

using namespace x86;

const char* edgeKindName(EdgeKind k) {
    switch (k) {
    case EdgeKind::Fallthrough: return "fallthrough";
    case EdgeKind::True: return "true";
    case EdgeKind::False: return "false";
    case EdgeKind::Jump: return "jump";
    case EdgeKind::Switch: return "case";
    case EdgeKind::Return: return "return";
    }
    return "?";
}

const char* terminatorName(Terminator t) {
    switch (t) {
    case Terminator::Fallthrough: return "fallthrough";
    case Terminator::Branch: return "branch";
    case Terminator::Jump: return "jump";
    case Terminator::Switch: return "switch";
    case Terminator::IndirectJump: return "indirect-jump";
    case Terminator::Return: return "return";
    case Terminator::TailCall: return "tail-call";
    case Terminator::NoReturnCall: return "noreturn-call";
    case Terminator::Halt: return "halt";
    case Terminator::DecodeError: return "decode-error";
    }
    return "?";
}

int Function::blockContaining(u64 addr) const {
    auto it = blockAt.upper_bound(addr);
    if (it == blockAt.begin()) return -1;
    --it;
    const BasicBlock& b = blocks[it->second];
    return addr >= b.start && addr < b.end ? it->second : -1;
}

Digraph Function::graph(bool withExit) const {
    Digraph g((int)blocks.size() + (withExit ? 1 : 0));
    g.entry = 0;
    for (const auto& b : blocks) {
        std::vector<int> seen;
        for (const auto& e : b.succs) {
            int t = e.target;
            if (e.kind == EdgeKind::Return) {
                if (!withExit) continue;
                t = exitNode();
            }
            if (std::find(seen.begin(), seen.end(), t) != seen.end()) continue;
            seen.push_back(t);
            g.addEdge(b.id, t);
        }
    }
    return g;
}

size_t Function::instructionCount() const {
    size_t n = 0;
    for (const auto& b : blocks) n += b.insns.size();
    return n;
}

Program::Program(std::unique_ptr<pe::Image> image) : image_(std::move(image)) {
    dis_ = createX86Disassembler(image_->is64());
    for (const auto& s : image_->coffSymbols()) {
        if (s.name.empty() || s.name[0] == '.') continue;
        symbols_.emplace(s.address, s.name);
    }
    for (const auto& e : image_->exports())
        if (!e.forwarded && !e.name.empty()) symbols_[image_->rvaToVa(e.rva)] = e.name;
}

Program::~Program() = default;

const Instruction* Program::instructionAt(u64 va) {
    auto it = insnCache_.find(va);
    if (it != insnCache_.end()) return it->second.get();
    const Instruction* result = nullptr;
    if (image_->isExecutableVa(va)) {
        auto bytes = image_->fileBytesAt(va);
        if (!bytes.empty()) {
            auto in = std::make_unique<Instruction>();
            if (dis_->decode(bytes.subspan(0, std::min<size_t>(bytes.size(), 16)), va, *in)) {
                result = in.get();
                insnCache_.emplace(va, std::move(in));
                return result;
            }
        }
    }
    insnCache_.emplace(va, nullptr);
    return nullptr;
}

Function* Program::functionAt(u64 va) {
    auto it = functions_.find(va);
    return it == functions_.end() ? nullptr : it->second.get();
}

const Function* Program::functionAt(u64 va) const {
    auto it = functions_.find(va);
    return it == functions_.end() ? nullptr : it->second.get();
}

const Function* Program::functionContaining(u64 va) const {
    for (const auto& [entry, f] : functions_)
        if (f->blockContaining(va) >= 0) return f.get();
    return nullptr;
}

std::optional<std::string> Program::symbolName(u64 va) const {
    auto it = symbols_.find(va);
    if (it == symbols_.end()) return std::nullopt;
    return it->second;
}

std::string Program::nameForAddress(u64 va) const {
    if (const Function* f = functionAt(va)) return f->name;
    if (auto s = symbolName(va)) return *s;
    if (const pe::Import* imp = importViaThunk(va)) return imp->displayName();
    return strfmt("sub_%llx", (unsigned long long)va);
}

const pe::Import* Program::importViaThunk(u64 target) const {
    auto it = importThunks_.find(target);
    return it == importThunks_.end() ? nullptr : it->second;
}

bool Program::isNoReturnImport(const pe::Import* imp) const {
    if (!imp || imp->name.empty()) return false;
    static const char* const names[] = {
        "ExitProcess", "ExitThread", "FatalExit", "FatalAppExitA", "FatalAppExitW", "RtlExitUserProcess",
        "RtlExitUserThread", "exit", "_exit", "_Exit", "quick_exit", "abort", "_amsg_exit", "__fastfail",
        "_invalid_parameter_noinfo_noreturn", "__report_gsfailure", "_CxxThrowException", "__std_terminate",
        "terminate", "longjmp", "_longjmp", "__crt_debugger_hook", "RaiseFailFastException", "_assert", "_wassert",
        "__stack_chk_fail", "ExitWindowsEx_noreturn",
    };
    for (const char* n : names)
        if (imp->name == n) return true;
    return false;
}

bool Program::isNoReturnTarget(u64 target) const {
    if (noReturnFunctions_.count(target)) return true;
    if (const pe::Import* imp = importViaThunk(target)) return isNoReturnImport(imp);
    return false;
}

// ---------------------------------------------------------------------------
// Seeds
// ---------------------------------------------------------------------------

void Program::collectSeeds() {
    const auto& img = *image_;
    auto addSeed = [&](u64 va) {
        if (va && img.isExecutableVa(va)) knownEntries_.insert(va);
    };
    addSeed(img.entryPoint());
    for (const auto& e : img.exports())
        if (!e.forwarded) addSeed(img.rvaToVa(e.rva));
    // x64 exception directory: every non-chained entry starts a function.
    for (const auto& rf : img.runtimeFunctions()) {
        bool chained = false;
        auto hdr = img.readValue<u8>(img.rvaToVa(rf.unwindRva & ~1u));
        if (rf.unwindRva & 1) chained = true; // RVA of another RUNTIME_FUNCTION
        else if (hdr && ((*hdr >> 3) & 0x4)) chained = true;
        pdataRanges_.push_back({rf.beginRva, rf.endRva});
        if (!chained) addSeed(img.rvaToVa(rf.beginRva));
    }
    std::sort(pdataRanges_.begin(), pdataRanges_.end());
    for (const auto& s : img.coffSymbols())
        if (s.isFunction && !s.name.empty() && s.name[0] != '.') addSeed(s.address);
    // TLS callbacks.
    pe::DataDirectory tls = img.dataDirectory(pe::DirTLS);
    if (tls.rva) {
        unsigned ps = pointerSize();
        u64 cbArray = 0;
        if (img.read(img.rvaToVa(tls.rva) + 3 * ps, &cbArray, ps)) {
            for (int i = 0; i < 64 && cbArray; ++i) {
                u64 cb = 0;
                if (!img.read(cbArray + (u64)i * ps, &cb, ps) || !cb) break;
                addSeed(cb);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Jump tables
// ---------------------------------------------------------------------------

namespace {

// Linear symbolic expression: c + sum(coef * reg) [+ load(addr)].
struct LinExpr {
    i64 c = 0;
    std::map<Family, i64> regs;
    bool hasLoad = false;
    unsigned loadSize = 0;
    bool loadSigned = false;
    std::map<Family, i64> loadRegs; // load address registers
    i64 loadC = 0;
    bool valid = true;
    bool signExtend = false;  // the definition sign-extends its source
};

// Definition of a register written by `in`, as a linear expression over the
// registers before `in` executes. Returns false if not representable.
bool defineReg(const Instruction& in, Family fam, LinExpr& def, bool& isLoad, u64 imageBase) {
    isLoad = false;
    def = LinExpr{};
    switch (in.mnem) {
    case Mnem::Cdqe: case Mnem::Cwde: case Mnem::Cbw:
        break; // implicit destination
    default:
        if (in.numOps < 1 || !in.ops[0].isReg() || regFamily(in.ops[0].reg) != fam) return false;
    }
    auto memToLin = [&](const Operand& op, std::map<Family, i64>& regs, i64& c) -> bool {
        const MemOperand& m = op.mem;
        c = m.disp;
        if (m.base == Reg::RIP || m.base == Reg::EIP) {
            c = (i64)(in.next() + (u64)m.disp);
        } else if (m.base != Reg::None) {
            regs[regFamily(m.base)] += 1;
        }
        if (m.index != Reg::None) regs[regFamily(m.index)] += m.scale;
        if (m.segment == Reg::FS || m.segment == Reg::GS) return false;
        (void)imageBase;
        return true;
    };
    switch (in.mnem) {
    case Mnem::Mov:
    case Mnem::Movzx:
    case Mnem::Movsx:
    case Mnem::Movsxd:
        if (in.numOps != 2) return false;
        if (in.ops[1].isImm()) { def.c = in.ops[1].imm; return in.mnem == Mnem::Mov; }
        if (in.ops[1].isReg()) {
            def.regs[regFamily(in.ops[1].reg)] = 1;
            return true;
        }
        if (in.ops[1].isMem()) {
            isLoad = true;
            def.hasLoad = true;
            def.loadSize = in.ops[1].size;
            def.loadSigned = in.mnem == Mnem::Movsx || in.mnem == Mnem::Movsxd;
            return memToLin(in.ops[1], def.loadRegs, def.loadC);
        }
        return false;
    case Mnem::Shl:
        // A shift by a small constant is how a compiler scales an index.
        if (in.numOps == 2 && in.ops[1].isImm() && in.ops[1].imm >= 0 && in.ops[1].imm <= 4) {
            def.regs[fam] = (i64)1 << in.ops[1].imm;
            return true;
        }
        return false;
    case Mnem::Imul:
        if (in.numOps == 3 && in.ops[1].isReg() && in.ops[2].isImm()) {
            def.regs[regFamily(in.ops[1].reg)] = in.ops[2].imm;
            return true;
        }
        if (in.numOps == 2 && in.ops[1].isImm()) {
            def.regs[fam] = in.ops[1].imm;
            return true;
        }
        return false;
    case Mnem::Cdqe:
    case Mnem::Cwde:
    case Mnem::Cbw:
        // Sign-extends the accumulator in place; the value is unchanged for
        // the purpose of following the table index, but records that table
        // entries are signed.
        if (fam != Family::F_RAX) return false;
        def.regs[Family::F_RAX] = 1;
        def.signExtend = true;
        return true;
    case Mnem::Lea:
        if (in.numOps != 2 || !in.ops[1].isMem()) return false;
        return memToLin(in.ops[1], def.regs, def.c);
    case Mnem::Add:
    case Mnem::Sub: {
        if (in.numOps != 2) return false;
        i64 sign = in.mnem == Mnem::Add ? 1 : -1;
        def.regs[fam] = 1;
        if (in.ops[1].isImm()) { def.c = sign * in.ops[1].imm; return true; }
        if (in.ops[1].isReg()) { def.regs[regFamily(in.ops[1].reg)] += sign; return true; }
        return false;
    }
    default:
        return false;
    }
}

bool writesFamily(const Instruction& in, Family fam) {
    // Conservative: first operand register writes plus implicit writers.
    switch (in.mnem) {
    case Mnem::Cmp: case Mnem::Test: case Mnem::Push: case Mnem::Nop: case Mnem::Bt:
        return false;
    default: break;
    }
    if (in.flow != Flow::Normal) return false;
    if (in.numOps >= 1 && in.ops[0].isReg() && regFamily(in.ops[0].reg) == fam) return true;
    if (in.mnem == Mnem::Xchg && in.numOps == 2 && in.ops[1].isReg() && regFamily(in.ops[1].reg) == fam) return true;
    // Implicit RAX/RDX writers.
    if (fam == Family::F_RAX || fam == Family::F_RDX) {
        switch (in.mnem) {
        case Mnem::Mul: case Mnem::Div: case Mnem::Idiv: case Mnem::Cdq: case Mnem::Cqo: case Mnem::Cwd:
            return true;
        case Mnem::Imul: return in.numOps == 1;
        case Mnem::Cdqe: case Mnem::Cwde: case Mnem::Cbw: return fam == Family::F_RAX;
        default: break;
        }
    }
    return false;
}

} // namespace

bool Program::resolveJumpTable(const std::map<u64, const Instruction*>& insns, const Instruction& jmp, JumpTable& out) {
    const auto& img = *image_;
    out = JumpTable{};
    out.jumpAddress = jmp.address;

    auto prevOf = [&](u64 addr) -> const Instruction* {
        auto it = insns.lower_bound(addr);
        if (it == insns.begin()) return nullptr;
        --it;
        return it->second->next() == addr ? it->second : nullptr;
    };

    // Start expression: target of the jmp.
    LinExpr e;
    if (jmp.numOps != 1) return false;
    if (jmp.ops[0].isReg()) {
        e.regs[regFamily(jmp.ops[0].reg)] = 1;
    } else if (jmp.ops[0].isMem()) {
        const MemOperand& m = jmp.ops[0].mem;
        if (m.base == Reg::RIP) return false; // jmp [rip+x]: import/tail call, not a table
        e.hasLoad = true;
        e.loadSize = jmp.ops[0].size ? jmp.ops[0].size : pointerSize();
        e.loadC = m.disp;
        if (m.base != Reg::None) e.loadRegs[regFamily(m.base)] += 1;
        if (m.index != Reg::None) e.loadRegs[regFamily(m.index)] += m.scale;
        out.loadAddress = jmp.address;
    } else {
        return false;
    }

    std::set<Family> frozen; // index register(s) we stop substituting
    bool sawSignExtend = false;
    bool indexPinned = false;   // the defining instruction for the index is known
    auto substitute = [&](std::map<Family, i64>& regs, i64& c, Family fam, const LinExpr& def) -> bool {
        auto it = regs.find(fam);
        if (it == regs.end()) return true;
        i64 coef = it->second;
        regs.erase(it);
        if (def.hasLoad) return false;
        c += coef * def.c;
        for (auto& [r, k] : def.regs) {
            regs[r] += coef * k;
            if (regs[r] == 0) regs.erase(r);
        }
        return true;
    };

    const Instruction* cur = &jmp;
    for (int steps = 0; steps < 48; ++steps) {
        const Instruction* p = prevOf(cur->address);
        if (!p) break;
        cur = p;
        if (cur->flow == Flow::Call || cur->flow == Flow::IndirectCall) break;
        // Once the index register is known, the first definition of it walking
        // backwards is where its value is ready to be read. Until then the
        // index comes from a predecessor and is read at block entry.
        if (!indexPinned) {
            for (Family fr : frozen) {
                if (!writesFamily(*cur, fr)) continue;
                out.indexAddress = cur->address;
                indexPinned = true;
                break;
            }
        }
        // Collect families this instruction writes that we care about.
        std::vector<Family> fams;
        for (auto& [r, k] : e.regs) fams.push_back(r);
        for (auto& [r, k] : e.loadRegs)
            if (!frozen.count(r)) fams.push_back(r);
        for (Family fam : fams) {
            if (!writesFamily(*cur, fam)) continue;
            LinExpr def;
            bool isLoad = false;
            bool ok = defineReg(*cur, fam, def, isLoad, img.imageBase());
            bool inTop = e.regs.count(fam) > 0;
            if (ok && def.signExtend && !isLoad) {
                sawSignExtend = true;
                continue; // the value itself is unchanged
            }
            if (ok && isLoad && inTop && !e.hasLoad && e.regs[fam] == 1) {
                // The table load itself.
                e.regs.erase(fam);
                e.hasLoad = true;
                e.loadSize = def.loadSize;
                e.loadSigned = def.loadSigned;
                e.loadRegs = def.loadRegs;
                e.loadC = def.loadC;
                out.loadAddress = cur->address;
                if (sawSignExtend) e.loadSigned = true;
                // The scaled register is the index, but only when the scale
                // already distinguishes it. Otherwise keep substituting: the
                // table base is usually still an unresolved register here, and
                // freezing now would pick it instead of the index.
                Family idx = Family::None;
                i64 bestScale = 0;
                int bestCount = 0;
                for (auto& [r, k] : e.loadRegs) {
                    if (k > bestScale) { bestScale = k; idx = r; bestCount = 1; }
                    else if (k == bestScale) ++bestCount;
                }
                if (idx != Family::None && bestScale > 1 && bestCount == 1) {
                    frozen.insert(idx);
                    // The load consumes the index; its value is whatever the
                    // register held before this instruction.
                    out.indexAddress = 0;
                }
                continue;
            }
            // A compiler narrows the index to its real width right before the
            // table load: `movzx ebx, bl` after biasing by the first case
            // value. That instruction is where the index is ready, and
            // following it further folds the bias into the table address and
            // loses the bound the compare established.
            if (ok && !isLoad && !inTop && frozen.empty() && e.loadRegs.count(fam) &&
                (cur->mnem == Mnem::Movzx || cur->mnem == Mnem::Movsx) && cur->numOps == 2 &&
                cur->ops[1].isReg() && regFamily(cur->ops[1].reg) == fam) {
                frozen.insert(fam);
                out.indexAddress = cur->address;
                indexPinned = true;
                continue;
            }
            if (!ok) {
                if (e.loadRegs.count(fam) && !inTop && frozen.empty()) {
                    frozen.insert(fam);
                    out.indexAddress = cur->address;
                    indexPinned = true;
                    continue;
                }
                return false;
            }
            if (inTop && !substitute(e.regs, e.c, fam, def)) return false;
            if (!inTop && e.loadRegs.count(fam)) {
                if (def.hasLoad) {
                    if (frozen.empty()) {
                        frozen.insert(fam);
                        out.indexAddress = cur->address;
                        indexPinned = true;
                        continue;
                    }
                    return false;
                }
                if (!substitute(e.loadRegs, e.loadC, fam, def)) return false;
            }
        }
        // Done when the shape is c + load(c2 + s*idx).
        if (e.hasLoad && e.regs.empty()) {
            int nonFrozen = 0;
            for (auto& [r, k] : e.loadRegs)
                if (!frozen.count(r)) ++nonFrozen;
            if (nonFrozen == 0 && e.loadRegs.size() == 1) break;
        }
    }
    if (!e.hasLoad || !e.regs.empty() || e.loadRegs.size() != 1) return false;
    Family idx = e.loadRegs.begin()->first;
    i64 scale = e.loadRegs.begin()->second;
    if (scale != (i64)e.loadSize || (e.loadSize != 4 && e.loadSize != 8)) return false;
    out.indexFamily = idx;
    out.entrySize = e.loadSize;
    out.tableAddress = (u64)e.loadC;
    if (!is64()) out.tableAddress &= 0xFFFFFFFFull;
    out.relative = e.c != 0;
    out.relativeBase = (u64)e.c;
    if (!img.isValidVa(out.tableAddress)) return false;

    // Bounds check: walk back from the table load looking for
    // "cmp idx, N; ja default" (possibly through register moves).
    i64 count = -1;
    Family bf = idx;
    const Instruction* jcc = nullptr;
    cur = insns.count(out.loadAddress) ? insns.at(out.loadAddress) : &jmp;
    for (int steps = 0; steps < 32 && count < 0; ++steps) {
        const Instruction* p = prevOf(cur->address);
        if (!p) break;
        cur = p;
        if (cur->flow == Flow::CondJump) {
            Cond c = cur->condition();
            jcc = (c == Cond::A || c == Cond::AE) ? cur : nullptr;
            continue;
        }
        if (cur->flow != Flow::Normal) break;
        if (cur->mnem == Mnem::Cmp && cur->numOps == 2 && cur->ops[0].isReg() && cur->ops[1].isImm() &&
            regFamily(cur->ops[0].reg) == bf) {
            if (jcc) {
                i64 n = cur->ops[1].imm & (i64)maskBits(cur->ops[0].size * 8);
                count = jcc->condition() == Cond::A ? n + 1 : n;
                out.defaultTarget = jcc->target;
            }
            break;
        }
        if (writesFamily(*cur, bf)) {
            // Follow simple register-to-register copies of the index.
            if ((cur->mnem == Mnem::Mov || cur->mnem == Mnem::Movzx || cur->mnem == Mnem::Movsxd) &&
                cur->numOps == 2 && cur->ops[1].isReg()) {
                bf = regFamily(cur->ops[1].reg);
                continue;
            }
            break;
        }
        // Instructions between cmp and jcc must not clobber flags.
        if (jcc) {
            switch (cur->mnem) {
            case Mnem::Mov: case Mnem::Movzx: case Mnem::Movsx: case Mnem::Movsxd: case Mnem::Lea: case Mnem::Nop:
                break;
            default:
                jcc = nullptr;
            }
        }
    }

    const i64 kMaxEntries = 4096;
    out.bounded = count > 0;
    if (count <= 0) count = 512; // unbounded: read while entries look valid
    if (count > kMaxEntries) return false;
    for (i64 i = 0; i < count; ++i) {
        u64 entry = 0;
        if (!img.read(out.tableAddress + (u64)i * out.entrySize, &entry, out.entrySize)) {
            if (out.bounded) return false;
            break;
        }
        u64 target;
        if (out.relative) {
            i64 off = out.entrySize == 4 ? (e.loadSigned ? (i64)(i32)entry : (i64)(u32)entry) : (i64)entry;
            target = out.relativeBase + (u64)off;
        } else {
            target = entry;
        }
        if (!is64()) target &= 0xFFFFFFFFull;
        if (!img.isExecutableVa(target) || !instructionAt(target)) {
            if (out.bounded) return false;
            break;
        }
        out.targets.push_back(target);
    }
    return !out.targets.empty();
}

// ---------------------------------------------------------------------------
// Function construction
// ---------------------------------------------------------------------------

std::unique_ptr<Function> Program::buildFunction(u64 entry) {
    auto f = std::make_unique<Function>();
    f->entry = entry;

    std::map<u64, const Instruction*> insns;
    std::set<u64> leaders{entry};
    std::set<u64> tailJumps, noRetCalls, decodeFailAfter;
    std::map<u64, JumpTable> tables;
    std::map<u64, const pe::Import*> tailImports;
    std::vector<u64> work{entry};

    // pdata range of this function (x64), used to recognise tail calls.
    auto pdataOf = [&](u64 va) -> const std::pair<u32, u32>* {
        auto rva = image_->vaToRva(va);
        if (!rva) return nullptr;
        auto it = std::upper_bound(pdataRanges_.begin(), pdataRanges_.end(), std::make_pair(*rva, 0xFFFFFFFFu));
        if (it == pdataRanges_.begin()) return nullptr;
        --it;
        return (*rva >= it->first && *rva < it->second) ? &*it : nullptr;
    };
    const auto* ownRange = pdataOf(entry);
    if (ownRange && image_->rvaToVa(ownRange->first) != entry) ownRange = nullptr;

    auto isTailTarget = [&](u64 target) {
        if (target == entry) return false;
        if (knownEntries_.count(target) || importThunks_.count(target)) return true;
        if (ownRange) {
            auto rva = image_->vaToRva(target);
            if (rva && (*rva < ownRange->first || *rva >= ownRange->second)) {
                // Outside our unwind range: another function's code unless it
                // is an unregistered chunk; treat as tail call when it lands
                // in some other registered function.
                const auto* other = pdataOf(target);
                if (other && other != ownRange) return true;
            }
        }
        return false;
    };

    auto importOfMem = [&](const Instruction& in) -> const pe::Import* {
        if (in.numOps != 1 || !in.ops[0].isMem()) return nullptr;
        if (auto t = in.ripTarget(0)) return image_->importByIat(*t);
        const MemOperand& m = in.ops[0].mem;
        if (m.base == Reg::None && m.index == Reg::None) return image_->importByIat((u64)m.disp & (is64() ? ~0ull : 0xFFFFFFFFull));
        return nullptr;
    };

    size_t budget = 200000; // instruction limit per function
    while (!work.empty()) {
        u64 addr = work.back();
        work.pop_back();
        while (true) {
            if (insns.count(addr)) { leaders.insert(addr); break; }
            if (budget-- == 0) break;
            const Instruction* in = instructionAt(addr);
            if (!in) { f->hasDecodeErrors = true; break; }
            insns[addr] = in;
            bool cont = false;
            switch (in->flow) {
            case Flow::Normal:
                cont = true;
                break;
            case Flow::Call:
                f->callees.insert(in->target);
                if (isNoReturnTarget(in->target)) noRetCalls.insert(addr);
                else cont = true;
                break;
            case Flow::IndirectCall: {
                const pe::Import* imp = importOfMem(*in);
                if (imp && isNoReturnImport(imp)) noRetCalls.insert(addr);
                else cont = true;
                break;
            }
            case Flow::CondJump:
                if (image_->isExecutableVa(in->target)) {
                    leaders.insert(in->target);
                    work.push_back(in->target);
                }
                leaders.insert(in->next());
                work.push_back(in->next());
                break;
            case Flow::Jump:
                if (isTailTarget(in->target)) {
                    tailJumps.insert(addr);
                    f->callees.insert(in->target);
                } else if (image_->isExecutableVa(in->target)) {
                    leaders.insert(in->target);
                    work.push_back(in->target);
                } else {
                    tailJumps.insert(addr);
                }
                break;
            case Flow::IndirectJump: {
                if (const pe::Import* imp = importOfMem(*in)) {
                    tailJumps.insert(addr);
                    tailImports[addr] = imp;
                    break;
                }
                JumpTable jt;
                if (resolveJumpTable(insns, *in, jt)) {
                    for (u64 t : jt.targets) {
                        leaders.insert(t);
                        work.push_back(t);
                    }
                    if (jt.defaultTarget && image_->isExecutableVa(jt.defaultTarget)) {
                        leaders.insert(jt.defaultTarget);
                        work.push_back(jt.defaultTarget);
                    }
                    tables[addr] = std::move(jt);
                } else {
                    f->hasUnresolvedIndirect = true;
                }
                break;
            }
            case Flow::Return:
            case Flow::Halt:
                break;
            }
            if (!cont) break;
            addr = in->next();
        }
    }

    // Detect thunks.
    if (insns.size() == 1) {
        const Instruction* in = insns.begin()->second;
        if (in->flow == Flow::IndirectJump) {
            if (const pe::Import* imp = importOfMem(*in)) {
                f->isImportThunk = true;
                f->thunkImport = imp;
                importThunks_[entry] = imp;
            }
        } else if (in->flow == Flow::Jump) {
            f->isThunk = true;
            f->thunkTarget = in->target;
        }
    }

    // Form basic blocks.
    const Instruction* prev = nullptr;
    BasicBlock* cur = nullptr;
    for (auto& [addr, in] : insns) {
        bool start = !cur || leaders.count(addr) || !prev || prev->next() != addr || prev->endsBlock() ||
                     noRetCalls.count(prev->address);
        if (start) {
            BasicBlock b;
            b.id = (int)f->blocks.size();
            b.start = addr;
            f->blocks.push_back(std::move(b));
            cur = &f->blocks.back();
            f->blockAt[addr] = cur->id;
        }
        cur->insns.push_back(*in);
        cur->end = in->next();
        prev = in;
    }
    // Entry block must be block 0 (it is the lowest address only sometimes).
    if (!f->blocks.empty() && f->blocks[0].start != entry) {
        int ei = f->blockAt.count(entry) ? f->blockAt[entry] : -1;
        if (ei > 0) {
            std::swap(f->blocks[0], f->blocks[ei]);
            f->blocks[0].id = 0;
            f->blocks[ei].id = ei;
            f->blockAt[f->blocks[0].start] = 0;
            f->blockAt[f->blocks[ei].start] = ei;
        }
    }

    // Edges and terminators.
    auto blockFor = [&](u64 a) -> int {
        auto it = f->blockAt.find(a);
        return it == f->blockAt.end() ? -1 : it->second;
    };
    for (auto& b : f->blocks) {
        const Instruction& last = b.last();
        for (const auto& in : b.insns) {
            if (in.flow == Flow::Call || in.flow == Flow::IndirectCall) {
                CallSite cs;
                cs.address = in.address;
                if (in.flow == Flow::Call) {
                    cs.target = in.target;
                    cs.import = importViaThunk(in.target);
                } else {
                    cs.indirect = true;
                    cs.import = importOfMem(in);
                    cs.indirect = cs.import == nullptr;
                }
                cs.noReturn = noRetCalls.count(in.address) > 0;
                b.calls.push_back(cs);
            }
        }
        auto addEdge = [&](u64 target, EdgeKind k) {
            int t = blockFor(target);
            if (t < 0) {
                b.term = Terminator::DecodeError;
                return false;
            }
            CfgEdge e;
            e.target = t;
            e.kind = k;
            b.succs.push_back(std::move(e));
            return true;
        };
        if (noRetCalls.count(last.address)) {
            b.term = Terminator::NoReturnCall;
            continue;
        }
        switch (last.flow) {
        case Flow::Normal:
        case Flow::Call:
        case Flow::IndirectCall:
            b.term = Terminator::Fallthrough;
            if (!addEdge(last.next(), EdgeKind::Fallthrough)) f->hasDecodeErrors = true;
            break;
        case Flow::CondJump:
            b.term = Terminator::Branch;
            if (!addEdge(last.target, EdgeKind::True)) { f->hasDecodeErrors = true; break; }
            if (!addEdge(last.next(), EdgeKind::False)) f->hasDecodeErrors = true;
            break;
        case Flow::Jump:
            if (tailJumps.count(last.address)) {
                b.term = Terminator::TailCall;
                b.tailTarget = last.target;
                b.tailImport = importViaThunk(last.target);
            } else {
                b.term = Terminator::Jump;
                addEdge(last.target, EdgeKind::Jump);
            }
            break;
        case Flow::IndirectJump: {
            if (tailJumps.count(last.address)) {
                b.term = Terminator::TailCall;
                b.tailImport = tailImports.count(last.address) ? tailImports[last.address] : nullptr;
                break;
            }
            auto it = tables.find(last.address);
            if (it == tables.end()) {
                b.term = Terminator::IndirectJump;
                break;
            }
            b.term = Terminator::Switch;
            b.jumpTable = (int)f->jumpTables.size();
            JumpTable& jt = it->second;
            // One edge per distinct target, carrying all selecting indices.
            std::map<u64, std::vector<i64>> byTarget;
            std::vector<u64> order;
            for (size_t i = 0; i < jt.targets.size(); ++i) {
                if (!byTarget.count(jt.targets[i])) order.push_back(jt.targets[i]);
                byTarget[jt.targets[i]].push_back((i64)i);
            }
            for (u64 t : order) {
                int ti = blockFor(t);
                if (ti < 0) continue;
                CfgEdge e;
                e.target = ti;
                e.kind = EdgeKind::Switch;
                e.caseValues = byTarget[t];
                b.succs.push_back(std::move(e));
            }
            f->jumpTables.push_back(jt);
            break;
        }
        case Flow::Return:
            b.term = Terminator::Return;
            b.succs.push_back(CfgEdge{-1, EdgeKind::Return, {}, false});
            break;
        case Flow::Halt:
            b.term = Terminator::Halt;
            break;
        }
    }
    // Blocks ending because the next address failed to decode.
    for (auto& b : f->blocks) {
        if (b.term == Terminator::Fallthrough && b.succs.empty()) b.term = Terminator::DecodeError;
    }
    for (auto& b : f->blocks)
        for (auto& e : b.succs)
            if (e.target >= 0) f->blocks[e.target].preds.push_back(b.id);
    for (auto& b : f->blocks) {
        std::sort(b.preds.begin(), b.preds.end());
        b.preds.erase(std::unique(b.preds.begin(), b.preds.end()), b.preds.end());
    }
    return f;
}

// Computes which functions can return; see header for the fixpoint.
void Program::computeReturns() {
    for (auto& [va, f] : functions_) {
        f->returns = !noReturnFunctions_.count(va);
        if (f->isImportThunk) {
            f->returns = !isNoReturnImport(f->thunkImport);
            if (!f->returns) noReturnFunctions_.insert(va);
        }
    }
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto& [va, f] : functions_) {
            if (f->isImportThunk || !f->returns) continue;
            bool returns = false;
            for (const auto& b : f->blocks) {
                switch (b.term) {
                case Terminator::Return:
                case Terminator::IndirectJump:
                case Terminator::DecodeError:
                    returns = true;
                    break;
                case Terminator::TailCall:
                    if (b.tailImport) returns |= !isNoReturnImport(b.tailImport);
                    else if (b.tailTarget) returns |= !noReturnFunctions_.count(b.tailTarget);
                    else returns = true;
                    break;
                default:
                    break;
                }
                if (returns) break;
            }
            if (!returns) {
                f->returns = false;
                noReturnFunctions_.insert(va);
                changed = true;
            }
        }
    }
}

void Program::discoverFunctions() {
    collectSeeds();
    // Iterate: building functions discovers new call targets; the set of
    // known entries and no-return functions changes CFGs, so rebuild until
    // stable (bounded).
    for (int round = 0; round < 8; ++round) {
        size_t entriesBefore = knownEntries_.size();
        size_t noretBefore = noReturnFunctions_.size();
        std::deque<u64> work(knownEntries_.begin(), knownEntries_.end());
        std::set<u64> builtThisRound;
        while (!work.empty()) {
            u64 va = work.front();
            work.pop_front();
            if (builtThisRound.count(va)) continue;
            builtThisRound.insert(va);
            auto f = buildFunction(va);
            for (u64 c : f->callees) {
                if (!image_->isExecutableVa(c)) continue;
                if (knownEntries_.insert(c).second) work.push_back(c);
            }
            functions_[va] = std::move(f);
        }
        computeReturns();
        if (knownEntries_.size() == entriesBefore && noReturnFunctions_.size() == noretBefore && round > 0) break;
    }
    // Names.
    for (auto& [va, f] : functions_) {
        if (auto rva = image_->vaToRva(va); rva && image_->exportByRva(*rva)) {
            f->name = image_->exportByRva(*rva)->name;
            f->fromExport = true;
        }
        if (f->name.empty()) {
            if (auto s = symbolName(va)) f->name = *s;
        }
        if (f->name.empty() && f->isImportThunk) f->name = f->thunkImport->displayName();
        if (f->name.empty()) f->name = strfmt("sub_%llx", (unsigned long long)va);
    }
}

Function* Program::ensureFunction(u64 va) {
    if (Function* f = functionAt(va)) return f;
    if (!image_->isExecutableVa(va) || !instructionAt(va)) return nullptr;
    knownEntries_.insert(va);
    auto f = buildFunction(va);
    f->name = symbolName(va).value_or(strfmt("sub_%llx", (unsigned long long)va));
    Function* raw = f.get();
    functions_[va] = std::move(f);
    return raw;
}

} // namespace dc
