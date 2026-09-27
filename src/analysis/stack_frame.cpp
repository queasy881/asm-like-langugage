#include "analysis/stack_frame.h"

#include <algorithm>
#include <sstream>

namespace dc {

using ir::Op;
using ir::ValueId;
using ir::kNoValue;

const char* slotKindName(SlotKind k) {
    switch (k) {
    case SlotKind::Local: return "local";
    case SlotKind::IncomingArg: return "incoming-arg";
    case SlotKind::ReturnAddress: return "return-address";
    case SlotKind::SavedRegister: return "saved-register";
    case SlotKind::OutgoingArg: return "outgoing-arg";
    }
    return "?";
}

const FrameSlot* StackFrame::at(i64 offset) const {
    for (const auto& s : slots)
        if (s.offset == offset) return &s;
    return nullptr;
}

FrameSlot* StackFrame::at(i64 offset) {
    for (auto& s : slots)
        if (s.offset == offset) return &s;
    return nullptr;
}

std::string StackFrame::print() const {
    std::ostringstream os;
    os << "stack frame: " << slots.size() << " slots, lowest sp " << lowestSp << ", stack args from "
       << stackArgStart << "\n";
    for (const auto& s : slots) {
        os << strfmt("  %+6lld  %-15s size %-3u %s", (long long)s.offset, slotKindName(s.kind), s.size,
                     s.name.c_str());
        if (s.escaped) os << " [address taken]";
        if (s.mixedSize) os << " [mixed widths]";
        if (s.promoted) os << " [promoted]";
        os << strfmt("  (%u loads, %u stores)", s.loads, s.stores);
        os << "\n";
    }
    return os.str();
}

StackFrame analyzeStackFrame(const ir::Function& f, const ConventionInfo& ci, unsigned ptrBytes) {
    StackFrame frame;
    frame.stackArgStart = ci.stackArgStart;

    struct Access {
        unsigned size = 0;
        bool mixed = false;
        bool escaped = false;
        unsigned loads = 0, stores = 0;
        ir::Type type;
    };
    std::map<i64, Access> accesses;
    auto uses = f.buildUses();

    for (const auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.op != Op::FrameAddr) continue;
            i64 off = (i64)in.imm;
            Access& a = accesses[off];
            auto it = uses.find(v);
            if (it == uses.end()) continue;
            for (ValueId u : it->second) {
                const ir::Inst& ui = f.inst(u);
                if (ui.op == Op::Load && ui.args[0] == v) {
                    ++a.loads;
                    unsigned sz = ui.type.bytes();
                    if (a.size && a.size != sz) a.mixed = true;
                    if (sz > a.size) { a.size = sz; a.type = ui.type; }
                } else if (ui.op == Op::Store && ui.args[0] == v) {
                    ++a.stores;
                    unsigned sz = f.inst(ui.args[1]).type.bytes();
                    if (a.size && a.size != sz) a.mixed = true;
                    if (sz > a.size) { a.size = sz; a.type = f.inst(ui.args[1]).type; }
                } else {
                    // Anything else means the address itself is used.
                    a.escaped = true;
                }
            }
        }
    }

    // Lowest stack pointer reached, used to recognise the outgoing argument area.
    for (const auto& [off, a] : accesses) frame.lowestSp = std::min(frame.lowestSp, off);
    frame.minOffset = frame.lowestSp;

    for (const auto& [off, a] : accesses) {
        FrameSlot s;
        s.offset = off;
        s.size = a.size ? a.size : ptrBytes;
        s.type = a.type.isVoid() ? ir::Type::i((u16)(s.size * 8)) : a.type;
        s.escaped = a.escaped;
        s.mixedSize = a.mixed;
        s.loads = a.loads;
        s.stores = a.stores;
        if (off >= (i64)ci.stackArgStart) s.kind = SlotKind::IncomingArg;
        else if (off >= 0 && off < (i64)ptrBytes) s.kind = SlotKind::ReturnAddress;
        else if (off > 0) s.kind = SlotKind::IncomingArg;
        else if (a.stores > 0 && a.loads == 0 && off < 0 && off - frame.lowestSp < 0x20)
            s.kind = SlotKind::OutgoingArg;
        else s.kind = SlotKind::Local;
        if (s.escaped) frame.anyEscaped = true;
        frame.slots.push_back(std::move(s));
    }
    std::sort(frame.slots.begin(), frame.slots.end(), [](const FrameSlot& a, const FrameSlot& b) { return a.offset < b.offset; });

    // Name the slots.
    int localIdx = 0, argIdx = 0;
    for (auto& s : frame.slots) {
        switch (s.kind) {
        case SlotKind::IncomingArg: s.name = strfmt("stack_arg%d", argIdx++); break;
        case SlotKind::ReturnAddress: s.name = "return_address"; break;
        case SlotKind::OutgoingArg: s.name = strfmt("outgoing_%llx", (unsigned long long)(-s.offset)); break;
        default: s.name = strfmt("local_%llx", (unsigned long long)(-s.offset)); ++localIdx; break;
        }
    }
    return frame;
}

void promoteStackSlots(ir::Function& f, StackFrame& frame) {
    // An escaped address may be used for pointer arithmetic, so assume it can
    // reach everything up to the next slot and keep those in memory.
    std::vector<std::pair<i64, i64>> poisoned;
    for (size_t i = 0; i < frame.slots.size(); ++i) {
        if (!frame.slots[i].escaped) continue;
        i64 lo = frame.slots[i].offset;
        i64 hi = i + 1 < frame.slots.size() ? frame.slots[i + 1].offset : lo + (i64)frame.slots[i].size;
        poisoned.push_back({lo, std::max(hi, lo + (i64)frame.slots[i].size)});
    }
    auto isPoisoned = [&](i64 off, unsigned size) {
        for (auto [lo, hi] : poisoned)
            if (off < hi && lo < off + (i64)size) return true;
        return false;
    };

    unsigned nextId = 0;
    std::map<i64, unsigned> slotIds;
    for (auto& s : frame.slots) {
        bool ok = !s.escaped && !s.mixedSize && s.kind != SlotKind::OutgoingArg &&
                  s.kind != SlotKind::ReturnAddress && !isPoisoned(s.offset, s.size) && s.size <= 8;
        // Overlapping slots cannot be treated as independent variables.
        for (const auto& o : frame.slots) {
            if (&o == &s) continue;
            if (o.offset < s.offset + (i64)s.size && s.offset < o.offset + (i64)o.size) ok = false;
        }
        if (!ok) continue;
        s.promoted = true;
        s.slotId = nextId++;
        slotIds[s.offset] = s.slotId;
        ++frame.promotedCount;
    }
    if (slotIds.empty()) return;

    // Rewrite loads and stores of promoted slots into location accesses.
    for (auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            ir::Inst& in = f.inst(v);
            if (in.op != Op::Load && in.op != Op::Store) continue;
            const ir::Inst& addr = f.inst(in.args[0]);
            if (addr.op != Op::FrameAddr) continue;
            auto it = slotIds.find((i64)addr.imm);
            if (it == slotIds.end()) continue;
            const FrameSlot* slot = frame.at((i64)addr.imm);
            if (in.op == Op::Load) {
                in.op = Op::ReadLoc;
                in.loc = ir::Loc{ir::LocKind::Stack, (u16)it->second, (u16)slot->size};
                in.args.clear();
            } else {
                ValueId val = in.args[1];
                in.op = Op::WriteLoc;
                in.loc = ir::Loc{ir::LocKind::Stack, (u16)it->second, (u16)slot->size};
                in.args = {val};
            }
        }
    }
    // Frame address computations with no remaining users disappear with DCE.
}

} // namespace dc
