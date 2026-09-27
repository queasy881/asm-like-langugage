#include "types/struct_recovery.h"

#include <algorithm>
#include <sstream>

namespace dc::types {

using ir::Op;
using ir::ValueId;

namespace {

TypeRef scalarFor(TypeTable& table, const AccessRecord& a) {
    if (a.kind == Kind::Float) return table.floating(a.size == 4 ? 32 : 64);
    return table.integer(a.size * 8, a.isSigned);
}

// A stable name for a layout, so the same structure seen through different
// functions gets the same name.
std::string layoutHash(const std::vector<AccessRecord>& accesses) {
    std::string s;
    for (const auto& a : accesses)
        s += strfmt("%lld:%u:%d;", (long long)a.offset, a.size, (int)a.kind);
    return strfmt("%08x", (unsigned)(fnv1a64(s) & 0xFFFFFFFFu));
}

} // namespace

std::vector<const Type*> recoverStructs(ir::Function& f, TypeTable& table, TypeResult& types,
                                        const std::string& functionName, unsigned ptrBits,
                                        const StructRecoveryOptions& opt) {
    std::vector<const Type*> created;

    for (auto& [root, accesses] : types.pointerAccesses) {
        if (accesses.size() < opt.minFields) continue;
        // Negative or absurd offsets mean this is not an object pointer.
        bool plausible = true;
        for (const auto& a : accesses)
            if (a.offset < 0 || a.offset > opt.maxOffset) plausible = false;
        if (!plausible) continue;
        // Overlapping accesses of different widths cannot be laid out as
        // distinct fields; leave the pointer alone rather than invent one.
        bool overlap = false;
        for (size_t i = 1; i < accesses.size(); ++i)
            if (accesses[i].offset < accesses[i - 1].offset + (i64)accesses[i - 1].size) overlap = true;
        if (overlap) continue;

        const ir::Inst& rootIn = f.inst(root);
        std::string name;
        if (rootIn.op == Op::Arg)
            name = sanitizeIdentifier(strfmt("s_%s_arg%u", functionName.c_str(), rootIn.aux + 1));
        else
            name = sanitizeIdentifier(strfmt("s_%s_%s", functionName.c_str(), layoutHash(accesses).c_str()));

        Type* st = table.makeStruct(name);
        if (!st->fields.empty()) {
            // Already built (a second function saw the same object).
            types.valueTypes[root] = table.pointer(st);
            continue;
        }

        i64 cursor = 0;
        for (const auto& a : accesses) {
            // Fill the gap the layout implies so offsets stay exact.
            while (cursor < a.offset) {
                i64 gap = a.offset - cursor;
                unsigned chunk = gap >= 8 && (cursor % 8) == 0 ? 8 : (gap >= 4 && (cursor % 4) == 0 ? 4 : (gap >= 2 && (cursor % 2) == 0 ? 2 : 1));
                StructField pad;
                pad.offset = (u64)cursor;
                pad.size = chunk;
                pad.type = table.integer(chunk * 8, false);
                pad.name = strfmt("field_%llx", (unsigned long long)cursor);
                pad.accessed = false;
                st->fields.push_back(std::move(pad));
                cursor += chunk;
            }
            StructField fld;
            fld.offset = (u64)a.offset;
            fld.size = a.size;
            fld.type = scalarFor(table, a);
            fld.name = strfmt("field_%llx", (unsigned long long)a.offset);
            fld.accessed = true;
            st->fields.push_back(std::move(fld));
            cursor = a.offset + (i64)a.size;
        }
        // When the pointer walks an array, the element is exactly one stride.
        auto strideIt = types.pointerStride.find(root);
        if (strideIt != types.pointerStride.end() && (i64)strideIt->second > cursor) {
            i64 target = (i64)strideIt->second;
            while (cursor < target) {
                i64 gap = target - cursor;
                unsigned chunk = gap >= 8 && (cursor % 8) == 0 ? 8 : (gap >= 4 && (cursor % 4) == 0 ? 4 : (gap >= 2 && (cursor % 2) == 0 ? 2 : 1));
                StructField pad;
                pad.offset = (u64)cursor;
                pad.size = chunk;
                pad.type = table.integer(chunk * 8, false);
                pad.name = strfmt("field_%llx", (unsigned long long)cursor);
                pad.accessed = false;
                st->fields.push_back(std::move(pad));
                cursor += chunk;
            }
        }
        st->bits = (unsigned)cursor * 8;
        created.push_back(st);
        types.valueTypes[root] = table.pointer(st);
        types.valueConfidence[root] = Confidence::Medium;
    }
    // An element pointer computed as base + index * sizeof(struct) means the
    // base is an array of that struct, so it gets the same type. Without this
    // the array itself stays an anonymous integer.
    bool spread = true;
    for (int round = 0; round < 4 && spread; ++round) {
        spread = false;
        for (auto& b : f.blocks()) {
            for (ValueId v : b.insts) {
                const ir::Inst& in = f.inst(v);
                if (in.op != Op::Add || in.args.size() != 2) continue;
                TypeRef vt = types.valueTypes.count(v) ? types.valueTypes[v] : nullptr;
                if (!vt || !vt->isPointer() || !vt->pointee || !vt->pointee->isStruct()) continue;
                unsigned size = vt->pointee->sizeInBytes();
                if (!size) continue;
                for (int side = 0; side < 2; ++side) {
                    const ir::Inst& other = f.inst(in.args[1 - side]);
                    bool scaled = false;
                    if (other.op == Op::Mul && other.args.size() == 2) {
                        const ir::Inst& k = f.inst(other.args[1]);
                        if (k.op == Op::Const && k.imm == size) scaled = true;
                    }
                    if (!scaled) continue;
                    ValueId base = in.args[side];
                    TypeRef bt = types.valueTypes.count(base) ? types.valueTypes[base] : nullptr;
                    if (bt && bt->isPointer() && bt->pointee && bt->pointee->isStruct()) continue;
                    types.valueTypes[base] = vt;
                    types.valueConfidence[base] = Confidence::Medium;
                    spread = true;
                }
            }
        }
        // And the other way: stepping through an array of structures by the
        // element size gives another pointer to the same structure.
        for (auto& b : f.blocks()) {
            for (ValueId v : b.insts) {
                const ir::Inst& in = f.inst(v);
                if (in.op != Op::Add || in.args.size() != 2) continue;
                TypeRef vt = types.valueTypes.count(v) ? types.valueTypes[v] : nullptr;
                if (vt && vt->isPointer() && vt->pointee && vt->pointee->isStruct()) continue;
                for (int side = 0; side < 2; ++side) {
                    TypeRef bt = types.valueTypes.count(in.args[side]) ? types.valueTypes[in.args[side]] : nullptr;
                    if (!bt || !bt->isPointer() || !bt->pointee || !bt->pointee->isStruct()) continue;
                    unsigned size = bt->pointee->sizeInBytes();
                    if (!size) continue;
                    const ir::Inst& other = f.inst(in.args[1 - side]);
                    bool scaled = false;
                    if (other.op == Op::Mul && other.args.size() == 2) {
                        const ir::Inst& k = f.inst(other.args[1]);
                        if (k.op == Op::Const && k.imm == size) scaled = true;
                    }
                    if (other.op == Op::Const && size && other.imm % size == 0) scaled = true;
                    if (!scaled) continue;
                    types.valueTypes[v] = bt;
                    types.valueConfidence[v] = Confidence::Medium;
                    spread = true;
                }
            }
        }
    }
    (void)ptrBits;
    std::sort(created.begin(), created.end(), [](const Type* a, const Type* b) { return a->name < b->name; });
    created.erase(std::unique(created.begin(), created.end()), created.end());
    return created;
}

} // namespace dc::types
