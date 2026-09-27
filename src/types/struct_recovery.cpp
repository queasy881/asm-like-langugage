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
        if (rootIn.op == Op::Arg) name = strfmt("s_%s_arg%u", functionName.c_str(), rootIn.aux + 1);
        else name = strfmt("s_%s_%s", functionName.c_str(), layoutHash(accesses).c_str());

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
        st->bits = (unsigned)cursor * 8;
        created.push_back(st);
        types.valueTypes[root] = table.pointer(st);
        types.valueConfidence[root] = Confidence::Medium;
    }
    (void)ptrBits;
    std::sort(created.begin(), created.end(), [](const Type* a, const Type* b) { return a->name < b->name; });
    created.erase(std::unique(created.begin(), created.end()), created.end());
    return created;
}

} // namespace dc::types
