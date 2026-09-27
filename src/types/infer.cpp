#include "types/infer.h"

#include "winapi/api_database.h"

#include <algorithm>
#include <functional>

namespace dc::types {

using ir::Op;
using ir::ValueId;
using ir::kNoValue;

int TypeInference::find(int a) {
    while (parent_[a] != a) {
        parent_[a] = parent_[parent_[a]];
        a = parent_[a];
    }
    return a;
}

void TypeInference::unite(int a, int b) {
    a = find(a);
    b = find(b);
    if (a == b) return;
    // A pointer and an integer are never the same type. Merging them is how a
    // length ends up declared as a pointer because it was added to one.
    if (classFacts_[a].pointer != classFacts_[b].pointer) return;
    parent_[b] = a;
    // Merge the evidence of the two classes.
    ValueFacts& fa = classFacts_[a];
    const ValueFacts& fb = classFacts_[b];
    fa.signedVotes += fb.signedVotes;
    fa.unsignedVotes += fb.unsignedVotes;
    fa.boolean = fa.boolean || fb.boolean;
    fa.pointer = fa.pointer || fb.pointer;
    fa.notFloat = fa.notFloat || fb.notFloat;
    fa.codePointer = fa.codePointer || fb.codePointer;
    if (!fa.pointee) fa.pointee = fb.pointee;
    if (!fa.fixed) fa.fixed = fb.fixed;
    if (fb.bits > fa.bits) fa.bits = fb.bits;
    if (fa.kind == Kind::Unknown) fa.kind = fb.kind;
    else if (fb.kind != Kind::Unknown && fb.kind != fa.kind) {
        // Float and integer disagreeing means one of them is a reinterpret;
        // prefer the stronger evidence and lower the confidence.
        if (fb.confidence > fa.confidence) fa.kind = fb.kind;
        fa.confidence = Confidence::Low;
    }
    if (fb.confidence > fa.confidence && fa.confidence != Confidence::Low) fa.confidence = fb.confidence;
}

int TypeInference::classOf(ValueId v) {
    auto it = classIndex_.find(v);
    if (it != classIndex_.end()) return find(it->second);
    int idx = (int)parent_.size();
    parent_.push_back(idx);
    classFacts_.emplace_back();
    classIndex_[v] = idx;
    return idx;
}

ValueFacts& TypeInference::facts(ValueId v) { return classFacts_[classOf(v)]; }

void TypeInference::seed(ir::Function& f, const Signature& sig) {
    unsigned ptrBits = prog_.pointerSize() * 8;

    for (auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            ValueFacts& fc = facts(v);
            if (in.type.bits > fc.bits) fc.bits = in.type.bits;

            switch (in.op) {
            case Op::Arg: {
                if (in.aux < sig.paramTypes.size()) {
                    ir::Type pt = sig.paramTypes[in.aux];
                    if (pt.isFloat()) fc.kind = Kind::Float;
                    else fc.kind = Kind::Int;
                    fc.confidence = Confidence::Medium;
                }
                break;
            }
            case Op::GlobalAddr:
            case Op::FrameAddr:
                fc.kind = Kind::Pointer;
                fc.pointer = true;
                fc.confidence = Confidence::High;
                break;
            case Op::Load:
            case Op::Store: {
                ValueFacts& af = facts(in.args[0]);
                af.kind = Kind::Pointer;
                af.pointer = true;
                if (af.confidence < Confidence::High) af.confidence = Confidence::High;
                if (af.bits < ptrBits) af.bits = ptrBits;
                ValueId valueSide = in.op == Op::Load ? v : in.args[1];
                ir::Type vt = f.inst(valueSide).type;
                // The pointer points at whatever is read or written through it.
                if (!af.pointee && !vt.isVoid()) {
                    if (vt.isFloat()) af.pointee = table_.floating(vt.bits);
                    else if (vt.bits >= 8) af.pointee = table_.integer(vt.bits, vt.bits != 8);
                }
                if (in.op == Op::Load) {
                    ValueFacts& lf = facts(v);
                    if (vt.isFloat()) lf.kind = Kind::Float;
                    else if (lf.kind == Kind::Unknown) lf.kind = Kind::Int;
                    if (lf.confidence < Confidence::Medium) lf.confidence = Confidence::Medium;
                }
                break;
            }
            case Op::SDiv: case Op::SRem: case Op::AShr:
            case Op::CmpSlt: case Op::CmpSle: case Op::CmpSgt: case Op::CmpSge:
                for (size_t i = 0; i < in.args.size(); ++i) {
                    ValueFacts& a = facts(in.args[i]);
                    a.signedVotes += 2;
                    if (a.kind == Kind::Unknown) a.kind = Kind::Int;
                }
                break;
            case Op::UDiv: case Op::URem: case Op::LShr:
            case Op::CmpUlt: case Op::CmpUle: case Op::CmpUgt: case Op::CmpUge:
                for (size_t i = 0; i < in.args.size(); ++i) {
                    ValueFacts& a = facts(in.args[i]);
                    // An unsigned comparison against a small constant is how a
                    // range check is written, so it is weaker evidence.
                    a.unsignedVotes += f.inst(in.args[i]).op == Op::Const ? 0 : 2;
                    if (a.kind == Kind::Unknown) a.kind = Kind::Int;
                }
                break;
            case Op::And: case Op::Or: case Op::Xor: case Op::Not:
            case Op::Shl: case Op::Rol: case Op::Ror:
                // Bit manipulation is an integer operation. A value that is a
                // float everywhere else cannot also be masked, and printing it
                // as one produces C that does not even compile.
                if (!in.type.isFloat()) {
                    fc.notFloat = true;
                    if (fc.kind == Kind::Unknown) fc.kind = Kind::Int;
                }
                for (ValueId a : in.args)
                    if (!f.inst(a).type.isFloat()) facts(a).notFloat = true;
                break;
            case Op::SExt:
                facts(in.args[0]).signedVotes += 2;
                break;
            case Op::ZExt:
                facts(in.args[0]).unsignedVotes += 1;
                break;
            case Op::SIToFP:
                facts(in.args[0]).signedVotes += 2;
                fc.kind = Kind::Float;
                fc.confidence = Confidence::High;
                break;
            case Op::UIToFP:
                facts(in.args[0]).unsignedVotes += 2;
                fc.kind = Kind::Float;
                fc.confidence = Confidence::High;
                break;
            case Op::FPToSI:
                fc.signedVotes += 2;
                fc.kind = Kind::Int;
                facts(in.args[0]).kind = Kind::Float;
                break;
            case Op::FPToUI:
                fc.unsignedVotes += 2;
                fc.kind = Kind::Int;
                facts(in.args[0]).kind = Kind::Float;
                break;
            case Op::Call: {
                if (!in.call) break;
                size_t base = in.aux ? 1 : 0;
                for (size_t i = 0; i + base < in.args.size() && i < in.call->paramTypes.size(); ++i) {
                    ValueFacts& a = facts(in.args[i + base]);
                    ir::Type pt = in.call->paramTypes[i];
                    if (pt.isFloat()) {
                        a.kind = Kind::Float;
                        a.confidence = Confidence::High;
                    } else if (pt.isPtr()) {
                        a.kind = Kind::Pointer;
                        a.pointer = true;
                        a.confidence = Confidence::High;
                    } else if (a.kind == Kind::Unknown) {
                        a.kind = Kind::Int;
                        a.confidence = Confidence::Medium;
                    }
                }
                if (!in.type.isVoid()) {
                    if (in.call->returnType.isFloat()) fc.kind = Kind::Float;
                    else if (in.call->returnType.isPtr()) { fc.kind = Kind::Pointer; fc.pointer = true; }
                    else fc.kind = Kind::Int;
                    fc.confidence = in.call->isImport ? Confidence::High : Confidence::Medium;
                }
                break;
            }
            default:
                if (ir::isFloatOp(in.op)) {
                    if (!in.type.isVoid() && !ir::isComparison(in.op)) {
                        fc.kind = Kind::Float;
                        fc.confidence = Confidence::High;
                    }
                    for (ValueId a : in.args)
                        if (f.inst(a).type.isFloat()) {
                            ValueFacts& af = facts(a);
                            af.kind = Kind::Float;
                            af.confidence = Confidence::High;
                        }
                }
                break;
            }
            if (in.type.isFloat()) {
                fc.kind = Kind::Float;
                if (fc.confidence < Confidence::High) fc.confidence = Confidence::High;
            }
            if (in.type.bits == 1) fc.boolean = true;
        }
    }

    // A function's own return type, and the types its callees expect, are the
    // strongest evidence available.
    for (auto& b : f.blocks()) {
        if (b.insts.empty()) continue;
        const ir::Inst& term = f.inst(b.insts.back());
        if (term.op != Op::Return || term.args.empty()) continue;
        ValueFacts& rf = facts(term.args[0]);
        if (sig.returnType.isFloat()) rf.kind = Kind::Float;
        else if (rf.kind == Kind::Unknown) rf.kind = Kind::Int;
    }
}

void TypeInference::propagate(ir::Function& f) {
    // Values that take part in a relational comparison against something that
    // is not a null test. Those behave like indices, not like objects.
    std::map<ValueId, bool> ordered;
    for (const auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            switch (in.op) {
            case Op::CmpSlt: case Op::CmpSle: case Op::CmpSgt: case Op::CmpSge:
            case Op::CmpUlt: case Op::CmpUle: case Op::CmpUgt: case Op::CmpUge:
                break;
            default:
                continue;
            }
            if (in.args.size() != 2) continue;
            for (int i = 0; i < 2; ++i) {
                const ir::Inst& o = f.inst(in.args[1 - i]);
                if (o.op == Op::Const && o.imm == 0) continue;   // a null test
                ordered[in.args[i]] = true;
            }
        }
    }

    // Phase one: work out which values are pointers, to a fixed point. This
    // has to finish before anything is united, because uniting the operands of
    // an addition would otherwise drag the offset into the pointer's class.
    for (int round = 0; round < 8; ++round) {
        bool changed = false;
        auto makePointer = [&](ValueId v, TypeRef pointee) {
            ValueFacts& r = facts(v);
            if (r.pointer) {
                if (!r.pointee && pointee) r.pointee = pointee;
                return false;
            }
            r.pointer = true;
            r.kind = Kind::Pointer;
            if (!r.pointee) r.pointee = pointee;
            if (r.confidence < Confidence::Medium) r.confidence = Confidence::Medium;
            return true;
        };
        // A phi or a select is a pointer exactly when its inputs are, and the
        // inputs are pointers when it is.
        for (auto& b : f.blocks()) {
            for (ValueId v : b.insts) {
                const ir::Inst& in = f.inst(v);
                if (in.op != Op::Phi && in.op != Op::Select) continue;
                size_t first = in.op == Op::Select ? 1 : 0;
                bool anyPtr = facts(v).pointer;
                TypeRef pointee = facts(v).pointee;
                for (size_t i = first; i < in.args.size(); ++i) {
                    if (in.args[i] == kNoValue) continue;
                    if (facts(in.args[i]).pointer) {
                        anyPtr = true;
                        if (!pointee) pointee = facts(in.args[i]).pointee;
                    }
                }
                if (!anyPtr) continue;
                changed |= makePointer(v, pointee);
                for (size_t i = first; i < in.args.size(); ++i) {
                    if (in.args[i] == kNoValue) continue;
                    if (f.inst(in.args[i]).op == Op::Const) continue; // a null literal
                    changed |= makePointer(in.args[i], pointee);
                }
            }
        }
        for (auto& b : f.blocks()) {
            for (ValueId v : b.insts) {
                const ir::Inst& in = f.inst(v);
                if ((in.op != Op::Add && in.op != Op::Sub) || in.args.size() != 2) continue;
                bool aPtr = facts(in.args[0]).pointer;
                bool bPtr = facts(in.args[1]).pointer;
                if (!aPtr && !bPtr && in.op == Op::Add && facts(v).pointer) {
                    // The sum is dereferenced, so one side carried the object
                    // and the other was the offset into it. Whichever side
                    // looks like an index leaves the other as the pointer.
                    auto indexLike = [&](ValueId o) {
                        const ir::Inst& oi = f.inst(o);
                        if (oi.op == Op::Const) return 4;
                        if (oi.op == Op::Mul || oi.op == Op::Shl) return 3;
                        if (oi.op == Op::SExt || oi.op == Op::ZExt) return 3;
                        // Where both sides are the same width, as on 32-bit,
                        // the tell is that an index gets range-checked and a
                        // pointer does not.
                        auto it = ordered.find(o);
                        if (it != ordered.end() && it->second) return 2;
                        if (oi.type.bits < prog_.pointerSize() * 8) return 1;
                        return 0;
                    };
                    int sa = indexLike(in.args[0]);
                    int sb = indexLike(in.args[1]);
                    if (sa != sb) {
                        ValueId base = sa > sb ? in.args[1] : in.args[0];
                        changed |= makePointer(base, facts(v).pointee);
                    }
                    continue;
                }
                if (aPtr == bPtr) continue; // neither, or pointer difference
                if (bPtr && in.op == Op::Sub) continue;
                ValueFacts& r = facts(v);
                if (r.pointer) continue;
                r.pointer = true;
                r.kind = Kind::Pointer;
                if (!r.pointee) r.pointee = facts(aPtr ? in.args[0] : in.args[1]).pointee;
                if (r.confidence < Confidence::Medium) r.confidence = Confidence::Medium;
                changed = true;
            }
        }
        if (!changed) break;
    }

    // Values that must share a type.
    for (int round = 0; round < 4; ++round) {
        for (auto& b : f.blocks()) {
            for (ValueId v : b.insts) {
                const ir::Inst& in = f.inst(v);
                switch (in.op) {
                case Op::Phi:
                    for (ValueId a : in.args)
                        if (a != kNoValue) unite(classOf(v), classOf(a));
                    break;
                case Op::Select:
                    if (in.args.size() == 3) {
                        unite(classOf(v), classOf(in.args[1]));
                        unite(classOf(v), classOf(in.args[2]));
                    }
                    break;
                case Op::And: case Op::Or: case Op::Xor:
                    // Bit masking does not change what a value is.
                    if (in.args.size() == 2) {
                        for (ValueId a : in.args)
                            if (f.inst(a).op != Op::Const) unite(classOf(v), classOf(a));
                    }
                    break;
                case Op::Add: case Op::Sub: {
                    if (in.args.size() != 2) break;
                    // Pointer arithmetic keeps the pointer type; integer
                    // arithmetic keeps the integer one.
                    bool aPtr = facts(in.args[0]).pointer;
                    bool bPtr = facts(in.args[1]).pointer;
                    if (aPtr && !bPtr) {
                        ValueFacts& r = facts(v);
                        r.kind = Kind::Pointer;
                        r.pointer = true;
                        if (!r.pointee) r.pointee = facts(in.args[0]).pointee;
                        if (r.confidence < Confidence::Medium) r.confidence = Confidence::Medium;
                    } else if (bPtr && !aPtr && in.op == Op::Add) {
                        ValueFacts& r = facts(v);
                        r.kind = Kind::Pointer;
                        r.pointer = true;
                        if (!r.pointee) r.pointee = facts(in.args[1]).pointee;
                        if (r.confidence < Confidence::Medium) r.confidence = Confidence::Medium;
                    } else if (!aPtr && !bPtr) {
                        for (ValueId a : in.args)
                            if (f.inst(a).op != Op::Const) unite(classOf(v), classOf(a));
                    }
                    break;
                }
                case Op::Mul: case Op::SDiv: case Op::UDiv: case Op::SRem: case Op::URem:
                    for (ValueId a : in.args)
                        if (f.inst(a).op != Op::Const) unite(classOf(v), classOf(a));
                    break;
                case Op::Shl: case Op::LShr: case Op::AShr:
                    if (!in.args.empty() && f.inst(in.args[0]).op != Op::Const)
                        unite(classOf(v), classOf(in.args[0]));
                    break;
                case Op::Neg: case Op::Not:
                    if (!in.args.empty()) unite(classOf(v), classOf(in.args[0]));
                    break;
                default:
                    break;
                }
            }
        }
    }
}

// Records the constant offsets at which each pointer root is dereferenced,
// which is what struct recovery is built from.
void TypeInference::collectPointerAccesses(ir::Function& f, TypeResult& out) {
    // Resolves an address to the object it is inside: a base value, the
    // constant offset within the element, and the array stride if one is
    // being walked. Peeling the strided term is what makes every access to an
    // array of structures land on the same base, so the fields seen through
    // different index expressions describe one structure.
    struct Resolved {
        ValueId base = 0;
        i64 offset = 0;
        u64 stride = 0;
    };
    std::function<Resolved(ValueId, int)> resolveAddr = [&](ValueId v, int depth) -> Resolved {
        if (depth > 24) return {v, 0, 0};
        const ir::Inst& in = f.inst(v);
        if (in.op == Op::Add && in.args.size() == 2) {
            for (int side = 0; side < 2; ++side) {
                const ir::Inst& term = f.inst(in.args[side]);
                if (term.op == Op::Const) {
                    Resolved r = resolveAddr(in.args[1 - side], depth + 1);
                    r.offset += (i64)signExtend(term.imm, term.type.bits);
                    return r;
                }
            }
            for (int side = 0; side < 2; ++side) {
                const ir::Inst& term = f.inst(in.args[side]);
                // An index scaled by a constant is a step through an array.
                u64 stride = 0;
                if (term.op == Op::Mul && term.args.size() == 2) {
                    const ir::Inst& k = f.inst(term.args[1]);
                    if (k.op == Op::Const) stride = k.imm;
                } else if (term.op == Op::Shl && term.args.size() == 2) {
                    const ir::Inst& k = f.inst(term.args[1]);
                    if (k.op == Op::Const && k.imm < 32) stride = 1ull << k.imm;
                }
                if (stride == 0 || stride > (1u << 16)) continue;
                Resolved r = resolveAddr(in.args[1 - side], depth + 1);
                if (!r.stride) r.stride = stride;
                return r;
            }
        }
        if (in.op == Op::Sub && in.args.size() == 2) {
            const ir::Inst& rhs = f.inst(in.args[1]);
            if (rhs.op == Op::Const) {
                Resolved r = resolveAddr(in.args[0], depth + 1);
                r.offset -= (i64)signExtend(rhs.imm, rhs.type.bits);
                return r;
            }
        }
        if (ir::isCast(in.op) && !in.args.empty()) return resolveAddr(in.args[0], depth + 1);
        return {v, 0, 0};
    };

    for (auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.op != Op::Load && in.op != Op::Store) continue;
            Resolved res = resolveAddr(in.args[0], 0);
            ValueId root = res.base;
            i64 off = res.offset;
            if (res.stride) {
                u64& known = out.pointerStride[root];
                if (!known || res.stride < known) known = res.stride;
            }
            const ir::Inst& rootIn = f.inst(root);
            // Only roots that behave like an object pointer are interesting.
            if (rootIn.op == Op::GlobalAddr || rootIn.op == Op::FrameAddr) continue;
            ir::Type vt = in.op == Op::Load ? in.type : f.inst(in.args[1]).type;
            AccessRecord rec;
            rec.offset = off;
            rec.size = vt.bytes();
            rec.kind = vt.isFloat() ? Kind::Float : Kind::Int;
            rec.written = in.op == Op::Store;
            rec.count = 1;
            auto& list = out.pointerAccesses[root];
            bool merged = false;
            for (auto& e : list) {
                if (e.offset != rec.offset || e.size != rec.size) continue;
                e.count += 1;
                e.written = e.written || rec.written;
                if (e.kind == Kind::Unknown) e.kind = rec.kind;
                merged = true;
                break;
            }
            if (!merged) list.push_back(rec);
        }
    }
    for (auto& [root, list] : out.pointerAccesses)
        std::sort(list.begin(), list.end(), [](const AccessRecord& a, const AccessRecord& b) {
            return a.offset < b.offset;
        });
}

TypeRef TypeInference::resolve(const ValueFacts& fc, unsigned ptrBits) {
    if (fc.fixed) return fc.fixed;
    switch (fc.kind) {
    case Kind::Float:
        // Bit manipulation wins over a float guess: a value that is masked
        // and shifted is being used as the bits of one, not as one.
        if (fc.notFloat) return table_.integer(fc.bits ? fc.bits : ptrBits, false);
        return table_.floating(fc.bits == 32 ? 32 : 64);
    case Kind::Pointer: return table_.pointer(fc.pointee ? fc.pointee : table_.voidType());
    case Kind::Bool: return table_.boolType();
    case Kind::Int:
    case Kind::Unknown:
    default: {
        unsigned bits = fc.bits ? fc.bits : ptrBits;
        if (bits == 1) return table_.boolType();
        return table_.integer(bits, fc.signedVotes >= fc.unsignedVotes);
    }
    }
}

TypeResult TypeInference::run(ir::Function& f, const Signature& sig, const StackFrame& frame) {
    (void)frame;
    classIndex_.clear();
    parent_.clear();
    classFacts_.clear();
    unsigned ptrBits = prog_.pointerSize() * 8;

    seed(f, sig);
    propagate(f);

    TypeResult out;
    for (auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.type.isVoid()) continue;
            const ValueFacts& fc = classFacts_[classOf(v)];
            out.valueTypes[v] = resolve(fc, ptrBits);
            out.valueConfidence[v] = fc.confidence;
            if (fc.kind == Kind::Unknown) ++out.unknownValues;
        }
    }
    collectPointerAccesses(f, out);

    size_t total = out.valueTypes.size();
    double unknownRatio = total ? (double)out.unknownValues / (double)total : 0.0;
    out.overall = unknownRatio < 0.10 ? Confidence::High
                  : unknownRatio < 0.30 ? Confidence::Medium
                                        : Confidence::Low;
    return out;
}

} // namespace dc::types
