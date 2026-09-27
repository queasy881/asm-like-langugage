#include "ast/build.h"
#include "ast/named_constants.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <functional>
#include <map>
#include <set>
#include <string>

namespace dc::ast {

using ir::Op;
using ir::ValueId;
using ir::kNoValue;

namespace {

// A frame slot's name. A negative offset is a local; a positive one is in the
// caller's frame, which is where an argument spill area lives.
std::string frameSlotName(i64 off) {
    return off < 0 ? strfmt("local_%llx", (unsigned long long)(-off))
                   : strfmt("inframe_%llx", (unsigned long long)off);
}


BinOp binOpFor(Op op) {
    switch (op) {
    case Op::Add: return BinOp::Add;
    case Op::Sub: return BinOp::Sub;
    case Op::Mul: return BinOp::Mul;
    case Op::UDiv: case Op::SDiv: return BinOp::Div;
    case Op::URem: case Op::SRem: return BinOp::Mod;
    case Op::And: return BinOp::And;
    case Op::Or: return BinOp::Or;
    case Op::Xor: return BinOp::Xor;
    case Op::Shl: return BinOp::Shl;
    case Op::LShr: case Op::AShr: return BinOp::Shr;
    case Op::CmpEq: case Op::FCmpEq: return BinOp::Eq;
    case Op::CmpNe: case Op::FCmpNe: return BinOp::Ne;
    case Op::CmpUlt: case Op::CmpSlt: case Op::FCmpLt: return BinOp::Lt;
    case Op::CmpUle: case Op::CmpSle: case Op::FCmpLe: return BinOp::Le;
    case Op::CmpUgt: case Op::CmpSgt: case Op::FCmpGt: return BinOp::Gt;
    case Op::CmpUge: case Op::CmpSge: case Op::FCmpGe: return BinOp::Ge;
    case Op::FAdd: return BinOp::Add;
    case Op::FSub: return BinOp::Sub;
    case Op::FMul: return BinOp::Mul;
    case Op::FDiv: return BinOp::Div;
    default: return BinOp::Add;
    }
}

bool isUnsignedOp(Op op) {
    switch (op) {
    case Op::UDiv: case Op::URem: case Op::LShr:
    case Op::CmpUlt: case Op::CmpUle: case Op::CmpUgt: case Op::CmpUge:
        return true;
    default:
        return false;
    }
}

bool isSignedOp(Op op) {
    switch (op) {
    case Op::SDiv: case Op::SRem: case Op::AShr:
    case Op::CmpSlt: case Op::CmpSle: case Op::CmpSgt: case Op::CmpSge:
        return true;
    default:
        return false;
    }
}

class Builder : public structure::BlockEmitter {
public:
    explicit Builder(const BuildInputs& in) : in_(in), f_(*in.ir), vars_(*in.variables), types_(*in.types) {}

    std::unique_ptr<Function> build();

    // --- BlockEmitter ---
    std::vector<StmtPtr> statements(int block) override;
    ExprPtr condition(int block) override;
    ExprPtr switchValue(int block) override;
    ExprPtr returnValue(int block) override;
    std::vector<StmtPtr> edgeCopies(int from, int to) override;
    std::string labelFor(int block) override {
        return strfmt("label_%llx", (unsigned long long)f_.block(block).addr);
    }

private:
    types::TypeRef typeOf(ValueId v);
    types::TypeRef irToC(ir::Type t, bool isSigned = true);
    ExprPtr build(ValueId v);
    ExprPtr buildInst(const ir::Inst& in);
    ExprPtr buildObject(ValueId addr, ir::Type accessType);  // the lvalue a load/store names
    ExprPtr castTo(ExprPtr e, types::TypeRef target);
    ExprPtr varRef(const Variable& var);
    bool sameCType(types::TypeRef a, types::TypeRef b);
    std::string globalName(u64 addr);

    const BuildInputs& in_;
    ir::Function& f_;
    const VariableMap& vars_;
    const types::TypeResult& types_;
    std::set<int> declaredInline_;
    std::vector<StmtPtr> topDeclarations_;
    std::set<int> needsTopDeclaration_;
    int nextSwapTemp_ = 1;
    std::vector<std::pair<std::string, types::TypeRef>> cycleTemporaries_;
    std::map<size_t, std::string> replacedSource_;
};

types::TypeRef Builder::irToC(ir::Type t, bool isSigned) {
    types::TypeTable& tt = *in_.typeTable;
    switch (t.kind) {
    case ir::TypeKind::Void: return tt.voidType();
    case ir::TypeKind::Float: return tt.floating(t.bits);
    case ir::TypeKind::Ptr: return tt.pointer(tt.voidType());
    default: break;
    }
    if (t.bits == 1) return tt.boolType();
    return tt.integer(t.bits, isSigned);
}

types::TypeRef Builder::typeOf(ValueId v) {
    if (types::TypeRef t = types_.of(v)) return t;
    return irToC(f_.inst(v).type);
}

bool Builder::sameCType(types::TypeRef a, types::TypeRef b) {
    if (a == b) return true;
    if (!a || !b) return false;
    if (a->kind != b->kind) return false;
    if (a->kind == types::Kind::Pointer) return a->pointee == b->pointee;
    return a->bits == b->bits && a->isSigned == b->isSigned;
}

ExprPtr Builder::castTo(ExprPtr e, types::TypeRef target) {
    if (!e || !target) return e;
    if (sameCType(e->type, target)) return e;
    // A constant just takes the type; no cast is printed for it.
    if (e->kind == ExprKind::IntConst && target->isInteger()) {
        e->type = target;
        return e;
    }
    return Expr::cast(target, std::move(e));
}

std::string Builder::globalName(u64 addr) {
    if (in_.prog) {
        if (auto s = in_.prog->symbolName(addr)) return *s;
        if (const dc::Function* fn = in_.prog->functionAt(addr)) return fn->name;
    }
    return strfmt("g_%llx", (unsigned long long)addr);
}

ExprPtr Builder::varRef(const Variable& var) {
    return Expr::var(var.type ? var.type : in_.typeTable->unknown(), var.id, var.name);
}

ExprPtr Builder::build(ValueId v) {
    if (v == kNoValue) return Expr::undefined(in_.typeTable->unknown());
    if (const Variable* var = vars_.forValue(v)) {
        if (!vars_.isInlined(v)) return varRef(*var);
    }
    return buildInst(f_.inst(v));
}

// Turns the address of a load or store into the object it names.
ExprPtr Builder::buildObject(ValueId addrVal, ir::Type accessType) {
    types::TypeTable& tt = *in_.typeTable;
    types::TypeRef accessC = irToC(accessType);
    const ir::Inst& a = f_.inst(addrVal);
    // Indexing or dereferencing needs a pointer to the element; anything else
    // has to say what it is being read as.
    auto asPointerTo = [&](ExprPtr e, types::TypeRef elem) {
        types::TypeRef want = tt.pointer(elem);
        if (e->type && e->type->isPointer() && e->type->pointee == elem) return e;
        return Expr::cast(want, std::move(e));
    };

    // base + constant, where base points at a structure.
    auto tryMember = [&](ValueId base, i64 offset) -> ExprPtr {
        types::TypeRef bt = types_.of(base);
        if (!bt || !bt->isPointer() || !bt->pointee || !bt->pointee->isStruct()) return nullptr;
        for (const auto& fl : bt->pointee->fields) {
            if ((i64)fl.offset != offset) continue;
            if (fl.size != accessType.bytes()) continue;
            ExprPtr obj = build(base);
            // &x[i] followed by a field is x[i].field, not (&x[i])->field.
            if (obj->kind == ExprKind::AddrOf && obj->args[0]->kind == ExprKind::Index)
                return Expr::member(fl.type, std::move(obj->args[0]), fl.name, false, fl.offset);
            return Expr::member(fl.type, std::move(obj), fl.name, true, fl.offset);
        }
        return nullptr;
    };

    if (a.op == Op::Add && a.args.size() == 2) {
        const ir::Inst& rhs = f_.inst(a.args[1]);
        if (rhs.op == Op::Const) {
            i64 off = signExtend(rhs.imm, rhs.type.bits);
            if (ExprPtr m = tryMember(a.args[0], off)) return m;
            // base[i] when the offset is a multiple of the element size.
            types::TypeRef bt = types_.of(a.args[0]);
            if (bt && bt->isPointer() && bt->pointee && bt->pointee->sizeInBytes() == accessType.bytes() &&
                accessType.bytes() && off % (i64)accessType.bytes() == 0) {
                types::TypeRef elem = bt->pointee;
                return Expr::index(elem, asPointerTo(build(a.args[0]), elem),
                                   Expr::intConst(tt.integer(32, true), (u64)(off / (i64)accessType.bytes())));
            }
        }
        // base + index * size
        const ir::Inst& lhs = f_.inst(a.args[0]);
        auto scaledIndex = [&](const ir::Inst& m, ValueId& idx) -> bool {
            if (m.op != Op::Mul || m.args.size() != 2) return false;
            const ir::Inst& k = f_.inst(m.args[1]);
            if (k.op != Op::Const || k.imm != accessType.bytes() || !accessType.bytes()) return false;
            idx = m.args[0];
            return true;
        };
        ValueId idx = kNoValue;
        if (scaledIndex(rhs, idx))
            return Expr::index(accessC, asPointerTo(build(a.args[0]), accessC), build(idx));
        if (scaledIndex(lhs, idx))
            return Expr::index(accessC, asPointerTo(build(a.args[1]), accessC), build(idx));
        // Byte arrays need no scale, so the index is the addend itself.
        if (accessType.bytes() == 1) {
            for (int side = 0; side < 2; ++side) {
                types::TypeRef bt = types_.of(a.args[side]);
                if (!bt || !bt->isPointer() || !bt->pointee) continue;
                if (bt->pointee->sizeInBytes() != 1) continue;
                types::TypeRef ot = types_.of(a.args[1 - side]);
                if (ot && ot->isPointer()) continue;
                return Expr::index(bt->pointee, asPointerTo(build(a.args[side]), bt->pointee),
                                   build(a.args[1 - side]));
            }
        }
    }
    if (ExprPtr m = tryMember(addrVal, 0)) return m;

    if (a.op == Op::FrameAddr) {
        // A local's address dereferenced is just the local.
        return Expr::raw(accessC, frameSlotName((i64)a.imm));
    }
    if (a.op == Op::GlobalAddr) {
        return Expr::global(accessC, a.imm, globalName(a.imm));
    }
    // Anything else is a plain dereference. When the pointer already points at
    // something of the right width, its own element type is used, so no cast
    // is printed for what the reader can already see.
    ExprPtr base = build(addrVal);
    types::TypeRef elem = accessC;
    if (base->type && base->type->isPointer() && base->type->pointee &&
        base->type->pointee->sizeInBytes() == accessType.bytes() &&
        base->type->pointee->isFloat() == accessC->isFloat())
        elem = base->type->pointee;
    types::TypeRef want = in_.typeTable->pointer(elem);
    if (!sameCType(base->type, want)) base = Expr::cast(want, std::move(base));
    return Expr::deref(elem, std::move(base));
}

ExprPtr Builder::buildInst(const ir::Inst& in) {
    types::TypeTable& tt = *in_.typeTable;
    types::TypeRef t = in.type.isVoid() ? tt.voidType() : typeOf(in.id);

    switch (in.op) {
    case Op::Const: {
        if (t && t->isFloat()) {
            if (in.type.bits == 32) {
                float fv;
                u32 b = (u32)in.imm;
                std::memcpy(&fv, &b, 4);
                return Expr::floatConst(t, (double)fv);
            }
            double dv;
            u64 b = in.imm;
            std::memcpy(&dv, &b, 8);
            return Expr::floatConst(t, dv);
        }
        auto e = Expr::intConst(t, in.imm, t && t->isSigned);
        if (const char* n = namedConstant(in.imm, in.type.bits)) e->constName = n;
        return e;
    }
    case Op::Undef: return Expr::undefined(t);
    case Op::Arg: {
        if (const Variable* var = vars_.forValue(in.id)) return varRef(*var);
        return Expr::var(t, -1, strfmt("arg%u", in.aux + 1));
    }
    case Op::EntryValue:
        return Expr::raw(t, strfmt("/* incoming %s */ 0", in.loc.str().c_str()));
    case Op::GlobalAddr: {
        if (in_.data) {
            if (const winapi::FoundString* s = in_.data->stringAtAddress(in.imm))
                return Expr::stringLit(tt.pointer(tt.integer(8, true)), s->text,
                                       s->kind == winapi::StringKind::Utf16);
        }
        if (in_.prog && in_.prog->image().isExecutableVa(in.imm))
            return Expr::func(t, in.imm, globalName(in.imm));
        return Expr::addrOf(t, Expr::global(tt.unknown(), in.imm, globalName(in.imm)));
    }
    case Op::FrameAddr:
        return Expr::addrOf(t, Expr::raw(tt.unknown(), frameSlotName((i64)in.imm)));
    case Op::Load: {
        ExprPtr e = buildObject(in.args[0], in.type);
        // What was loaded may be known to be a pointer even though the access
        // itself only says how wide it was. Saying so here keeps the uses -
        // indexing, field access - valid C.
        if (t && t->isPointer() && e->type && !e->type->isPointer() && !e->type->isStruct())
            e = Expr::cast(t, std::move(e));
        return e;
    }
    case Op::Select:
        return Expr::ternary(t, build(in.args[0]), build(in.args[1]), build(in.args[2]));
    case Op::Not:
        if (in.type.bits == 1) return Expr::unary(t, UnOp::LogicalNot, build(in.args[0]));
        return Expr::unary(t, UnOp::Not, build(in.args[0]));
    case Op::Neg: case Op::FNeg: return Expr::unary(t, UnOp::Neg, build(in.args[0]));
    case Op::Trunc: case Op::ZExt: case Op::SExt: case Op::Bitcast:
    case Op::IntToPtr: case Op::PtrToInt: case Op::FPExt: case Op::FPTrunc:
    case Op::SIToFP: case Op::UIToFP: case Op::FPToSI: case Op::FPToUI: {
        ExprPtr inner = build(in.args[0]);
        return castTo(std::move(inner), t);
    }
    case Op::Call: {
        size_t first = in.aux ? 1 : 0;
        ExprPtr callee;
        if (in.aux) {
            callee = build(in.args[0]);
        } else if (in.call) {
            callee = Expr::func(tt.unknown(), in.call->target,
                                in.call->name.empty() ? globalName(in.call->target) : in.call->name);
        } else {
            callee = Expr::raw(tt.unknown(), "<indirect>");
        }
        std::vector<ExprPtr> args;
        for (size_t i = first; i < in.args.size(); ++i) args.push_back(build(in.args[i]));
        return Expr::call(t, std::move(callee), std::move(args));
    }
    case Op::Intrinsic: {
        std::vector<ExprPtr> args;
        // An instruction with no model at all is reported, not guessed at.
        // Spelling it as a call to a named placeholder keeps what it reads
        // visible and the surrounding code readable.
        if (in.text.rfind("asm(", 0) == 0) {
            std::string body = in.text.substr(5, in.text.size() >= 7 ? in.text.size() - 7 : 0);
            args.push_back(Expr::stringLit(in_.typeTable->pointer(in_.typeTable->integer(8, true)),
                                           body, false));
            for (ValueId a : in.args) args.push_back(build(a));
            return Expr::raw(t, "__unmodelled", std::move(args), true);
        }
        for (ValueId a : in.args) args.push_back(build(a));
        // An operation the machine has and C does not is always written as a
        // call, even when it takes nothing.
        return Expr::raw(t, in.text, std::move(args), true);
    }
    case Op::Phi:
        // Resolved into edge copies; a phi should never be read directly.
        if (const Variable* var = vars_.forValue(in.id)) return varRef(*var);
        return Expr::undefined(t);
    default:
        break;
    }

    if (ir::isComparison(in.op) && in.args.size() == 2) {
        ExprPtr a = build(in.args[0]);
        ExprPtr b = build(in.args[1]);
        // Make the signedness of the comparison visible where it matters.
        if (!f_.inst(in.args[0]).type.isFloat()) {
            types::TypeRef at = a->type;
            bool wantUnsigned = isUnsignedOp(in.op);
            bool wantSigned = isSignedOp(in.op);
            if (at && at->isInteger() && at->bits > 1) {
                if (wantUnsigned && at->isSigned) {
                    types::TypeRef u = in_.typeTable->integer(at->bits, false);
                    a = Expr::cast(u, std::move(a));
                    b = castTo(std::move(b), u);
                } else if (wantSigned && !at->isSigned) {
                    types::TypeRef s = in_.typeTable->integer(at->bits, true);
                    a = Expr::cast(s, std::move(a));
                    b = castTo(std::move(b), s);
                }
            }
        }
        return Expr::binary(in_.typeTable->boolType(), binOpFor(in.op), std::move(a), std::move(b));
    }
    if (in.args.size() == 2) {
        // Bitwise operations on single-bit values are the logical operators.
        if (in.type.bits == 1 && (in.op == Op::And || in.op == Op::Or || in.op == Op::Xor)) {
            BinOp lop = in.op == Op::And ? BinOp::LogicalAnd
                                         : (in.op == Op::Or ? BinOp::LogicalOr : BinOp::Ne);
            return Expr::binary(in_.typeTable->boolType(), lop, build(in.args[0]), build(in.args[1]));
        }
        ExprPtr a = build(in.args[0]);
        ExprPtr b = build(in.args[1]);
        // A literal takes the type of what it is combined with, so a mask is
        // printed as the bit pattern it is rather than a negative number.
        if (b->kind == ExprKind::IntConst && a->type && a->type->isInteger() && b->constName.empty()) {
            b->type = a->type;
            b->isSignedConst = a->type->isSigned;
        } else if (a->kind == ExprKind::IntConst && b->type && b->type->isInteger() && a->constName.empty()) {
            a->type = b->type;
            a->isSignedConst = b->type->isSigned;
        }
        types::TypeRef at = a->type;
        if (at && at->isInteger() && at->bits > 1) {
            if (isUnsignedOp(in.op) && at->isSigned) {
                types::TypeRef u = in_.typeTable->integer(at->bits, false);
                a = Expr::cast(u, std::move(a));
                t = u;
            } else if (isSignedOp(in.op) && !at->isSigned) {
                types::TypeRef s = in_.typeTable->integer(at->bits, true);
                a = Expr::cast(s, std::move(a));
                t = s;
            }
        }
        // C only allows a pointer in an addition, a subtraction of two
        // compatible pointers, and a comparison. Anywhere else it has to be
        // read as the integer it is.
        {
            bool aPtr = a && a->type && a->type->isPointer();
            bool bPtr = b && b->type && b->type->isPointer();
            bool arith = in.op == Op::Add || in.op == Op::Sub;
            types::TypeRef intT = t && t->isInteger() ? t : in_.typeTable->integer(in.type.bits ? in.type.bits : 64, true);
            if (in.op == Op::Sub && aPtr && bPtr) {
                // A difference of pointers is only C if they agree; make them.
                if (a->type->pointee != b->type->pointee) {
                    types::TypeRef bytePtr = in_.typeTable->pointer(in_.typeTable->integer(8, false));
                    a = Expr::cast(bytePtr, std::move(a));
                    b = Expr::cast(bytePtr, std::move(b));
                }
            } else if (in.op == Op::Sub && bPtr && !aPtr) {
                b = Expr::cast(intT, std::move(b));
                t = intT;
            } else if (!arith && (aPtr || bPtr)) {
                if (aPtr) a = Expr::cast(intT, std::move(a));
                if (bPtr) b = Expr::cast(intT, std::move(b));
                t = intT;
            }
        }
        // Pointer arithmetic reads better with the pointer first.
        if (in.op == Op::Add && b && a && b->type && a->type && b->type->isPointer() &&
            !a->type->isPointer()) {
            std::swap(a, b);
            t = a->type;
        }
        // base + index * sizeof(element) is the address of an element.
        if (in.op == Op::Add && a && a->type && a->type->isPointer() && a->type->pointee) {
            unsigned esz = a->type->pointee->sizeInBytes();
            const ir::Inst& other = f_.inst(in.args[0] == kNoValue ? in.args[1] : in.args[1]);
            ValueId scaledValue = kNoValue;
            for (size_t k = 0; k < in.args.size(); ++k) {
                const ir::Inst& cand = f_.inst(in.args[k]);
                if (cand.op != Op::Mul || cand.args.size() != 2) continue;
                const ir::Inst& mulBy = f_.inst(cand.args[1]);
                if (mulBy.op == Op::Const && esz && mulBy.imm == esz) scaledValue = cand.args[0];
            }
            (void)other;
            if (scaledValue != kNoValue && esz > 1) {
                // Read the types out first: the pointer is about to be moved.
                types::TypeRef ptrType = a->type;
                types::TypeRef elemType = a->type->pointee;
                ExprPtr idx = build(scaledValue);
                return Expr::addrOf(ptrType, Expr::index(elemType, std::move(a), std::move(idx)));
            }
        }
        // The IR counts in bytes. Adding to a pointer whose element is larger
        // would scale in C, so the pointer is viewed as bytes for the sum.
        if ((in.op == Op::Add || in.op == Op::Sub) && a && a->type && a->type->isPointer() &&
            b && b->type && !b->type->isPointer()) {
            types::TypeRef elem = a->type->pointee;
            unsigned esz = elem ? elem->sizeInBytes() : 1;
            if (esz > 1 || !elem || elem->kind == types::Kind::Void) {
                types::TypeRef bytePtr = in_.typeTable->pointer(in_.typeTable->integer(8, false));
                a = Expr::cast(bytePtr, std::move(a));
                t = bytePtr;
            }
        }
        if (in.op == Op::Rol || in.op == Op::Ror) {
            std::vector<ExprPtr> args;
            unsigned bits = in.type.bits;
            args.push_back(std::move(a));
            args.push_back(std::move(b));
            const char* name = in.op == Op::Rol ? (bits > 32 ? "_rotl64" : "_rotl")
                                                : (bits > 32 ? "_rotr64" : "_rotr");
            return Expr::raw(t, name, std::move(args));
        }
        if (in.op == Op::MulHiU || in.op == Op::MulHiS) {
            std::vector<ExprPtr> args;
            args.push_back(std::move(a));
            args.push_back(std::move(b));
            return Expr::raw(t, in.op == Op::MulHiU ? "__umulh" : "__mulh", std::move(args), true);
        }
        return Expr::binary(t, binOpFor(in.op), std::move(a), std::move(b));
    }
    if (in.args.size() == 1) {
        std::vector<ExprPtr> args;
        args.push_back(build(in.args[0]));
        return Expr::raw(t, ir::opName(in.op), std::move(args), true);
    }
    return Expr::undefined(t);
}

std::vector<StmtPtr> Builder::statements(int block) {
    std::vector<StmtPtr> out;
    for (ValueId v : f_.block(block).insts) {
        const ir::Inst& in = f_.inst(v);
        if (in.isTerminator() || in.op == Op::Phi) continue;
        if (in.op == Op::Store) {
            ExprPtr lhs = buildObject(in.args[0], f_.inst(in.args[1]).type);
            ExprPtr rhs = castTo(build(in.args[1]), lhs->type);
            auto s = Stmt::assign(std::move(lhs), std::move(rhs));
            s->address = in.addr;
            out.push_back(std::move(s));
            continue;
        }
        if (in.op == Op::Arg || in.op == Op::Phi) continue; // parameters and phis are not statements
        if (vars_.isInlined(v)) continue;
        const Variable* var = vars_.forValue(v);
        if (!var) {
            // A value with no variable and no users: keep it only if it does
            // something, such as a call whose result is discarded.
            if (in.op == Op::Call || (in.op == Op::Intrinsic && in.aux)) {
                auto s = Stmt::exprStmt(buildInst(in));
                s->address = in.addr;
                out.push_back(std::move(s));
            }
            continue;
        }
        ExprPtr value = castTo(buildInst(in), var->type);
        StmtPtr s;
        // Whether a variable is declared where it is assigned is decided once,
        // before structuring, because the structurer emits blocks twice.
        if (declaredInline_.count(var->id)) {
            s = Stmt::decl(var->id, var->type, var->name, std::move(value), true);
        } else {
            s = Stmt::assign(varRef(*var), std::move(value));
        }
        s->address = in.addr;
        out.push_back(std::move(s));
    }
    return out;
}

ExprPtr Builder::condition(int block) {
    const ir::Block& b = f_.block(block);
    const ir::Inst& term = f_.inst(b.insts.back());
    if (term.op != Op::Branch || term.args.empty()) return Expr::intConst(in_.typeTable->boolType(), 1);
    return build(term.args[0]);
}

ExprPtr Builder::switchValue(int block) {
    const ir::Block& b = f_.block(block);
    const ir::Inst& term = f_.inst(b.insts.back());
    if (term.op != Op::Switch || term.args.empty()) return Expr::undefined(in_.typeTable->unknown());
    return build(term.args[0]);
}

ExprPtr Builder::returnValue(int block) {
    const ir::Block& b = f_.block(block);
    const ir::Inst& term = f_.inst(b.insts.back());
    if (term.op != Op::Return || term.args.empty()) return nullptr;
    types::TypeRef rt = in_.signature ? nullptr : nullptr;
    (void)rt;
    return build(term.args[0]);
}

std::vector<StmtPtr> Builder::edgeCopies(int from, int to) {
    std::vector<StmtPtr> out;
    if (to < 0 || to >= f_.blockCount()) return out;
    const ir::Block& tb = f_.block(to);
    auto it = std::find(tb.preds.begin(), tb.preds.end(), from);
    if (it == tb.preds.end()) return out;
    size_t slot = (size_t)(it - tb.preds.begin());

    // The phis of a block all read their arguments at once, so these copies
    // are a parallel assignment. Writing them in source order is wrong
    // whenever one copy's destination is another's source - the classic case
    // being a loop that rotates two variables. They are ordered here, and a
    // genuine cycle is broken with a temporary.
    struct Copy {
        int dstVar = -1;
        ValueId src = ir::kNoValue;
        int srcVar = -1;     // -1 when the source is an expression, not a variable
        types::TypeRef type = nullptr;
        std::string dstName;
    };
    std::vector<Copy> copies;
    for (ValueId v : tb.insts) {
        const ir::Inst& in = f_.inst(v);
        if (in.op != Op::Phi) break;
        if (slot >= in.args.size()) continue;
        ValueId src = in.args[slot];
        const Variable* dst = vars_.forValue(v);
        if (!dst) continue;
        const Variable* srcVar = vars_.forValue(src);
        if (srcVar && srcVar->id == dst->id) continue; // coalesced: nothing to do
        Copy c;
        c.dstVar = dst->id;
        c.src = src;
        c.srcVar = srcVar ? srcVar->id : -1;
        c.type = dst->type;
        c.dstName = dst->name;
        copies.push_back(std::move(c));
    }
    if (copies.empty()) return out;

    // A copy must be written before anything that overwrites what it reads.
    // An expression source may read several variables, so collect them all.
    auto sourcesOf = [&](const Copy& c) {
        std::set<int> srcs;
        if (c.srcVar >= 0) {
            srcs.insert(c.srcVar);
            return srcs;
        }
        std::function<void(ValueId, int)> walk = [&](ValueId v, int depth) {
            if (depth > 32) return;
            if (const Variable* var = vars_.forValue(v)) {
                if (!vars_.isInlined(v)) {
                    srcs.insert(var->id);
                    return;
                }
            }
            for (ValueId a : f_.inst(v).args)
                if (a != kNoValue) walk(a, depth + 1);
        };
        walk(c.src, 0);
        return srcs;
    };

    size_t n = copies.size();
    std::vector<std::set<int>> srcSets(n);
    for (size_t i = 0; i < n; ++i) srcSets[i] = sourcesOf(copies[i]);

    std::vector<bool> done(n, false);
    size_t emitted = 0;
    while (emitted < n) {
        bool progress = false;
        for (size_t i = 0; i < n; ++i) {
            if (done[i]) continue;
            // Safe once nothing still to be written reads this destination.
            bool blocked = false;
            for (size_t k = 0; k < n; ++k) {
                if (k == i || done[k]) continue;
                if (srcSets[k].count(copies[i].dstVar)) { blocked = true; break; }
            }
            if (blocked) continue;
            out.push_back(Stmt::assign(Expr::var(copies[i].type, copies[i].dstVar, copies[i].dstName),
                                       castTo(build(copies[i].src), copies[i].type)));
            done[i] = true;
            ++emitted;
            progress = true;
        }
        if (progress) continue;
        // Everything left is part of a cycle: save one value aside and retry.
        for (size_t i = 0; i < n; ++i) {
            if (done[i]) continue;
            std::string tmp = strfmt("swap_%d", nextSwapTemp_++);
            cycleTemporaries_.push_back({tmp, copies[i].type});
            out.push_back(Stmt::assign(Expr::var(copies[i].type, -1, tmp),
                                       Expr::var(copies[i].type, copies[i].dstVar, copies[i].dstName)));
            // Anything reading that destination now reads the saved copy.
            for (size_t k = 0; k < n; ++k) {
                if (done[k] || k == i) continue;
                if (!srcSets[k].count(copies[i].dstVar)) continue;
                if (copies[k].srcVar == copies[i].dstVar) {
                    copies[k].srcVar = -2; // resolved through the temporary
                    copies[k].src = kNoValue;
                    copies[k].dstName = copies[k].dstName; // unchanged
                    replacedSource_[k] = tmp;
                }
            }
            out.push_back(Stmt::assign(Expr::var(copies[i].type, copies[i].dstVar, copies[i].dstName),
                                       castTo(build(copies[i].src), copies[i].type)));
            done[i] = true;
            ++emitted;
            for (size_t k = 0; k < n; ++k) {
                if (done[k] || !replacedSource_.count(k)) continue;
                out.push_back(Stmt::assign(Expr::var(copies[k].type, copies[k].dstVar, copies[k].dstName),
                                           Expr::var(copies[k].type, -1, replacedSource_[k])));
                done[k] = true;
                ++emitted;
            }
            replacedSource_.clear();
            break;
        }
    }
    return out;
}

namespace {

bool sameLValue(const Expr* a, const Expr* b) {
    if (!a || !b) return false;
    if (a->kind != b->kind) return false;
    if (a->kind == ExprKind::VarRef) return a->varId == b->varId && a->varId >= 0;
    return false;
}

// Rewrites that only make the text read better; none of them change what the
// code does.
void tidy(Stmt& s) {
    for (auto& c : s.body) if (c) tidy(*c);
    if (s.thenBranch) tidy(*s.thenBranch);
    if (s.elseBranch) tidy(*s.elseBranch);
    if (s.loopBody) tidy(*s.loopBody);
    for (auto& c : s.cases) if (c.body) tidy(*c.body);
    if (s.kind != StmtKind::Compound) return;

    auto& list = s.body;
    // Splice a nested compound into its parent. Braces here carry no meaning
    // of their own, and flattening lets the rewrites below see the whole
    // sequence.
    for (size_t i = 0; i < list.size();) {
        if (list[i] && list[i]->kind == StmtKind::Compound) {
            std::vector<StmtPtr> inner = std::move(list[i]->body);
            list.erase(list.begin() + i);
            list.insert(list.begin() + i, std::make_move_iterator(inner.begin()),
                        std::make_move_iterator(inner.end()));
            continue;
        }
        ++i;
    }
    // Drop "x = x;" and empty statements.
    for (auto it = list.begin(); it != list.end();) {
        Stmt* st = it->get();
        bool drop = !st || st->isEmpty();
        if (!drop && st->kind == StmtKind::Assign && sameLValue(st->lhs.get(), st->rhs.get())) drop = true;
        it = drop ? list.erase(it) : it + 1;
    }
    // "x = expr; return x;" is just "return expr;" - nothing can observe x
    // afterwards, because control leaves the function.
    for (size_t i = 0; i + 1 < list.size();) {
        Stmt* a = list[i].get();
        Stmt* b = list[i + 1].get();
        if (a->kind == StmtKind::Assign && b->kind == StmtKind::Return && b->expr &&
            sameLValue(a->lhs.get(), b->expr.get())) {
            b->expr = std::move(a->rhs);
            list.erase(list.begin() + i);
            continue;
        }
        if (a->kind == StmtKind::Decl && a->declInit && b->kind == StmtKind::Return && b->expr &&
            b->expr->kind == ExprKind::VarRef && b->expr->varId == a->varId && a->varId >= 0) {
            b->expr = std::move(a->declInit);
            list.erase(list.begin() + i);
            continue;
        }
        ++i;
    }
    // Flatten a compound that holds a single compound.
    for (auto& c : list) {
        while (c && c->kind == StmtKind::Compound && c->body.size() == 1 &&
               c->body[0]->kind == StmtKind::Compound)
            c = std::move(c->body[0]);
    }
}

// Removes assignments whose destination is never read. Member and index
// resolution rebuilds an address from the IR, which can leave the variable
// that held it with no readers at all.
void removeUnreadAssignments(Function& fn) {
    for (int pass = 0; pass < 4; ++pass) {
        std::set<int> read;
        std::function<void(const Expr*)> scanExpr = [&](const Expr* e) {
            if (!e) return;
            if (e->kind == ExprKind::VarRef && e->varId >= 0) read.insert(e->varId);
            for (const auto& a : e->args) scanExpr(a.get());
        };
        std::function<void(const Stmt&)> scan = [&](const Stmt& st) {
            if (st.kind == StmtKind::Assign) {
                // The destination itself is not a read, but an index or a
                // member on the left reads whatever it is built from.
                if (st.lhs && st.lhs->kind != ExprKind::VarRef) scanExpr(st.lhs.get());
                scanExpr(st.rhs.get());
            } else {
                scanExpr(st.lhs.get());
                scanExpr(st.rhs.get());
            }
            scanExpr(st.expr.get());
            scanExpr(st.declInit.get());
            for (const auto& c : st.body) scan(*c);
            if (st.thenBranch) scan(*st.thenBranch);
            if (st.elseBranch) scan(*st.elseBranch);
            if (st.loopBody) scan(*st.loopBody);
            if (st.init) scan(*st.init);
            if (st.step) scan(*st.step);
            for (const auto& c : st.cases)
                if (c.body) scan(*c.body);
        };
        if (fn.body) scan(*fn.body);

        bool hasSideEffect = false;
        std::function<bool(const Expr*)> effectful = [&](const Expr* e) -> bool {
            if (!e) return false;
            if (e->kind == ExprKind::Call) return true;
            if (e->kind == ExprKind::Raw && !e->args.empty()) return true;
            for (const auto& a : e->args)
                if (effectful(a.get())) return true;
            return false;
        };
        int removed = 0;
        std::function<void(Stmt&)> prune = [&](Stmt& st) {
            for (auto& c : st.body) if (c) prune(*c);
            if (st.thenBranch) prune(*st.thenBranch);
            if (st.elseBranch) prune(*st.elseBranch);
            if (st.loopBody) prune(*st.loopBody);
            if (st.init) prune(*st.init);
            if (st.step) prune(*st.step);
            for (auto& c : st.cases) if (c.body) prune(*c.body);
            if (st.kind != StmtKind::Compound) return;
            for (auto it = st.body.begin(); it != st.body.end();) {
                Stmt* s2 = it->get();
                bool drop = false;
                if (s2->kind == StmtKind::Assign && s2->lhs && s2->lhs->kind == ExprKind::VarRef &&
                    s2->lhs->varId >= 0 && !read.count(s2->lhs->varId) && !effectful(s2->rhs.get()))
                    drop = true;
                if (s2->kind == StmtKind::Decl && s2->varId >= 0 && !read.count(s2->varId) &&
                    !effectful(s2->declInit.get()))
                    drop = true;
                if (drop) {
                    it = st.body.erase(it);
                    ++removed;
                } else {
                    ++it;
                }
            }
        };
        (void)hasSideEffect;
        if (fn.body) prune(*fn.body);
        if (!removed) break;
    }
}

} // namespace

std::unique_ptr<Function> Builder::build() {
    auto fn = std::make_unique<Function>();
    fn->name = f_.name();
    fn->address = f_.entryAddr();
    fn->confidence = in_.confidence;
    fn->notes = in_.notes;
    for (const auto& n : f_.notes()) fn->notes.push_back(n);

    // Parameters.
    for (size_t i = 0; i < f_.params().size(); ++i) {
        const auto& p = f_.params()[i];
        Param ap;
        ap.name = p.name.empty() ? strfmt("arg%zu", i + 1) : p.name;
        ap.used = p.used;
        ap.type = nullptr;
        if (p.value != kNoValue) ap.type = types_.of(p.value);
        if (!ap.type) ap.type = irToC(p.type);
        fn->params.push_back(std::move(ap));
    }
    fn->returnType = in_.typeTable->voidType();
    if (!f_.returnType().isVoid()) {
        // The return type is whatever the returned values agree on.
        types::TypeRef rt = nullptr;
        for (const auto& b : f_.blocks()) {
            if (b.insts.empty()) continue;
            const ir::Inst& term = f_.inst(b.insts.back());
            if (term.op != Op::Return || term.args.empty()) continue;
            types::TypeRef t = types_.of(term.args[0]);
            if (!rt) rt = t;
        }
        fn->returnType = rt ? rt : irToC(f_.returnType());
    }
    fn->variadic = f_.variadic();

    // A variable may only be declared where it is assigned when that is its
    // single assignment and every use is in the same block; otherwise the
    // declaration would not be in scope where it is read. A variable a phi
    // writes is assigned on an edge, never by a statement, so it always needs
    // a declaration of its own.
    auto uses = f_.buildUses();
    for (const auto& var : vars_.variables) {
        if (var.isParam || var.values.empty()) continue;
        bool writtenByPhi = false;
        for (ValueId v : var.values)
            if (f_.inst(v).op == Op::Phi) writtenByPhi = true;
        bool localToOneBlock = var.values.size() == 1 && !writtenByPhi;
        if (localToOneBlock) {
            int defBlock = f_.inst(var.values[0]).block;
            auto it = uses.find(var.values[0]);
            if (it != uses.end())
                for (ValueId u : it->second)
                    if (f_.inst(u).block != defBlock) localToOneBlock = false;
        }
        if (localToOneBlock && var.singleAssignment) declaredInline_.insert(var.id);
        else needsTopDeclaration_.insert(var.id);
    }

    auto result = structure::structureFunction(f_, *this, {});
    fn->gotoCount = result.gotoCount;
    for (const auto& n : result.notes) fn->notes.push_back(n);

    for (const auto& var : vars_.variables) {
        if (!needsTopDeclaration_.count(var.id)) continue;
        fn->declarations.push_back(Stmt::decl(var.id, var.type, var.name, nullptr, false));
    }
    // Locals that stayed in memory need declaring too, and so does every other
    // frame slot the code still names.
    {
        std::set<i64> referenced;
        for (const auto& b : f_.blocks())
            for (ValueId v : b.insts)
                if (f_.inst(v).op == Op::FrameAddr) referenced.insert((i64)f_.inst(v).imm);
        std::set<std::string> declared;
        for (const auto& d : fn->declarations) declared.insert(d->declName);
        if (in_.frame) {
            for (const auto& slot : in_.frame->slots) {
                if (slot.promoted || slot.kind != SlotKind::Local) continue;
                if (!referenced.count(slot.offset)) continue;
                types::TypeRef t = in_.typeTable->integer(std::max(8u, slot.size * 8), true);
                if (slot.size > 8) t = in_.typeTable->array(in_.typeTable->integer(8, false), slot.size);
                std::string name = frameSlotName(slot.offset);
                if (!declared.insert(name).second) continue;
                fn->declarations.push_back(Stmt::decl(-1, t, name, nullptr, false));
                referenced.erase(slot.offset);
            }
        }
        for (i64 off : referenced) {
            std::string name = frameSlotName(off);
            if (!declared.insert(name).second) continue;
            fn->declarations.push_back(
                Stmt::decl(-1, in_.typeTable->integer(64, true), name, nullptr, false));
        }
    }
    fn->body = std::move(result.body);
    for (const auto& [name, type] : cycleTemporaries_) {
        bool already = false;
        for (const auto& d : fn->declarations)
            if (d->declName == name) already = true;
        if (!already) fn->declarations.push_back(Stmt::decl(-1, type, name, nullptr, false));
    }
    if (fn->body) tidy(*fn->body);
    removeUnreadAssignments(*fn);
    // A variable that every assignment just fused away needs no declaration.
    std::set<int> stillUsed;
    std::function<void(const Stmt&)> scanStmt = [&](const Stmt& st) {
        std::function<void(const Expr*)> scanExpr = [&](const Expr* e) {
            if (!e) return;
            if (e->kind == ExprKind::VarRef && e->varId >= 0) stillUsed.insert(e->varId);
            for (const auto& a : e->args) scanExpr(a.get());
        };
        scanExpr(st.expr.get());
        scanExpr(st.lhs.get());
        scanExpr(st.rhs.get());
        scanExpr(st.declInit.get());
        if (st.kind == StmtKind::Decl && st.varId >= 0 && st.declInit) stillUsed.insert(st.varId);
        for (const auto& c : st.body) scanStmt(*c);
        if (st.thenBranch) scanStmt(*st.thenBranch);
        if (st.elseBranch) scanStmt(*st.elseBranch);
        if (st.loopBody) scanStmt(*st.loopBody);
        if (st.init) scanStmt(*st.init);
        if (st.step) scanStmt(*st.step);
        for (const auto& c : st.cases)
            if (c.body) scanStmt(*c.body);
    };
    if (fn->body) scanStmt(*fn->body);
    fn->declarations.erase(
        std::remove_if(fn->declarations.begin(), fn->declarations.end(),
                       [&](const StmtPtr& d) { return d->varId >= 0 && !stillUsed.count(d->varId); }),
        fn->declarations.end());
    return fn;
}

} // namespace

std::unique_ptr<Function> buildFunction(const BuildInputs& in) {
    Builder b(in);
    return b.build();
}

} // namespace dc::ast
