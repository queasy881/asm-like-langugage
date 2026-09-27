#include "ir/ir.h"

#include <algorithm>
#include <sstream>

namespace dc::ir {

std::string Type::str() const {
    switch (kind) {
    case TypeKind::Void: return "void";
    case TypeKind::Int: return bits == 1 ? "i1" : strfmt("i%u", bits);
    case TypeKind::Float: return strfmt("f%u", bits);
    case TypeKind::Ptr: return strfmt("p%u", bits);
    }
    return "?";
}

namespace {
struct OpDesc {
    const char* name;
    bool terminator;
    bool commutative;
    bool comparison;
    bool floating;
    bool cast;
    bool sideEffects;
};

const OpDesc kOps[] = {
    {"const", 0, 0, 0, 0, 0, 0}, {"undef", 0, 0, 0, 0, 0, 0}, {"arg", 0, 0, 0, 0, 0, 0},
    {"entryvalue", 0, 0, 0, 0, 0, 0},
    {"globaladdr", 0, 0, 0, 0, 0, 0}, {"frameaddr", 0, 0, 0, 0, 0, 0}, {"phi", 0, 0, 0, 0, 0, 0},
    {"readloc", 0, 0, 0, 0, 0, 0}, {"writeloc", 0, 0, 0, 0, 0, 1},
    {"add", 0, 1, 0, 0, 0, 0}, {"sub", 0, 0, 0, 0, 0, 0}, {"mul", 0, 1, 0, 0, 0, 0},
    {"udiv", 0, 0, 0, 0, 0, 0}, {"sdiv", 0, 0, 0, 0, 0, 0}, {"urem", 0, 0, 0, 0, 0, 0}, {"srem", 0, 0, 0, 0, 0, 0},
    {"and", 0, 1, 0, 0, 0, 0}, {"or", 0, 1, 0, 0, 0, 0}, {"xor", 0, 1, 0, 0, 0, 0},
    {"shl", 0, 0, 0, 0, 0, 0}, {"lshr", 0, 0, 0, 0, 0, 0}, {"ashr", 0, 0, 0, 0, 0, 0},
    {"rol", 0, 0, 0, 0, 0, 0}, {"ror", 0, 0, 0, 0, 0, 0}, {"not", 0, 0, 0, 0, 0, 0}, {"neg", 0, 0, 0, 0, 0, 0},
    {"mulhiu", 0, 1, 0, 0, 0, 0}, {"mulhis", 0, 1, 0, 0, 0, 0},
    {"cmpeq", 0, 1, 1, 0, 0, 0}, {"cmpne", 0, 1, 1, 0, 0, 0},
    {"cmpult", 0, 0, 1, 0, 0, 0}, {"cmpule", 0, 0, 1, 0, 0, 0}, {"cmpugt", 0, 0, 1, 0, 0, 0}, {"cmpuge", 0, 0, 1, 0, 0, 0},
    {"cmpslt", 0, 0, 1, 0, 0, 0}, {"cmpsle", 0, 0, 1, 0, 0, 0}, {"cmpsgt", 0, 0, 1, 0, 0, 0}, {"cmpsge", 0, 0, 1, 0, 0, 0},
    {"trunc", 0, 0, 0, 0, 1, 0}, {"zext", 0, 0, 0, 0, 1, 0}, {"sext", 0, 0, 0, 0, 1, 0},
    {"bitcast", 0, 0, 0, 0, 1, 0}, {"inttoptr", 0, 0, 0, 0, 1, 0}, {"ptrtoint", 0, 0, 0, 0, 1, 0},
    {"fadd", 0, 1, 0, 1, 0, 0}, {"fsub", 0, 0, 0, 1, 0, 0}, {"fmul", 0, 1, 0, 1, 0, 0}, {"fdiv", 0, 0, 0, 1, 0, 0},
    {"fneg", 0, 0, 0, 1, 0, 0}, {"fabs", 0, 0, 0, 1, 0, 0}, {"fsqrt", 0, 0, 0, 1, 0, 0},
    {"fmin", 0, 0, 0, 1, 0, 0}, {"fmax", 0, 0, 0, 1, 0, 0},
    {"fcmpeq", 0, 1, 1, 1, 0, 0}, {"fcmpne", 0, 1, 1, 1, 0, 0}, {"fcmplt", 0, 0, 1, 1, 0, 0},
    {"fcmple", 0, 0, 1, 1, 0, 0}, {"fcmpgt", 0, 0, 1, 1, 0, 0}, {"fcmpge", 0, 0, 1, 1, 0, 0}, {"fcmpuno", 0, 1, 1, 1, 0, 0},
    {"sitofp", 0, 0, 0, 1, 1, 0}, {"uitofp", 0, 0, 0, 1, 1, 0}, {"fptosi", 0, 0, 0, 1, 1, 0}, {"fptoui", 0, 0, 0, 1, 1, 0},
    {"fpext", 0, 0, 0, 1, 1, 0}, {"fptrunc", 0, 0, 0, 1, 1, 0},
    {"load", 0, 0, 0, 0, 0, 0}, {"store", 0, 0, 0, 0, 0, 1},
    {"select", 0, 0, 0, 0, 0, 0},
    {"call", 0, 0, 0, 0, 0, 1}, {"intrinsic", 0, 0, 0, 0, 0, 1},
    {"jump", 1, 0, 0, 0, 0, 1}, {"branch", 1, 0, 0, 0, 0, 1}, {"switch", 1, 0, 0, 0, 0, 1},
    {"return", 1, 0, 0, 0, 0, 1}, {"unreachable", 1, 0, 0, 0, 0, 1},
};
static_assert(sizeof(kOps) / sizeof(kOps[0]) == (size_t)Op::Count, "op table out of sync");

const OpDesc& desc(Op op) { return kOps[(size_t)op]; }
} // namespace

const char* opName(Op op) { return desc(op).name; }
bool isTerminator(Op op) { return desc(op).terminator; }
bool isCommutative(Op op) { return desc(op).commutative; }
bool isComparison(Op op) { return desc(op).comparison; }
bool isFloatOp(Op op) { return desc(op).floating; }
bool isCast(Op op) { return desc(op).cast; }
bool hasSideEffects(Op op) { return desc(op).sideEffects; }

Op invertComparison(Op op) {
    switch (op) {
    case Op::CmpEq: return Op::CmpNe;
    case Op::CmpNe: return Op::CmpEq;
    case Op::CmpUlt: return Op::CmpUge;
    case Op::CmpUge: return Op::CmpUlt;
    case Op::CmpUgt: return Op::CmpUle;
    case Op::CmpUle: return Op::CmpUgt;
    case Op::CmpSlt: return Op::CmpSge;
    case Op::CmpSge: return Op::CmpSlt;
    case Op::CmpSgt: return Op::CmpSle;
    case Op::CmpSle: return Op::CmpSgt;
    case Op::FCmpEq: return Op::FCmpNe;
    case Op::FCmpNe: return Op::FCmpEq;
    default: return op;
    }
}

Op swapComparisonOperands(Op op) {
    switch (op) {
    case Op::CmpUlt: return Op::CmpUgt;
    case Op::CmpUgt: return Op::CmpUlt;
    case Op::CmpUle: return Op::CmpUge;
    case Op::CmpUge: return Op::CmpUle;
    case Op::CmpSlt: return Op::CmpSgt;
    case Op::CmpSgt: return Op::CmpSlt;
    case Op::CmpSle: return Op::CmpSge;
    case Op::CmpSge: return Op::CmpSle;
    case Op::FCmpLt: return Op::FCmpGt;
    case Op::FCmpGt: return Op::FCmpLt;
    case Op::FCmpLe: return Op::FCmpGe;
    case Op::FCmpGe: return Op::FCmpLe;
    default: return op; // eq/ne are symmetric
    }
}

const char* flagName(FlagBit f) {
    static const char* const names[] = {"cf", "pf", "af", "zf", "sf", "of", "df"};
    return f < FlagCount ? names[f] : "?";
}

std::string Loc::str() const {
    switch (kind) {
    case LocKind::None: return "<none>";
    case LocKind::Reg: return strfmt("reg%u.%u", index, size);
    case LocKind::Flag: return flagName((FlagBit)index);
    case LocKind::Stack: return strfmt("slot%u", index);
    case LocKind::Temp: return strfmt("t%u", index);
    }
    return "?";
}

std::string valueName(ValueId v) { return v == kNoValue ? "<none>" : strfmt("%%%u", v); }

int Function::addBlock(u64 addr) {
    Block b;
    b.id = (int)blocks_.size();
    b.addr = addr;
    blocks_.push_back(std::move(b));
    return blocks_.back().id;
}

ValueId Function::add(int block, Inst inst) {
    ValueId id = (ValueId)insts_.size();
    inst.id = id;
    inst.block = block;
    insts_.push_back(std::move(inst));
    blocks_[block].insts.push_back(id);
    return id;
}

ValueId Function::insertBefore(ValueId anchor, Inst inst) {
    int b = insts_[anchor].block;
    ValueId id = (ValueId)insts_.size();
    inst.id = id;
    inst.block = b;
    insts_.push_back(std::move(inst));
    auto& list = blocks_[b].insts;
    auto it = std::find(list.begin(), list.end(), anchor);
    list.insert(it, id);
    return id;
}

ValueId Function::constInt(int block, Type t, u64 value, u64 addr) {
    Inst in;
    in.op = Op::Const;
    in.type = t;
    in.imm = t.bits >= 64 ? value : truncBits(value, t.bits);
    in.addr = addr;
    return add(block, std::move(in));
}

ValueId Function::undef(int block, Type t) {
    Inst in;
    in.op = Op::Undef;
    in.type = t;
    return add(block, std::move(in));
}

ValueId Function::binary(int block, Op op, Type t, ValueId a, ValueId b, u64 addr) {
    Inst in;
    in.op = op;
    in.type = t;
    in.args = {a, b};
    in.addr = addr;
    return add(block, std::move(in));
}

ValueId Function::unary(int block, Op op, Type t, ValueId a, u64 addr) {
    Inst in;
    in.op = op;
    in.type = t;
    in.args = {a};
    in.addr = addr;
    return add(block, std::move(in));
}

ValueId Function::cast(int block, Op op, Type t, ValueId a, u64 addr) {
    // An extension that does not extend is a no-op, and one that narrows is a
    // truncation. Emitting either verbatim leaves the IR ill-typed, and the
    // x87 paths reach here with 80-bit values that are already wide enough.
    if (op == Op::ZExt || op == Op::SExt) {
        unsigned from = inst(a).type.bits;
        if (from == t.bits && inst(a).type.kind == t.kind) return a;
        if (from > t.bits) op = Op::Trunc;
    } else if (op == Op::Trunc) {
        unsigned from = inst(a).type.bits;
        if (from == t.bits && inst(a).type.kind == t.kind) return a;
    }
    return unary(block, op, t, a, addr);
}

ValueId Function::load(int block, Type t, ValueId addrVal, u64 addr) {
    Inst in;
    in.op = Op::Load;
    in.type = t;
    in.args = {addrVal};
    in.aux = t.bytes();
    in.addr = addr;
    return add(block, std::move(in));
}

ValueId Function::store(int block, ValueId addrVal, ValueId value, u64 addr) {
    Inst in;
    in.op = Op::Store;
    in.type = Type::voidTy();
    in.args = {addrVal, value};
    in.aux = insts_[value].type.bytes();
    in.addr = addr;
    return add(block, std::move(in));
}

ValueId Function::readLoc(int block, Loc l, Type t, u64 addr) {
    Inst in;
    in.op = Op::ReadLoc;
    in.type = t;
    in.loc = l;
    in.addr = addr;
    return add(block, std::move(in));
}

ValueId Function::writeLoc(int block, Loc l, ValueId value, u64 addr) {
    Inst in;
    in.op = Op::WriteLoc;
    in.type = Type::voidTy();
    in.loc = l;
    in.args = {value};
    in.addr = addr;
    return add(block, std::move(in));
}

void Function::addEdge(int from, int to) {
    blocks_[from].succs.push_back(to);
    blocks_[to].preds.push_back(from);
}

void Function::setSuccessors(int block, std::vector<int> succs) {
    blocks_[block].succs = std::move(succs);
    recomputePreds();
}

void Function::recomputePreds() {
    for (auto& b : blocks_) b.preds.clear();
    for (auto& b : blocks_)
        for (int s : b.succs) blocks_[s].preds.push_back(b.id);
}

void Function::replaceAllUses(ValueId from, ValueId to) {
    if (from == to) return;
    for (auto& in : insts_)
        for (auto& a : in.args)
            if (a == from) a = to;
}

std::unordered_map<ValueId, std::vector<ValueId>> Function::buildUses() const {
    std::unordered_map<ValueId, std::vector<ValueId>> uses;
    for (const auto& b : blocks_)
        for (ValueId v : b.insts)
            for (ValueId a : insts_[v].args)
                if (a != kNoValue) uses[a].push_back(v);
    return uses;
}

void Function::removeDeadInsts() {
    for (auto& b : blocks_) {
        auto& list = b.insts;
        list.erase(std::remove_if(list.begin(), list.end(), [&](ValueId v) { return insts_[v].dead; }), list.end());
    }
}

Digraph Function::cfg() const {
    Digraph g((int)blocks_.size());
    g.entry = 0;
    for (const auto& b : blocks_)
        for (int s : b.succs) g.addEdge(b.id, s);
    return g;
}

void Function::pruneUnreachableBlocks() {
    if (blocks_.empty()) return;
    std::vector<bool> seen(blocks_.size(), false);
    std::vector<int> work{0};
    seen[0] = true;
    while (!work.empty()) {
        int b = work.back();
        work.pop_back();
        for (int s : blocks_[b].succs)
            if (!seen[s]) { seen[s] = true; work.push_back(s); }
    }
    if (std::find(seen.begin(), seen.end(), false) == seen.end()) return;
    std::vector<int> remap(blocks_.size(), -1);
    int next = 0;
    for (size_t i = 0; i < blocks_.size(); ++i)
        if (seen[i]) remap[i] = next++;
    std::vector<Block> kept;
    kept.reserve(next);
    for (size_t i = 0; i < blocks_.size(); ++i) {
        if (!seen[i]) continue;
        Block b = std::move(blocks_[i]);
        // Drop phi arguments coming from removed predecessors.
        std::vector<size_t> keepArgs;
        for (size_t p = 0; p < b.preds.size(); ++p)
            if (remap[b.preds[p]] >= 0) keepArgs.push_back(p);
        if (keepArgs.size() != b.preds.size()) {
            for (ValueId v : b.insts) {
                Inst& in = insts_[v];
                if (in.op != Op::Phi) continue;
                std::vector<ValueId> na;
                for (size_t k : keepArgs)
                    if (k < in.args.size()) na.push_back(in.args[k]);
                in.args = std::move(na);
            }
        }
        b.id = remap[i];
        std::vector<int> ns;
        for (int s : b.succs)
            if (remap[s] >= 0) ns.push_back(remap[s]);
        b.succs = std::move(ns);
        std::vector<int> np;
        for (int p : b.preds)
            if (remap[p] >= 0) np.push_back(remap[p]);
        b.preds = std::move(np);
        if (b.defaultSucc >= 0) b.defaultSucc = remap[b.defaultSucc];
        for (ValueId v : b.insts) insts_[v].block = b.id;
        kept.push_back(std::move(b));
    }
    blocks_ = std::move(kept);
}

std::string Function::print(bool withAddresses) const {
    std::ostringstream os;
    os << "function " << name_ << " @ " << hex(entryAddr_) << " -> " << returnType_.str() << "\n";
    for (size_t i = 0; i < params_.size(); ++i) {
        const Param& p = params_[i];
        os << "  param " << i << ": " << p.type.str() << " " << p.name;
        if (!p.location.empty()) os << "  [" << p.location << "]";
        if (!p.used) os << "  (unused)";
        os << "\n";
    }
    for (const auto& note : notes_) os << "  ; " << note << "\n";
    for (const auto& b : blocks_) {
        os << "\nblock " << b.id;
        if (b.addr) os << " (" << hex(b.addr) << ")";
        if (!b.preds.empty()) {
            os << "  preds:";
            for (int p : b.preds) os << " " << p;
        }
        os << "\n";
        for (ValueId v : b.insts) {
            const Inst& in = insts_[v];
            if (in.dead) continue;
            os << "  ";
            if (in.definesValue()) os << valueName(v) << " = ";
            os << opName(in.op);
            if (!in.type.isVoid()) os << "." << in.type.str();
            switch (in.op) {
            case Op::Const:
                os << " " << (i64)in.imm << " (" << hex(in.imm) << ")";
                break;
            case Op::GlobalAddr:
                os << " " << hex(in.imm);
                break;
            case Op::FrameAddr:
                os << " " << (i64)in.imm;
                break;
            case Op::Arg:
                os << " #" << in.aux;
                break;
            case Op::EntryValue:
                os << " " << in.loc.str();
                break;
            case Op::ReadLoc:
            case Op::WriteLoc:
                os << " " << in.loc.str();
                break;
            default:
                break;
            }
            for (size_t i = 0; i < in.args.size(); ++i) os << (i || in.op == Op::WriteLoc ? ", " : " ") << valueName(in.args[i]);
            if (in.op == Op::Phi) {
                os << "  ; from";
                for (size_t i = 0; i < b.preds.size() && i < in.args.size(); ++i) os << " b" << b.preds[i];
            }
            if (in.call) {
                os << "  ; " << (in.call->name.empty() ? hex(in.call->target) : in.call->name);
                if (in.call->noReturn) os << " [noreturn]";
            }
            if (!in.text.empty()) os << "  ; " << in.text;
            if (withAddresses && in.addr) os << "   @" << hex(in.addr);
            os << "\n";
        }
        if (!b.succs.empty()) {
            os << "  ; succs:";
            for (size_t i = 0; i < b.succs.size(); ++i) {
                os << " " << b.succs[i];
                if (i < b.caseValues.size() && !b.caseValues[i].empty()) {
                    os << "(case";
                    for (size_t k = 0; k < b.caseValues[i].size() && k < 6; ++k) os << " " << b.caseValues[i][k];
                    if (b.caseValues[i].size() > 6) os << " ...";
                    os << ")";
                }
                if (b.defaultSucc == b.succs[i]) os << "(default)";
            }
            os << "\n";
        }
    }
    return os.str();
}

std::vector<std::string> Function::verify() const {
    std::vector<std::string> errs;
    auto err = [&](const std::string& s) {
        if (errs.size() < 64) errs.push_back(s);
    };
    std::vector<char> defined(insts_.size(), 0);
    for (const auto& b : blocks_) {
        if (b.insts.empty()) {
            err(strfmt("block %d is empty", b.id));
            continue;
        }
        for (size_t i = 0; i < b.insts.size(); ++i) {
            ValueId v = b.insts[i];
            const Inst& in = insts_[v];
            if (in.block != b.id) err(strfmt("%s: block field %d != %d", valueName(v).c_str(), in.block, b.id));
            if (in.isTerminator() && i + 1 != b.insts.size())
                err(strfmt("%s: terminator is not last in block %d", valueName(v).c_str(), b.id));
            if (!in.isTerminator() && i + 1 == b.insts.size())
                err(strfmt("block %d does not end in a terminator", b.id));
            if (in.op == Op::Phi && in.args.size() != b.preds.size())
                err(strfmt("%s: phi has %zu args but block %d has %zu preds", valueName(v).c_str(), in.args.size(), b.id, b.preds.size()));
            if (in.op == Op::Phi && i > 0 && insts_[b.insts[i - 1]].op != Op::Phi)
                err(strfmt("%s: phi is not at the top of block %d", valueName(v).c_str(), b.id));
            for (ValueId a : in.args) {
                if (a == kNoValue) {
                    err(strfmt("%s: null operand", valueName(v).c_str()));
                    continue;
                }
                if (a >= insts_.size()) {
                    err(strfmt("%s: operand out of range", valueName(v).c_str()));
                    continue;
                }
                if (!insts_[a].definesValue()) err(strfmt("%s: operand %s defines no value", valueName(v).c_str(), valueName(a).c_str()));
            }
            defined[v] = 1;
        }
        for (int s : b.succs) {
            if (s < 0 || s >= (int)blocks_.size()) {
                err(strfmt("block %d has invalid successor %d", b.id, s));
                continue;
            }
            const auto& p = blocks_[s].preds;
            if (std::find(p.begin(), p.end(), b.id) == p.end())
                err(strfmt("block %d -> %d missing from predecessor list", b.id, s));
        }
    }
    // Type checks on the value graph.
    for (const auto& b : blocks_) {
        for (ValueId v : b.insts) {
            const Inst& in = insts_[v];
            auto argType = [&](size_t i) { return in.args.size() > i && in.args[i] < insts_.size() ? insts_[in.args[i]].type : Type::voidTy(); };
            switch (in.op) {
            case Op::Add: case Op::Sub: case Op::Mul: case Op::UDiv: case Op::SDiv: case Op::URem: case Op::SRem:
            case Op::And: case Op::Or: case Op::Xor:
                if (in.args.size() != 2) err(strfmt("%s: expected 2 operands", valueName(v).c_str()));
                else if (argType(0).bits != in.type.bits || argType(1).bits != in.type.bits)
                    err(strfmt("%s: operand width mismatch (%s, %s vs %s)", valueName(v).c_str(),
                               argType(0).str().c_str(), argType(1).str().c_str(), in.type.str().c_str()));
                break;
            case Op::Shl: case Op::LShr: case Op::AShr: case Op::Rol: case Op::Ror:
                if (in.args.size() != 2) err(strfmt("%s: expected 2 operands", valueName(v).c_str()));
                else if (argType(0).bits != in.type.bits)
                    err(strfmt("%s: shifted operand width mismatch", valueName(v).c_str()));
                break;
            case Op::Trunc:
                if (argType(0).bits <= in.type.bits) err(strfmt("%s: trunc does not narrow", valueName(v).c_str()));
                break;
            case Op::ZExt: case Op::SExt:
                if (argType(0).bits >= in.type.bits) err(strfmt("%s: extend does not widen", valueName(v).c_str()));
                break;
            case Op::Select:
                if (in.args.size() != 3) err(strfmt("%s: select needs 3 operands", valueName(v).c_str()));
                else if (argType(0).bits != 1) err(strfmt("%s: select condition is not i1", valueName(v).c_str()));
                break;
            case Op::Branch:
                if (in.args.size() != 1 || argType(0).bits != 1) err(strfmt("%s: branch condition is not i1", valueName(v).c_str()));
                if (b.succs.size() != 2) err(strfmt("block %d: branch needs 2 successors", b.id));
                break;
            case Op::Jump:
                if (b.succs.size() != 1) err(strfmt("block %d: jump needs 1 successor", b.id));
                break;
            default:
                break;
            }
            if (isComparison(in.op) && in.type.bits != 1) err(strfmt("%s: comparison must produce i1", valueName(v).c_str()));
        }
    }
    return errs;
}

} // namespace dc::ir
