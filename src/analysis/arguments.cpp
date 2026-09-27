#include "analysis/arguments.h"

#include "analysis/stack_frame.h"
#include "opt/passes.h"
#include "ssa/ssa.h"
#include "winapi/api_database.h"

#include <algorithm>
#include <set>
#include <sstream>

namespace dc {

using ir::Op;
using ir::ValueId;
using ir::kNoValue;

std::string ParamLocation::str() const {
    if (isStack) return strfmt("stack%+lld", (long long)stackOffset);
    if (xmmIndex >= 0) return strfmt("xmm%d", xmmIndex);
    return x86::familyName(reg);
}

std::string Signature::str() const {
    std::ostringstream os;
    os << returnType.str() << " " << (name.empty() ? "?" : name) << "(";
    for (size_t i = 0; i < paramTypes.size(); ++i) {
        if (i) os << ", ";
        os << paramTypes[i].str();
        if (i < paramLocations.size()) os << " /*" << paramLocations[i].str() << "*/";
        if (i < paramUsed.size() && !paramUsed[i]) os << " /*unused*/";
    }
    if (variadic) os << (paramTypes.empty() ? "..." : ", ...");
    os << ")";
    if (noReturn) os << " /*noreturn*/";
    return os.str();
}

namespace {

// Locations whose entry value is observed: the function reads them before
// writing them on at least one path.
std::set<u32> liveInLocations(const ir::Function& f, std::map<u32, ir::Type>& types) {
    std::set<u32> result;
    for (const auto& b : f.blocks()) {
        for (ValueId v : b.insts) {
            const ir::Inst& in = f.inst(v);
            if (in.op != Op::EntryValue) continue;
            result.insert(in.loc.key());
            types[in.loc.key()] = in.type;
        }
    }
    return result;
}

bool valueIsMeaningful(const ir::Function& f, ValueId v) {
    if (v == kNoValue) return false;
    const ir::Inst& in = f.inst(v);
    return in.op != Op::Undef;
}

} // namespace

Signature recoverSignature(Program& prog, const Function& mf, const ir::Function& f, CallConv conv) {
    Signature sig;
    sig.name = mf.name;
    sig.conv = conv == CallConv::Unknown ? defaultConvention(prog.is64()) : conv;
    sig.noReturn = !mf.returns;
    ConventionInfo ci = conventionInfo(sig.conv, prog.is64());
    unsigned ps = prog.pointerSize();

    std::map<u32, ir::Type> types;
    std::set<u32> live = liveInLocations(f, types);
    auto isLive = [&](ir::Loc l) { return live.count(l.key()) > 0; };
    auto typeOf = [&](ir::Loc l) {
        auto it = types.find(l.key());
        return it == types.end() ? ir::Type::i((u16)(ps * 8)) : it->second;
    };

    // Integer and float argument registers, in convention order. A later
    // argument being used means the earlier ones exist too, even if this
    // function ignores them.
    size_t lastUsed = 0;
    bool anyUsed = false;
    std::vector<bool> used;
    std::vector<ir::Type> tys;
    std::vector<ParamLocation> locs;

    size_t maxRegArgs = std::max(ci.intArgRegs.size(), ci.floatArgRegs.size());
    for (size_t i = 0; i < maxRegArgs; ++i) {
        ir::Loc intLoc{ir::LocKind::Reg, (u16)(i < ci.intArgRegs.size() ? ci.intArgRegs[i] : x86::Family::None), (u16)ps};
        bool intUsed = i < ci.intArgRegs.size() && isLive(intLoc);
        bool fltUsed = false;
        ir::Loc fltLoc{};
        if (ci.positionalFloatRegs && i < ci.floatArgRegs.size()) {
            for (unsigned w : {4u, 8u, 16u}) {
                ir::Loc l{ir::LocKind::Reg, (u16)x86::xmmFamily(ci.floatArgRegs[i]), (u16)w};
                if (isLive(l)) { fltUsed = true; fltLoc = l; break; }
            }
        }
        ParamLocation pl;
        ir::Type t;
        bool u = intUsed || fltUsed;
        if (fltUsed && !intUsed) {
            pl.xmmIndex = ci.floatArgRegs[i];
            ir::Type raw = typeOf(fltLoc);
            t = raw.bits == 32 ? ir::kF32 : ir::kF64;
        } else {
            pl.reg = i < ci.intArgRegs.size() ? ci.intArgRegs[i] : x86::Family::None;
            t = intUsed ? typeOf(intLoc) : ir::Type::i((u16)(ps * 8));
        }
        if (u) {
            lastUsed = i + 1;
            anyUsed = true;
        }
        used.push_back(u);
        tys.push_back(t);
        locs.push_back(pl);
    }
    // Only keep up to the last register argument actually consumed.
    if (!anyUsed) lastUsed = 0;
    used.resize(lastUsed);
    tys.resize(lastUsed);
    locs.resize(lastUsed);

    // Stack arguments: frame slots at or above the convention's first slot.
    ConventionInfo ci2 = ci;
    StackFrame frame = analyzeStackFrame(f, ci2, ps);
    std::vector<const FrameSlot*> stackArgs;
    for (const auto& s : frame.slots)
        if (s.kind == SlotKind::IncomingArg && s.offset >= ci.stackArgStart) stackArgs.push_back(&s);
    std::sort(stackArgs.begin(), stackArgs.end(), [](const FrameSlot* a, const FrameSlot* b) { return a->offset < b->offset; });
    if (!stackArgs.empty()) {
        // Fill the gap between the register arguments and the first stack slot.
        i64 want = ci.stackArgStart;
        for (const FrameSlot* s : stackArgs) {
            while (want < s->offset) {
                ParamLocation pl;
                pl.isStack = true;
                pl.stackOffset = want;
                locs.push_back(pl);
                tys.push_back(ir::Type::i((u16)(ps * 8)));
                used.push_back(false);
                want += ps;
            }
            ParamLocation pl;
            pl.isStack = true;
            pl.stackOffset = s->offset;
            locs.push_back(pl);
            tys.push_back(s->type);
            used.push_back(true);
            want = s->offset + (i64)std::max<unsigned>(s->size, ps);
        }
        // Register arguments must all exist if a stack argument does.
        if (locs.size() > used.size()) used.resize(locs.size(), false);
        if (lastUsed < ci.intArgRegs.size()) {
            std::vector<ir::Type> t2;
            std::vector<ParamLocation> l2;
            std::vector<bool> u2;
            for (size_t i = 0; i < ci.intArgRegs.size(); ++i) {
                ParamLocation pl;
                pl.reg = ci.intArgRegs[i];
                if (i < locs.size() && !locs[i].isStack) {
                    t2.push_back(tys[i]);
                    l2.push_back(locs[i]);
                    u2.push_back(used[i]);
                } else {
                    t2.push_back(ir::Type::i((u16)(ps * 8)));
                    l2.push_back(pl);
                    u2.push_back(false);
                }
            }
            for (size_t i = 0; i < locs.size(); ++i) {
                if (!locs[i].isStack) continue;
                t2.push_back(tys[i]);
                l2.push_back(locs[i]);
                u2.push_back(used[i]);
            }
            tys = std::move(t2);
            locs = std::move(l2);
            used = std::move(u2);
        }
    }

    sig.paramTypes = std::move(tys);
    sig.paramLocations = std::move(locs);
    sig.paramUsed = std::move(used);

    // Return value: is the convention's return register meaningfully set on
    // any path that returns?
    bool returnsInt = false, returnsFloat = false;
    unsigned intBytes = 0, floatBytes = 0;
    for (const auto& b : f.blocks()) {
        if (b.insts.empty()) continue;
        const ir::Inst& term = f.inst(b.insts.back());
        if (term.op != Op::Return || term.args.empty()) continue;
        ValueId rv = term.args[0];
        if (!valueIsMeaningful(f, rv)) continue;
        const ir::Inst& in = f.inst(rv);
        // A return of the incoming value of the return register means the
        // function never set it, so it returns nothing.
        if (in.op == Op::EntryValue && in.loc.kind == ir::LocKind::Reg &&
            (x86::Family)in.loc.index == ci.intReturn)
            continue;
        if (in.type.isFloat()) {
            returnsFloat = true;
            floatBytes = std::max(floatBytes, in.type.bytes());
        } else {
            returnsInt = true;
            intBytes = std::max(intBytes, in.type.bytes());
        }
    }
    if (returnsFloat && !returnsInt) {
        sig.returnType = floatBytes == 4 ? ir::kF32 : ir::kF64;
        sig.returnsValue = true;
    } else if (returnsInt) {
        sig.returnType = ir::Type::i((u16)(std::max(intBytes, 1u) * 8));
        sig.returnsValue = true;
    } else {
        sig.returnType = ir::Type::voidTy();
    }
    if (sig.conv == CallConv::Stdcall || sig.conv == CallConv::Fastcall || sig.conv == CallConv::Thiscall) {
        unsigned stackParams = 0;
        for (const auto& l : sig.paramLocations)
            if (l.isStack) ++stackParams;
        sig.stackBytesCleaned = stackParams * ps;
    }
    sig.known = true;
    return sig;
}

// ---------------------------------------------------------------------------

const Signature* SignatureDatabase::forFunction(u64 entry) const {
    auto it = byEntry_.find(entry);
    return it == byEntry_.end() ? nullptr : &it->second;
}

const Signature* SignatureDatabase::forImport(const pe::Import* imp) const {
    if (!imp) return nullptr;
    auto it = byImport_.find(imp->displayName());
    return it == byImport_.end() ? nullptr : &it->second;
}

CallConv SignatureDatabase::conventionOf(u64 entry) const {
    const Signature* s = forFunction(entry);
    return s ? s->conv : CallConv::Unknown;
}

lift::SignatureResolver SignatureDatabase::resolver() const {
    return [this](u64 target, const pe::Import* imp, lift::CalleeSignature& out) {
        const Signature* s = imp ? forImport(imp) : forFunction(target);
        if (!s && !imp && target) {
            // A direct call to an import thunk resolves through the thunk.
            if (const pe::Import* via = prog_.importViaThunk(target)) s = forImport(via);
        }
        if (!s) return false;
        out.known = true;
        out.conv = s->conv;
        out.paramTypes = s->paramTypes;
        out.returnType = s->returnType;
        out.variadic = s->variadic;
        out.noReturn = s->noReturn;
        out.stackBytesCleaned = s->stackBytesCleaned;
        out.name = s->name;
        return true;
    };
}

void SignatureDatabase::build(int maxRounds) {
    // Imports come from the API database, which knows them exactly.
    for (const auto& imp : prog_.image().imports()) {
        Signature s;
        s.name = imp.displayName();
        s.known = true;
        s.conv = defaultConvention(prog_.is64());
        if (const winapi::ApiSignature* api = winapi::lookup(imp.name, prog_.is64())) {
            s.paramTypes = api->paramTypes(prog_.pointerSize());
            s.returnType = api->returnIrType(prog_.pointerSize());
            s.variadic = api->variadic;
            s.noReturn = api->noReturn;
            s.conv = api->convention(prog_.is64());
            for (size_t i = 0; i < s.paramTypes.size(); ++i) s.paramUsed.push_back(true);
        } else {
            s.known = false;
        }
        if (s.known) byImport_[s.name] = std::move(s);
    }

    // Internal functions: start with no arguments and grow to a fixed point.
    for (int round = 0; round < maxRounds; ++round) {
        ++rounds_;
        bool changed = false;
        auto res = resolver();
        for (const auto& [va, mf] : prog_.functions()) {
            if (mf->isImportThunk) {
                if (const pe::Import* imp = mf->thunkImport) {
                    if (const Signature* s = forImport(imp)) {
                        Signature copy = *s;
                        copy.name = mf->name;
                        auto& slot = byEntry_[va];
                        if (slot.paramTypes.size() != copy.paramTypes.size()) changed = true;
                        slot = std::move(copy);
                    }
                }
                continue;
            }
            lift::LiftOptions lo;
            lo.convention = defaultConvention(prog_.is64());
            lo.resolveCallee = res;
            auto lifted = lift::liftFunction(prog_, *mf, lo);
            lifted.func->pruneUnreachableBlocks();
            lifted.func->recomputePreds();
            ssa::construct(*lifted.func);
            // Dead reads would make a register look like an argument.
            opt::deadCodeElimination(*lifted.func);
            Signature s = recoverSignature(prog_, *mf, *lifted.func, lo.convention);
            auto it = byEntry_.find(va);
            if (it == byEntry_.end() || it->second.paramTypes.size() != s.paramTypes.size() ||
                it->second.returnType != s.returnType) {
                changed = true;
            }
            byEntry_[va] = std::move(s);
        }
        if (!changed) break;
    }
}

} // namespace dc
