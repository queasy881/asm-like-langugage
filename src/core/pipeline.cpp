#include "core/pipeline.h"
#include <algorithm>
#include <set>

namespace dc {

Pipeline::Pipeline(Program& prog, PipelineOptions opt) : prog_(prog), opt_(opt), sigs_(prog) {}

void Pipeline::buildSignatures() {
    if (sigsBuilt_) return;
    sigs_.build();
    sigsBuilt_ = true;
}

std::unique_ptr<FunctionResult> Pipeline::runToSsa(const Function& f) {
    buildSignatures();
    auto res = std::make_unique<FunctionResult>();
    res->machine = &f;
    res->convention = defaultConvention(prog_.is64());
    if (const Signature* s = sigs_.forFunction(f.entry)) {
        res->signature = *s;
        res->convention = s->conv;
    }

    lift::LiftOptions lo;
    lo.convention = res->convention;
    lo.resolveCallee = sigs_.resolver();
    if (res->signature.known) {
        lo.returnType = res->signature.returnType;
        lo.returnTypeKnown = true;
    }
    auto lifted = lift::liftFunction(prog_, f, lo);
    res->ir = std::move(lifted.func);
    res->unsupported = std::move(lifted.unsupported);
    if (opt_.verifyStages) {
        for (const auto& e : res->ir->verify()) res->problems.push_back("lift: " + e);
    }

    res->ir->pruneUnreachableBlocks();
    res->ir->recomputePreds();

    ConventionInfo ci = conventionInfo(res->convention, prog_.is64());
    res->frame = analyzeStackFrame(*res->ir, ci, prog_.pointerSize());
    promoteStackSlots(*res->ir, res->frame);

    res->ssa = ssa::construct(*res->ir);
    res->ssaBuilt = true;
    bindParameters(*res, prog_.pointerSize(), prog_.is64());
    if (opt_.verifyStages) {
        for (const auto& e : res->ir->verify()) res->problems.push_back("ssa-structure: " + e);
        for (const auto& e : ssa::verify(*res->ir)) res->problems.push_back("ssa: " + e);
    }
    return res;
}

void Pipeline::bindParameters(FunctionResult& r, unsigned ptrBytes, bool is64) {
    if (!r.ir || !r.signature.known) return;
    ir::Function& f = *r.ir;
    ConventionInfo ci = conventionInfo(r.convention, is64);

    // Frame offset of each promoted stack slot, so a stack parameter can be
    // recognised after promotion turned it into a location.
    std::map<unsigned, i64> slotOffset;
    for (const auto& s : r.frame.slots)
        if (s.promoted) slotOffset[s.slotId] = s.offset;

    f.params().clear();
    for (size_t i = 0; i < r.signature.paramTypes.size(); ++i) {
        ir::Function::Param p;
        p.type = r.signature.paramTypes[i];
        p.name = strfmt("arg%zu", i + 1);
        p.location = i < r.signature.paramLocations.size() ? r.signature.paramLocations[i].str() : "";
        p.used = i < r.signature.paramUsed.size() ? r.signature.paramUsed[i] : false;
        f.params().push_back(std::move(p));
    }
    f.returnType() = r.signature.returnType;
    f.variadic() = r.signature.variadic;

    // Match each entry value against a parameter location.
    std::vector<ir::ValueId> narrowed;
    for (auto& b : f.blocks()) {
        for (ir::ValueId v : b.insts) {
            ir::Inst& in = f.inst(v);
            if (in.op != ir::Op::EntryValue) continue;
            int match = -1;
            for (size_t i = 0; i < r.signature.paramLocations.size(); ++i) {
                const ParamLocation& pl = r.signature.paramLocations[i];
                if (pl.isStack) {
                    if (in.loc.kind == ir::LocKind::Stack) {
                        auto it = slotOffset.find(in.loc.index);
                        if (it != slotOffset.end() && it->second == pl.stackOffset) { match = (int)i; break; }
                    }
                    continue;
                }
                if (in.loc.kind != ir::LocKind::Reg) continue;
                x86::Family fam = (x86::Family)in.loc.index;
                if (pl.xmmIndex >= 0) {
                    if (fam == x86::xmmFamily(pl.xmmIndex)) { match = (int)i; break; }
                } else if (fam == pl.reg) {
                    match = (int)i;
                    break;
                }
            }
            if (match < 0) continue;
            in.op = ir::Op::Arg;
            in.aux = (u32)match;
            in.loc = ir::Loc{};
            f.params()[match].value = v;
            f.params()[match].used = true;
            narrowed.push_back(v);
        }
    }

    // Where the recovered width is narrower than the register the value came
    // in, the argument really is that narrow: the truncations that revealed it
    // become no-ops and go away, so the narrow value flows on directly.
    for (ir::ValueId v : narrowed) {
        ir::Inst& in = f.inst(v);
        ir::Type want = f.params()[in.aux].type;
        if (want.isFloat() || in.type.isFloat() || want.bits >= in.type.bits) continue;
        in.type = want;
        std::vector<ir::ValueId> identity;
        for (auto& b : f.blocks())
            for (ir::ValueId u : b.insts) {
                const ir::Inst& uu = f.inst(u);
                if (uu.op == ir::Op::Trunc && uu.args.size() == 1 && uu.args[0] == v &&
                    uu.type.bits == want.bits)
                    identity.push_back(u);
            }
        for (ir::ValueId u : identity) f.replaceAllUses(u, v);
        if (!identity.empty()) {
            std::set<ir::ValueId> drop(identity.begin(), identity.end());
            for (auto& b : f.blocks())
                b.insts.erase(std::remove_if(b.insts.begin(), b.insts.end(),
                                             [&](ir::ValueId u) { return drop.count(u) > 0; }),
                              b.insts.end());
        }
    }
    (void)ptrBytes;
}

const winapi::DataAnalysis& Pipeline::data() {
    if (!dataScanned_) {
        data_ = winapi::scanStrings(prog_.image());
        dataScanned_ = true;
    }
    return data_;
}

std::unique_ptr<FunctionResult> Pipeline::runToVariables(const Function& f) {
    auto res = runToOptimized(f);
    if (!res->ir) return res;

    // Spread cheap values back to their uses so they stay expressions instead
    // of turning into named temporaries.
    opt::rematerializeCheapValues(*res->ir);

    types::TypeInference infer(prog_, types_, sigs_);
    res->types = infer.run(*res->ir, res->signature, res->frame);
    res->structs = types::recoverStructs(*res->ir, types_, res->types, f.name, prog_.pointerSize() * 8);
    res->variables = recoverVariables(*res->ir, res->types, res->frame);

    // Overall confidence: type inference, plus everything the analysis had to
    // give up on along the way.
    res->confidence = res->types.overall;
    auto lower = [&](types::Confidence c, const char* why) {
        if (c < res->confidence) res->confidence = c;
        res->confidenceReasons.push_back(why);
    };
    if (!res->unsupported.empty()) lower(types::Confidence::Low, "unsupported instructions");
    if (f.hasUnresolvedIndirect) lower(types::Confidence::Low, "unresolved indirect jump");
    if (f.hasDecodeErrors) lower(types::Confidence::Low, "undecodable bytes");
    if (res->frame.anyEscaped) lower(types::Confidence::Medium, "a frame address escapes");
    if (!res->problems.empty()) lower(types::Confidence::Low, "verification problems");
    return res;
}

std::unique_ptr<FunctionResult> Pipeline::decompile(const Function& f) {
    auto res = runToVariables(f);
    if (!res->ir) return res;
    ast::BuildInputs bi;
    bi.prog = &prog_;
    bi.ir = res->ir.get();
    bi.variables = &res->variables;
    bi.types = &res->types;
    bi.signature = &res->signature;
    bi.frame = &res->frame;
    bi.typeTable = &types_;
    bi.data = &data();
    bi.signatures = &sigs_;
    bi.confidence = res->confidence;
    bi.notes = res->confidenceReasons;
    res->ast = ast::buildFunction(bi);
    cgen::WriterOptions wo;
    res->code = cgen::writeFunction(*res->ast, wo);
    return res;
}

std::unique_ptr<FunctionResult> Pipeline::runToOptimized(const Function& f) {
    auto res = runToSsa(f);
    if (opt_.optimize) {
        res->optStats = opt::optimize(*res->ir);
        if (opt_.verifyStages) {
            for (const auto& e : res->ir->verify()) res->problems.push_back("opt-structure: " + e);
            for (const auto& e : ssa::verify(*res->ir)) res->problems.push_back("opt-ssa: " + e);
        }
    }
    return res;
}

} // namespace dc
