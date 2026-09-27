#include "core/pipeline.h"

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
    if (opt_.verifyStages) {
        for (const auto& e : res->ir->verify()) res->problems.push_back("ssa-structure: " + e);
        for (const auto& e : ssa::verify(*res->ir)) res->problems.push_back("ssa: " + e);
    }
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
