#include "structure/structurer.h"

#include <algorithm>
#include <functional>
#include <set>

namespace dc::structure {

using ast::Stmt;
using ast::StmtPtr;
using ast::Expr;
using ast::ExprPtr;

namespace {

constexpr int kNone = -1;

struct LoopContext {
    int loopIndex = -1;
    int header = kNone;
    int breakTarget = kNone;
    bool headerIsCondition = false; // the header's branch is the loop condition
};

class Structurer {
public:
    Structurer(const ir::Function& f, BlockEmitter& em, const StructurerOptions& opt)
        : f_(f), em_(em), opt_(opt) {
        g_ = f.cfg();
        exitNode_ = g_.size();
        // Post-dominators need a single exit, so add a virtual one.
        Digraph withExit(g_.size() + 1);
        withExit.entry = 0;
        for (int b = 0; b < g_.size(); ++b) {
            if (g_.succ[b].empty()) withExit.addEdge(b, exitNode_);
            for (int s : g_.succ[b]) withExit.addEdge(b, s);
        }
        dom_ = DomTree::build(g_);
        pdom_ = DomTree::build(withExit.reversed(exitNode_));
        loops_ = LoopInfo::build(g_, dom_);
    }

    StructureResult run() {
        StructureResult res;
        res.irreducible = loops_.irreducible;
        if (loops_.irreducible)
            res.notes.push_back("irreducible control flow: some edges become goto");

        // Two passes: the first discovers which blocks a goto targets, the
        // second emits those labels.
        for (int pass = 0; pass < 2; ++pass) {
            emitted_.assign(g_.size(), false);
            gotoCount_ = 0;
            emitLabels_ = pass == 1;
            LoopContext ctx;
            auto body = sequence(0, kNone, ctx);
            if (pass == 1) {
                res.body = std::move(body);
                res.gotoCount = gotoCount_;
                res.labelCount = (int)labelled_.size();
            }
        }
        return res;
    }

private:
    // Emits blocks starting at `node`, stopping before `stopAt`.
    StmtPtr sequence(int node, int stopAt, const LoopContext& ctx) {
        std::vector<StmtPtr> out;
        int cur = node;
        int guard = 0;
        while (cur != kNone && cur != stopAt) {
            if (++guard > g_.size() * 4 + 16) {
                out.push_back(Stmt::comment("structuring gave up here"));
                break;
            }
            if (emitted_[cur]) {
                // A block that only returns can simply be written again,
                // which is what a programmer would have done.
                if (canDuplicate(cur)) {
                    for (auto& st : em_.statements(cur)) out.push_back(std::move(st));
                    out.push_back(Stmt::ret(em_.returnValue(cur)));
                    break;
                }
                out.push_back(jumpTo(cur, ctx));
                break;
            }
            // A loop header starts a loop, unless we are already inside it.
            int li = headerLoop(cur);
            if (li >= 0 && li != ctx.loopIndex && !insideLoop(ctx, li)) {
                int follow = kNone;
                out.push_back(emitLoop(li, ctx, follow));
                cur = follow;
                continue;
            }
            emitted_[cur] = true;
            if (emitLabels_ && labelled_.count(cur)) out.push_back(Stmt::labelStmt(em_.labelFor(cur)));
            for (auto& s : em_.statements(cur)) out.push_back(std::move(s));

            const ir::Block& b = f_.block(cur);
            const ir::Inst& term = f_.inst(b.insts.back());
            switch (term.op) {
            case ir::Op::Return: {
                out.push_back(Stmt::ret(em_.returnValue(cur)));
                cur = kNone;
                break;
            }
            case ir::Op::Unreachable:
                cur = kNone;
                break;
            case ir::Op::Jump: {
                int next = b.succs.empty() ? kNone : b.succs[0];
                for (auto& s : em_.edgeCopies(cur, next)) out.push_back(std::move(s));
                cur = next;
                break;
            }
            case ir::Op::Branch: {
                if (b.succs.size() != 2) {
                    cur = kNone;
                    break;
                }
                int t = b.succs[0], fls = b.succs[1];
                int follow = chooseFollow(cur, stopAt, ctx);
                out.push_back(emitIf(cur, t, fls, follow, stopAt, ctx));
                cur = follow;
                break;
            }
            case ir::Op::Switch: {
                int follow = chooseFollow(cur, stopAt, ctx);
                out.push_back(emitSwitch(cur, follow, stopAt, ctx));
                cur = follow;
                break;
            }
            default:
                cur = kNone;
                break;
            }
        }
        return Stmt::compound(std::move(out));
    }

    // A conditional region ends where both arms come back together.
    //
    // The immediate post-dominator is the usual answer, but it is too far when
    // one arm can return early: there the arms still rejoin at a nearer block,
    // and using that one keeps the region structured instead of forcing a goto
    // back into it.
    int chooseFollow(int node, int stopAt, const LoopContext& ctx) {
        auto acceptable = [&](int cand) {
            if (cand == kNone || cand == exitNode_ || cand == node) return false;
            if (emitted_[cand]) return false;
            if (!dom_.dominates(node, cand)) return false;
            if (ctx.loopIndex >= 0 && !loops_.loops[ctx.loopIndex].contains(cand)) return false;
            return true;
        };
        int ipd = pdom_.reachable(node) ? pdom_.idom(node) : kNone;
        int best = acceptable(ipd) ? ipd : kNone;

        const ir::Block& b = f_.block(node);
        if (b.succs.size() == 2) {
            std::vector<bool> fromThen = reachableAvoiding(b.succs[0], node);
            std::vector<bool> fromElse = reachableAvoiding(b.succs[1], node);
            for (int cand : dom_.rpo()) {
                if (!acceptable(cand)) continue;
                if (!fromThen[cand] || !fromElse[cand]) continue;
                // Earlier in reverse post-order means a tighter region.
                if (best == kNone || rpoIndex(cand) < rpoIndex(best)) best = cand;
                break;
            }
        }
        return best == kNone ? stopAt : best;
    }

    std::vector<bool> reachableAvoiding(int start, int avoid) {
        std::vector<bool> seen(g_.size(), false);
        if (start < 0 || start >= g_.size()) return seen;
        std::vector<int> work{start};
        seen[start] = true;
        while (!work.empty()) {
            int n = work.back();
            work.pop_back();
            if (n == avoid) continue;
            for (int s : g_.succ[n])
                if (!seen[s]) { seen[s] = true; work.push_back(s); }
        }
        return seen;
    }

    int rpoIndex(int b) {
        if (rpoIndex_.empty()) {
            rpoIndex_.assign(g_.size(), 1 << 30);
            const auto& order = dom_.rpo();
            for (size_t i = 0; i < order.size(); ++i) rpoIndex_[order[i]] = (int)i;
        }
        return b >= 0 && b < (int)rpoIndex_.size() ? rpoIndex_[b] : (1 << 30);
    }

    StmtPtr emitIf(int node, int thenBlock, int elseBlock, int follow, int stopAt, const LoopContext& ctx) {
        ExprPtr cond = em_.condition(node);
        auto copies = [&](int to) { return em_.edgeCopies(node, to); };

        // An arm that goes straight to the follow is no arm at all.
        bool thenEmpty = thenBlock == follow && copies(thenBlock).empty();
        bool elseEmpty = elseBlock == follow && copies(elseBlock).empty();

        if (thenEmpty && !elseEmpty) {
            cond = invert(std::move(cond));
            std::swap(thenBlock, elseBlock);
            std::swap(thenEmpty, elseEmpty);
        }
        std::vector<StmtPtr> thenSeq;
        for (auto& s : copies(thenBlock)) thenSeq.push_back(std::move(s));
        StmtPtr thenBody = sequence(thenBlock, follow == kNone ? stopAt : follow, ctx);
        if (!thenBody->isEmpty() || thenSeq.empty()) thenSeq.push_back(std::move(thenBody));
        StmtPtr thenStmt = Stmt::compound(std::move(thenSeq));

        StmtPtr elseStmt;
        if (!elseEmpty) {
            std::vector<StmtPtr> elseSeq;
            for (auto& s : copies(elseBlock)) elseSeq.push_back(std::move(s));
            StmtPtr body = sequence(elseBlock, follow == kNone ? stopAt : follow, ctx);
            if (!body->isEmpty() || elseSeq.empty()) elseSeq.push_back(std::move(body));
            elseStmt = Stmt::compound(std::move(elseSeq));
            if (elseStmt->isEmpty()) elseStmt.reset();
        }
        // "else { if ... }" reads better as "else if".
        if (opt_.mergeElseIf && elseStmt && elseStmt->kind == ast::StmtKind::Compound &&
            elseStmt->body.size() == 1 && elseStmt->body[0]->kind == ast::StmtKind::If) {
            elseStmt = std::move(elseStmt->body[0]);
        }
        return Stmt::ifStmt(std::move(cond), std::move(thenStmt), std::move(elseStmt));
    }

    StmtPtr emitSwitch(int node, int follow, int stopAt, const LoopContext& ctx) {
        const ir::Block& b = f_.block(node);
        std::vector<ast::SwitchCase> cases;
        LoopContext caseCtx = ctx;
        // `break` inside a switch leaves the switch, not the enclosing loop.
        caseCtx.breakTarget = follow == kNone ? stopAt : follow;
        caseCtx.loopIndex = ctx.loopIndex;

        for (size_t i = 0; i < b.succs.size(); ++i) {
            ast::SwitchCase c;
            if (i < b.caseValues.size()) c.values = b.caseValues[i];
            if (b.succs[i] == b.defaultSucc) c.values.clear();
            std::vector<StmtPtr> seq;
            for (auto& s : em_.edgeCopies(node, b.succs[i])) seq.push_back(std::move(s));
            if (emitted_[b.succs[i]]) {
                seq.push_back(jumpTo(b.succs[i], caseCtx));
            } else {
                seq.push_back(sequence(b.succs[i], caseCtx.breakTarget, caseCtx));
                seq.push_back(Stmt::brk());
            }
            c.body = Stmt::compound(std::move(seq));
            cases.push_back(std::move(c));
        }
        return Stmt::switchStmt(em_.switchValue(node), std::move(cases));
    }

    StmtPtr emitLoop(int li, const LoopContext& outer, int& follow) {
        const Loop& loop = loops_.loops[li];
        int header = loop.header;
        LoopContext ctx;
        ctx.loopIndex = li;
        ctx.header = header;

        // Where the loop leaves to. One exit is the common case; with several
        // the others become goto.
        int exitTarget = kNone;
        for (int e : loop.exits) {
            if (exitTarget == kNone) exitTarget = e;
            else if (e != exitTarget) {
                // Prefer the exit the header branches to.
                const ir::Block& hb = f_.block(header);
                for (int s : hb.succs)
                    if (!loop.contains(s)) exitTarget = s;
            }
        }
        ctx.breakTarget = exitTarget;
        follow = exitTarget;

        // Is the header itself the loop test?
        const ir::Block& hb = f_.block(header);
        const ir::Inst& hterm = f_.inst(hb.insts.back());
        bool headerTests = hterm.op == ir::Op::Branch && hb.succs.size() == 2 &&
                           (!loop.contains(hb.succs[0]) || !loop.contains(hb.succs[1]));

        emitted_[header] = true;
        std::vector<StmtPtr> pre;
        if (emitLabels_ && labelled_.count(header)) pre.push_back(Stmt::labelStmt(em_.labelFor(header)));
        for (auto& s : em_.statements(header)) pre.push_back(std::move(s));

        if (headerTests) {
            ctx.headerIsCondition = true;
            int inside = loop.contains(hb.succs[0]) ? hb.succs[0] : hb.succs[1];
            int outside = loop.contains(hb.succs[0]) ? hb.succs[1] : hb.succs[0];
            ExprPtr cond = em_.condition(header);
            if (!loop.contains(hb.succs[0])) cond = invert(std::move(cond));
            ctx.breakTarget = outside;
            follow = outside;

            std::vector<StmtPtr> bodySeq;
            for (auto& s : em_.edgeCopies(header, inside)) bodySeq.push_back(std::move(s));
            bodySeq.push_back(sequence(inside, header, ctx));
            StmtPtr body = Stmt::compound(std::move(bodySeq));

            StmtPtr loopStmt;
            // Everything the header computes has to run each iteration, so it
            // can only stay a while loop when the header is just the test.
            if (pre.empty()) {
                loopStmt = Stmt::whileStmt(std::move(cond), std::move(body));
                if (opt_.recoverForLoops) loopStmt = tryMakeFor(std::move(loopStmt), header);
            } else {
                // Header work first, then test, then body: while (1) { work; if (!c) break; body; }
                std::vector<StmtPtr> inner;
                for (auto& s : pre) inner.push_back(std::move(s));
                inner.push_back(Stmt::ifStmt(invert(std::move(cond)), Stmt::brk(), nullptr));
                inner.push_back(std::move(body));
                loopStmt = Stmt::whileStmt(Expr::intConst(nullptr, 1), Stmt::compound(std::move(inner)));
                pre.clear();
            }
            std::vector<StmtPtr> out;
            for (auto& s : pre) out.push_back(std::move(s));
            out.push_back(std::move(loopStmt));
            for (auto& s : em_.edgeCopies(header, outside)) out.push_back(std::move(s));
            return Stmt::compound(std::move(out));
        }

        // Otherwise the test is at the bottom, or there is none.
        std::vector<StmtPtr> bodySeq;
        for (auto& s : pre) bodySeq.push_back(std::move(s));
        int next = hb.succs.empty() ? kNone : hb.succs[0];
        if (hterm.op == ir::Op::Jump) {
            for (auto& s : em_.edgeCopies(header, next)) bodySeq.push_back(std::move(s));
            bodySeq.push_back(sequence(next, header, ctx));
        } else {
            // A conditional header whose arms are both inside the loop.
            int t = hb.succs.size() > 0 ? hb.succs[0] : kNone;
            int fl = hb.succs.size() > 1 ? hb.succs[1] : kNone;
            if (t != kNone && fl != kNone)
                bodySeq.push_back(emitIf(header, t, fl, kNone, header, ctx));
        }
        StmtPtr body = Stmt::compound(std::move(bodySeq));

        // If the only latch tests a condition, that is a do-while.
        if (loop.latches.size() == 1) {
            int latch = loop.latches[0];
            const ir::Block& lb = f_.block(latch);
            const ir::Inst& lterm = f_.inst(lb.insts.back());
            if (lterm.op == ir::Op::Branch && lb.succs.size() == 2 && latchIsTail_) {
                bool toHeader0 = lb.succs[0] == header;
                ExprPtr cond = em_.condition(latch);
                if (!toHeader0) cond = invert(std::move(cond));
                return Stmt::doWhile(std::move(body), std::move(cond));
            }
        }
        return Stmt::whileStmt(Expr::intConst(nullptr, 1), std::move(body));
    }

    // Recognises `i = init; while (i < n) { ...; i = i + 1; }`.
    StmtPtr tryMakeFor(StmtPtr whileStmt, int header) {
        (void)header;
        if (!whileStmt || whileStmt->kind != ast::StmtKind::While) return whileStmt;
        Stmt* body = whileStmt->loopBody.get();
        if (!body || body->kind != ast::StmtKind::Compound || body->body.empty()) return whileStmt;
        // Find the last non-empty statement; it must be a self-update.
        int lastIdx = -1;
        for (int i = (int)body->body.size() - 1; i >= 0; --i) {
            if (body->body[i]->isEmpty()) continue;
            lastIdx = i;
            break;
        }
        if (lastIdx < 0) return whileStmt;
        Stmt* last = body->body[lastIdx].get();
        // Flatten a trailing compound of one statement.
        while (last->kind == ast::StmtKind::Compound && last->body.size() == 1) last = last->body[0].get();
        if (last->kind != ast::StmtKind::Assign) return whileStmt;
        if (!last->lhs || last->lhs->kind != ast::ExprKind::VarRef) return whileStmt;
        int varId = last->lhs->varId;
        if (!last->rhs || last->rhs->kind != ast::ExprKind::Binary) return whileStmt;
        if (last->rhs->binOp != ast::BinOp::Add && last->rhs->binOp != ast::BinOp::Sub) return whileStmt;
        const Expr* a = last->rhs->args[0].get();
        if (a->kind != ast::ExprKind::VarRef || a->varId != varId) return whileStmt;
        // The condition has to mention the same variable.
        bool mentions = false;
        std::function<void(const Expr*)> scan = [&](const Expr* e) {
            if (!e) return;
            if (e->kind == ast::ExprKind::VarRef && e->varId == varId) mentions = true;
            for (const auto& c : e->args) scan(c.get());
        };
        scan(whileStmt->expr.get());
        if (!mentions) return whileStmt;

        StmtPtr step = std::move(body->body[lastIdx]);
        body->body.erase(body->body.begin() + lastIdx);
        return Stmt::forStmt(nullptr, std::move(whileStmt->expr), std::move(step),
                             std::move(whileStmt->loopBody));
    }

    // True for a block that ends in a return and computes nothing that could
    // be observed twice, so emitting it again is free of consequence.
    bool canDuplicate(int b) {
        const ir::Block& blk = f_.block(b);
        if (blk.insts.empty()) return false;
        const ir::Inst& term = f_.inst(blk.insts.back());
        if (term.op != ir::Op::Return) return false;
        int statements = 0;
        for (ir::ValueId v : blk.insts) {
            const ir::Inst& in = f_.inst(v);
            if (in.isTerminator() || in.op == ir::Op::Phi) continue;
            if (ir::hasSideEffects(in.op)) return false;
            ++statements;
        }
        return statements <= 2;
    }

    StmtPtr jumpTo(int target, const LoopContext& ctx) {
        if (ctx.loopIndex >= 0 && target == ctx.header) return Stmt::cont();
        if (ctx.breakTarget != kNone && target == ctx.breakTarget) return Stmt::brk();
        ++gotoCount_;
        labelled_.insert(target);
        return Stmt::gotoStmt(em_.labelFor(target));
    }

    static ExprPtr invert(ExprPtr cond) {
        if (!cond) return cond;
        if (cond->kind == ast::ExprKind::Binary) {
            using ast::BinOp;
            BinOp inv = cond->binOp;
            bool ok = true;
            switch (cond->binOp) {
            case BinOp::Eq: inv = BinOp::Ne; break;
            case BinOp::Ne: inv = BinOp::Eq; break;
            case BinOp::Lt: inv = BinOp::Ge; break;
            case BinOp::Ge: inv = BinOp::Lt; break;
            case BinOp::Gt: inv = BinOp::Le; break;
            case BinOp::Le: inv = BinOp::Gt; break;
            default: ok = false; break;
            }
            if (ok) {
                cond->binOp = inv;
                return cond;
            }
        }
        if (cond->kind == ast::ExprKind::Unary && cond->unOp == ast::UnOp::LogicalNot)
            return std::move(cond->args[0]);
        types::TypeRef t = cond->type;
        return Expr::unary(t, ast::UnOp::LogicalNot, std::move(cond));
    }

    int headerLoop(int b) const {
        for (size_t i = 0; i < loops_.loops.size(); ++i)
            if (loops_.loops[i].header == b) return (int)i;
        return -1;
    }
    bool insideLoop(const LoopContext& ctx, int li) const {
        if (ctx.loopIndex < 0) return false;
        int cur = ctx.loopIndex;
        while (cur >= 0) {
            if (cur == li) return true;
            cur = loops_.loops[cur].parent;
        }
        return false;
    }

    const ir::Function& f_;
    BlockEmitter& em_;
    StructurerOptions opt_;
    Digraph g_;
    int exitNode_ = 0;
    DomTree dom_, pdom_;
    LoopInfo loops_;
    std::vector<bool> emitted_;
    std::set<int> labelled_;
    int gotoCount_ = 0;
    bool emitLabels_ = false;
    bool latchIsTail_ = true;
    std::vector<int> rpoIndex_;
};

} // namespace

StructureResult structureFunction(const ir::Function& f, BlockEmitter& emitter,
                                  const StructurerOptions& opt) {
    Structurer s(f, emitter, opt);
    return s.run();
}

} // namespace dc::structure
