#include "ast/ast.h"

namespace dc::ast {

const char* unOpText(UnOp op) {
    switch (op) {
    case UnOp::Neg: return "-";
    case UnOp::Not: return "~";
    case UnOp::LogicalNot: return "!";
    case UnOp::Plus: return "+";
    }
    return "?";
}

const char* binOpText(BinOp op) {
    switch (op) {
    case BinOp::Add: return "+";
    case BinOp::Sub: return "-";
    case BinOp::Mul: return "*";
    case BinOp::Div: return "/";
    case BinOp::Mod: return "%";
    case BinOp::And: return "&";
    case BinOp::Or: return "|";
    case BinOp::Xor: return "^";
    case BinOp::Shl: return "<<";
    case BinOp::Shr: return ">>";
    case BinOp::Eq: return "==";
    case BinOp::Ne: return "!=";
    case BinOp::Lt: return "<";
    case BinOp::Le: return "<=";
    case BinOp::Gt: return ">";
    case BinOp::Ge: return ">=";
    case BinOp::LogicalAnd: return "&&";
    case BinOp::LogicalOr: return "||";
    case BinOp::Comma: return ",";
    }
    return "?";
}

int precedenceOf(BinOp op) {
    switch (op) {
    case BinOp::Mul: case BinOp::Div: case BinOp::Mod: return 13;
    case BinOp::Add: case BinOp::Sub: return 12;
    case BinOp::Shl: case BinOp::Shr: return 11;
    case BinOp::Lt: case BinOp::Le: case BinOp::Gt: case BinOp::Ge: return 10;
    case BinOp::Eq: case BinOp::Ne: return 9;
    case BinOp::And: return 8;
    case BinOp::Xor: return 7;
    case BinOp::Or: return 6;
    case BinOp::LogicalAnd: return 5;
    case BinOp::LogicalOr: return 4;
    case BinOp::Comma: return 1;
    }
    return 0;
}

int unaryPrecedence() { return 14; }
bool isRightAssociative(BinOp op) { return op == BinOp::Comma ? false : false; }

namespace {
ExprPtr make(ExprKind k, types::TypeRef t) {
    auto e = std::make_unique<Expr>();
    e->kind = k;
    e->type = t;
    return e;
}
} // namespace

ExprPtr Expr::intConst(types::TypeRef t, u64 v, bool isSigned) {
    auto e = make(ExprKind::IntConst, t);
    e->intValue = v;
    e->isSignedConst = isSigned;
    return e;
}
ExprPtr Expr::floatConst(types::TypeRef t, double v) {
    auto e = make(ExprKind::FloatConst, t);
    e->floatValue = v;
    return e;
}
ExprPtr Expr::stringLit(types::TypeRef t, std::string s, bool wide) {
    auto e = make(ExprKind::StringLit, t);
    e->text = std::move(s);
    e->wide = wide;
    return e;
}
ExprPtr Expr::var(types::TypeRef t, int id, std::string name) {
    auto e = make(ExprKind::VarRef, t);
    e->varId = id;
    e->text = std::move(name);
    return e;
}
ExprPtr Expr::global(types::TypeRef t, u64 addr, std::string name) {
    auto e = make(ExprKind::GlobalRef, t);
    e->address = addr;
    e->text = std::move(name);
    return e;
}
ExprPtr Expr::func(types::TypeRef t, u64 addr, std::string name) {
    auto e = make(ExprKind::FuncRef, t);
    e->address = addr;
    e->text = std::move(name);
    return e;
}
ExprPtr Expr::unary(types::TypeRef t, UnOp op, ExprPtr a) {
    auto e = make(ExprKind::Unary, t);
    e->unOp = op;
    e->args.push_back(std::move(a));
    return e;
}
ExprPtr Expr::binary(types::TypeRef t, BinOp op, ExprPtr a, ExprPtr b) {
    auto e = make(ExprKind::Binary, t);
    e->binOp = op;
    e->args.push_back(std::move(a));
    e->args.push_back(std::move(b));
    return e;
}
ExprPtr Expr::ternary(types::TypeRef t, ExprPtr c, ExprPtr a, ExprPtr b) {
    auto e = make(ExprKind::Ternary, t);
    e->args.push_back(std::move(c));
    e->args.push_back(std::move(a));
    e->args.push_back(std::move(b));
    return e;
}
ExprPtr Expr::call(types::TypeRef t, ExprPtr callee, std::vector<ExprPtr> args) {
    auto e = make(ExprKind::Call, t);
    e->args.push_back(std::move(callee));
    for (auto& a : args) e->args.push_back(std::move(a));
    return e;
}
ExprPtr Expr::cast(types::TypeRef t, ExprPtr a) {
    auto e = make(ExprKind::Cast, t);
    e->args.push_back(std::move(a));
    return e;
}
ExprPtr Expr::deref(types::TypeRef t, ExprPtr a) {
    auto e = make(ExprKind::Deref, t);
    e->args.push_back(std::move(a));
    return e;
}
ExprPtr Expr::addrOf(types::TypeRef t, ExprPtr a) {
    auto e = make(ExprKind::AddrOf, t);
    e->args.push_back(std::move(a));
    return e;
}
ExprPtr Expr::member(types::TypeRef t, ExprPtr base, std::string field, bool arrow, u64 offset) {
    auto e = make(ExprKind::Member, t);
    e->args.push_back(std::move(base));
    e->text = std::move(field);
    e->arrow = arrow;
    e->memberOffset = offset;
    return e;
}
ExprPtr Expr::index(types::TypeRef t, ExprPtr base, ExprPtr idx) {
    auto e = make(ExprKind::Index, t);
    e->args.push_back(std::move(base));
    e->args.push_back(std::move(idx));
    return e;
}
ExprPtr Expr::undefined(types::TypeRef t) { return make(ExprKind::Undefined, t); }
ExprPtr Expr::raw(types::TypeRef t, std::string text, std::vector<ExprPtr> args) {
    auto e = make(ExprKind::Raw, t);
    e->text = std::move(text);
    e->args = std::move(args);
    return e;
}

ExprPtr Expr::clone() const {
    auto e = std::make_unique<Expr>();
    e->kind = kind;
    e->type = type;
    e->intValue = intValue;
    e->floatValue = floatValue;
    e->isSignedConst = isSignedConst;
    e->constName = constName;
    e->text = text;
    e->wide = wide;
    e->varId = varId;
    e->address = address;
    e->unOp = unOp;
    e->binOp = binOp;
    e->arrow = arrow;
    e->memberOffset = memberOffset;
    for (const auto& a : args) e->args.push_back(a->clone());
    return e;
}

bool Expr::isSimple() const {
    switch (kind) {
    case ExprKind::IntConst: case ExprKind::FloatConst: case ExprKind::StringLit:
    case ExprKind::VarRef: case ExprKind::GlobalRef: case ExprKind::FuncRef:
    case ExprKind::Call: case ExprKind::Member: case ExprKind::Index: case ExprKind::Undefined:
        return true;
    default:
        return false;
    }
}

namespace {
StmtPtr makeStmt(StmtKind k) {
    auto s = std::make_unique<Stmt>();
    s->kind = k;
    return s;
}
} // namespace

StmtPtr Stmt::compound(std::vector<StmtPtr> body) {
    auto s = makeStmt(StmtKind::Compound);
    s->body = std::move(body);
    return s;
}
StmtPtr Stmt::exprStmt(ExprPtr e) {
    auto s = makeStmt(StmtKind::ExprStmt);
    s->expr = std::move(e);
    return s;
}
StmtPtr Stmt::assign(ExprPtr lhs, ExprPtr rhs) {
    auto s = makeStmt(StmtKind::Assign);
    s->lhs = std::move(lhs);
    s->rhs = std::move(rhs);
    return s;
}
StmtPtr Stmt::decl(int varId, types::TypeRef t, std::string name, ExprPtr init, bool isConst) {
    auto s = makeStmt(StmtKind::Decl);
    s->varId = varId;
    s->declType = t;
    s->declName = std::move(name);
    s->declInit = std::move(init);
    s->isConst = isConst;
    return s;
}
StmtPtr Stmt::ifStmt(ExprPtr cond, StmtPtr thenB, StmtPtr elseB) {
    auto s = makeStmt(StmtKind::If);
    s->expr = std::move(cond);
    s->thenBranch = std::move(thenB);
    s->elseBranch = std::move(elseB);
    return s;
}
StmtPtr Stmt::whileStmt(ExprPtr cond, StmtPtr body) {
    auto s = makeStmt(StmtKind::While);
    s->expr = std::move(cond);
    s->loopBody = std::move(body);
    return s;
}
StmtPtr Stmt::doWhile(StmtPtr body, ExprPtr cond) {
    auto s = makeStmt(StmtKind::DoWhile);
    s->loopBody = std::move(body);
    s->expr = std::move(cond);
    return s;
}
StmtPtr Stmt::forStmt(StmtPtr init, ExprPtr cond, StmtPtr step, StmtPtr body) {
    auto s = makeStmt(StmtKind::For);
    s->init = std::move(init);
    s->expr = std::move(cond);
    s->step = std::move(step);
    s->loopBody = std::move(body);
    return s;
}
StmtPtr Stmt::switchStmt(ExprPtr value, std::vector<SwitchCase> cases) {
    auto s = makeStmt(StmtKind::Switch);
    s->expr = std::move(value);
    s->cases = std::move(cases);
    return s;
}
StmtPtr Stmt::ret(ExprPtr value) {
    auto s = makeStmt(StmtKind::Return);
    s->expr = std::move(value);
    return s;
}
StmtPtr Stmt::brk() { return makeStmt(StmtKind::Break); }
StmtPtr Stmt::cont() { return makeStmt(StmtKind::Continue); }
StmtPtr Stmt::gotoStmt(std::string label) {
    auto s = makeStmt(StmtKind::Goto);
    s->label = std::move(label);
    return s;
}
StmtPtr Stmt::labelStmt(std::string label) {
    auto s = makeStmt(StmtKind::Label);
    s->label = std::move(label);
    return s;
}
StmtPtr Stmt::comment(std::string text) {
    auto s = makeStmt(StmtKind::Comment);
    s->text = std::move(text);
    return s;
}
StmtPtr Stmt::empty() { return makeStmt(StmtKind::Empty); }

bool Stmt::isEmpty() const {
    if (kind == StmtKind::Empty) return true;
    if (kind != StmtKind::Compound) return false;
    for (const auto& s : body)
        if (!s->isEmpty()) return false;
    return true;
}

} // namespace dc::ast
