#include <map>
#include "cgen/cwriter.h"
#include "ast/named_constants.h"

#include <cmath>
#include <cstdio>
#include <cctype>
#include <functional>
#include <set>
#include <sstream>

namespace dc::cgen {

using namespace dc::ast;

namespace {

// Globals the recovered code reaches that are declared as raw byte arrays,
// because their real type is not known or is used inconsistently. Accesses to
// those have to go through a cast.
using GlobalKinds = std::map<std::string, types::TypeRef>;

class Writer {
public:
    explicit Writer(const WriterOptions& opt, const GlobalKinds* globals = nullptr)
        : opt_(opt), globals_(globals) {}

    std::string function(const Function& fn);
    std::string signatureOf(const Function& fn);
    std::string applyPrefix(const std::string& name) const;

private:
    void line(const std::string& s);
    void raw(const std::string& s);
    void openBrace();
    void closeBrace(const char* suffix = "");
    void stmt(const Stmt& s);
    void stmtAsBlock(const Stmt* s);
    std::string expr(const Expr& e, int parentPrec = 0);
    // The declared type of a global, or null when it is a raw byte array.
    types::TypeRef globalType(const std::string& name) const {
        if (!globals_) return nullptr;
        auto it = globals_->find(name);
        return it == globals_->end() ? nullptr : it->second;
    }
    const GlobalKinds* globals_ = nullptr;
    std::string constant(const Expr& e);
    std::string declaration(types::TypeRef t, const std::string& name);

    WriterOptions opt_;
    std::ostringstream os_;
    int indent_ = 0;
};

void Writer::line(const std::string& s) {
    os_ << std::string((size_t)indent_ * opt_.indentWidth, ' ') << s << "\n";
}
void Writer::raw(const std::string& s) { os_ << s; }

void Writer::openBrace() {
    if (opt_.braceOnNewLine) line("{");
    ++indent_;
}
void Writer::closeBrace(const char* suffix) {
    --indent_;
    line(std::string("}") + suffix);
}

std::string Writer::applyPrefix(const std::string& name) const {
    std::string base = sanitizeIdentifier(name);
    if (opt_.symbolPrefix.empty()) return base;
    return opt_.localFunctions.count(name) ? opt_.symbolPrefix + base : base;
}

std::string Writer::declaration(types::TypeRef t, const std::string& name) {
    if (!t) return "void* " + name;
    std::string text = t->spell(name);
    // Struct names come from the binary's own symbols and may need cleaning.
    size_t pos = 0;
    while ((pos = text.find("struct ", pos)) != std::string::npos) {
        size_t start = pos + 7;
        size_t end = start;
        while (end < text.size() && (std::isalnum((unsigned char)text[end]) || text[end] == '_' ||
                                     text[end] == '.' || text[end] == '$'))
            ++end;
        std::string raw = text.substr(start, end - start);
        std::string clean = sanitizeIdentifier(raw);
        text.replace(start, end - start, clean);
        pos = start + clean.size();
    }
    return text;
}

std::string Writer::constant(const Expr& e) {
    if (!e.constName.empty()) return e.constName;
    if (e.kind == ExprKind::FloatConst) {
        double v = e.floatValue;
        if (v == (double)(i64)v && std::fabs(v) < 1e15) return strfmt("%lld.0", (long long)(i64)v);
        char buf[64];
        std::snprintf(buf, sizeof buf, "%.17g", v);
        std::string s = buf;
        if (s.find('.') == std::string::npos && s.find('e') == std::string::npos &&
            s.find("inf") == std::string::npos && s.find("nan") == std::string::npos)
            s += ".0";
        if (e.type && e.type->bits == 32) s += "f";
        return s;
    }
    unsigned bits = e.type ? e.type->bits : 64;
    if (bits == 1) return e.intValue ? "true" : "false";
    u64 v = e.intValue;
    if (e.isSignedConst) {
        i64 sv = signExtend(v, bits ? bits : 64);
        // Small values read better in decimal, bit patterns in hex.
        if (sv >= -1024 && sv <= 1024) return std::to_string(sv);
        if (sv < 0) return std::to_string(sv);
    } else if (v <= 1024) {
        return std::to_string(v);
    }
    std::string s = strfmt("0x%llx", (unsigned long long)v);
    if (bits > 32) s += "ULL";
    else if (!e.isSignedConst) s += "u";
    return s;
}

namespace {

// C already performs some of these conversions on its own, so printing them
// only adds noise. Integer promotion widens anything narrower than int to int
// before any operation, so a cast that does exactly that says nothing.
const Expr* stripPromotion(const Expr& e) {
    if (e.kind != ExprKind::Cast || e.args.empty() || !e.args[0]) return &e;
    const Expr& in = *e.args[0];
    if (!e.type || !in.type || !e.type->isInteger() || !in.type->isInteger()) return &e;
    if (e.type->bits == 32 && e.type->isSigned && in.type->bits < 32 && in.type->bits > 1)
        return stripPromotion(in);
    return &e;
}

// In a context that only consumes the bits (a store into a same-width
// destination), a cast that changes nothing but signedness is invisible.
const Expr* stripSameWidth(const Expr& e, unsigned destBits) {
    const Expr* p = stripPromotion(e);
    if (p->kind != ExprKind::Cast || p->args.empty() || !p->args[0]) return p;
    const Expr& in = *p->args[0];
    if (!p->type || !in.type || !p->type->isInteger() || !in.type->isInteger()) return p;
    if (p->type->bits == in.type->bits && p->type->bits == destBits)
        return stripSameWidth(in, destBits);
    return p;
}

// An index is converted to the pointer's arithmetic width anyway, and the
// conversion C picks is the one the cast was spelling out.
const Expr* stripIndexCast(const Expr& e) {
    const Expr* p = stripPromotion(e);
    if (p->kind != ExprKind::Cast || p->args.empty() || !p->args[0]) return p;
    const Expr& in = *p->args[0];
    if (!p->type || !in.type || !p->type->isInteger() || !in.type->isInteger()) return p;
    if (p->type->bits >= in.type->bits && p->type->isSigned == in.type->isSigned && in.type->bits > 1)
        return stripIndexCast(in);
    return p;
}

} // namespace

std::string Writer::expr(const Expr& e, int parentPrec) {
    if (const Expr* p = stripPromotion(e); p != &e) return expr(*p, parentPrec);
    switch (e.kind) {
    case ExprKind::IntConst:
    case ExprKind::FloatConst:
        return constant(e);
    case ExprKind::StringLit:
        return (e.wide ? "L\"" : "\"") + escapeCString(e.text) + "\"";
    case ExprKind::VarRef:
        return e.text;
    case ExprKind::GlobalRef: {
        std::string name = sanitizeIdentifier(e.text);
        types::TypeRef declared = globalType(name);
        // A byte-array global has to be read at the width the code used.
        if (!declared && e.type && e.type->kind != types::Kind::Unknown) {
            std::string s2 = "*(" + e.type->spell() + "*)" + name;
            return unaryPrecedence() < parentPrec ? "(" + s2 + ")" : s2;
        }
        return name;
    }
    case ExprKind::FuncRef:
        return applyPrefix(e.text);
    case ExprKind::Raw: {
        if (e.args.empty()) return e.rawIsCall ? e.text + "()" : e.text;
        std::string s = e.text + "(";
        for (size_t i = 0; i < e.args.size(); ++i) {
            if (i) s += ", ";
            s += expr(*e.args[i], 0);
        }
        return s + ")";
    }
    case ExprKind::Undefined:
        return "/* undefined */ 0";
    case ExprKind::Unary: {
        std::string s = std::string(unOpText(e.unOp)) + expr(*e.args[0], unaryPrecedence());
        return unaryPrecedence() < parentPrec ? "(" + s + ")" : s;
    }
    case ExprKind::Deref: {
        std::string s = "*" + expr(*e.args[0], unaryPrecedence());
        return unaryPrecedence() < parentPrec ? "(" + s + ")" : s;
    }
    case ExprKind::AddrOf: {
        // The address of a byte-array global is the array itself.
        if (e.args[0]->kind == ExprKind::GlobalRef &&
            !globalType(sanitizeIdentifier(e.args[0]->text)))
            return sanitizeIdentifier(e.args[0]->text);
        std::string s = "&" + expr(*e.args[0], unaryPrecedence());
        return unaryPrecedence() < parentPrec ? "(" + s + ")" : s;
    }
    case ExprKind::Cast: {
        std::string s = "(" + (e.type ? e.type->spell() : std::string("void*")) + ")" +
                        expr(*e.args[0], unaryPrecedence());
        return unaryPrecedence() < parentPrec ? "(" + s + ")" : s;
    }
    case ExprKind::Member:
        return expr(*e.args[0], 15) + (e.arrow ? "->" : ".") + e.text;
    case ExprKind::Index:
        return expr(*e.args[0], 15) + "[" + expr(*stripIndexCast(*e.args[1]), 0) + "]";
    case ExprKind::Call: {
        const Expr& callee = *e.args[0];
        std::string target;
        // Calling through anything that is not already a function pointer
        // needs the signature spelled out, or the C says nothing about how
        // the call is made.
        bool typed = callee.kind == ExprKind::FuncRef ||
                     (callee.type && callee.type->kind == types::Kind::Function) ||
                     (callee.type && callee.type->isPointer() && callee.type->pointee &&
                      callee.type->pointee->kind == types::Kind::Function);
        if (typed) {
            target = expr(callee, 15);
        } else {
            std::string sig = (e.type && e.type->kind != types::Kind::Unknown ? e.type->spell()
                                                                             : std::string("void"));
            sig += " (*)(";
            for (size_t i = 1; i < e.args.size(); ++i) {
                if (i > 1) sig += ", ";
                sig += e.args[i] && e.args[i]->type ? e.args[i]->type->spell() : std::string("LONGLONG");
            }
            if (e.args.size() == 1) sig += "void";
            sig += ")";
            target = "((" + sig + ")" + expr(callee, unaryPrecedence()) + ")";
        }
        std::string s = target + "(";
        for (size_t i = 1; i < e.args.size(); ++i) {
            if (i > 1) s += ", ";
            s += expr(*e.args[i], 0);
        }
        return s + ")";
    }
    case ExprKind::Ternary: {
        std::string s = expr(*e.args[0], 4) + " ? " + expr(*e.args[1], 0) + " : " + expr(*e.args[2], 3);
        return 3 < parentPrec ? "(" + s + ")" : s;
    }
    case ExprKind::Binary: {
        int prec = precedenceOf(e.binOp);
        // C's precedence between the bitwise and shift operators is a common
        // source of mistakes, so those combinations are parenthesised even
        // where the grammar does not require it.
        auto family = [](BinOp op) {
            switch (op) {
            case BinOp::And: case BinOp::Or: case BinOp::Xor: return 1;
            case BinOp::Shl: case BinOp::Shr: return 2;
            case BinOp::Add: case BinOp::Sub: case BinOp::Mul: case BinOp::Div: case BinOp::Mod: return 3;
            case BinOp::Eq: case BinOp::Ne: case BinOp::Lt: case BinOp::Le:
            case BinOp::Gt: case BinOp::Ge: return 4;
            default: return 0;
            }
        };
        int mine = family(e.binOp);
        auto side = [&](const Expr& child, int minPrec) {
            std::string text = expr(child, minPrec);
            if (child.kind != ExprKind::Binary) return text;
            int theirs = family(child.binOp);
            bool needClarity = (mine == 1 && theirs != 1 && theirs != 0) ||
                               (mine == 2 && theirs != 2 && theirs != 0) ||
                               (mine == 1 && theirs == 1 && child.binOp != e.binOp) ||
                               (mine == 4 && (theirs == 1 || theirs == 2));
            if (needClarity && !(text.size() > 1 && text.front() == '(' && text.back() == ')'))
                return "(" + text + ")";
            return text;
        };
        std::string s = side(*e.args[0], prec) + " " + binOpText(e.binOp) + " " + side(*e.args[1], prec + 1);
        return prec < parentPrec ? "(" + s + ")" : s;
    }
    }
    return "?";
}

void Writer::stmtAsBlock(const Stmt* s) {
    if (!s) {
        openBrace();
        closeBrace();
        return;
    }
    openBrace();
    if (s->kind == StmtKind::Compound) {
        for (const auto& c : s->body) stmt(*c);
    } else {
        stmt(*s);
    }
    closeBrace();
}

void Writer::stmt(const Stmt& s) {
    switch (s.kind) {
    case StmtKind::Empty:
        return;
    case StmtKind::Compound:
        for (const auto& c : s.body) stmt(*c);
        return;
    case StmtKind::Comment:
        line("/* " + s.text + " */");
        return;
    case StmtKind::Decl: {
        std::string d = declaration(s.declType, s.declName);
        if (s.isConst && s.declType && !s.declType->isPointer()) d = "const " + d;
        if (s.declInit) d += " = " + expr(*s.declInit, 0);
        line(d + ";");
        return;
    }
    case StmtKind::Assign: {
        std::string lhs = expr(*s.lhs, 0);
        if (s.lhs->type && s.lhs->type->isInteger()) {
            if (const Expr* p = stripSameWidth(*s.rhs, s.lhs->type->bits); p != s.rhs.get()) {
                line(lhs + " = " + expr(*p, 0) + ";");
                return;
            }
        }
        // Print the idiomatic compound forms.
        if (s.rhs->kind == ExprKind::Binary && s.rhs->args.size() == 2) {
            const Expr& r = *s.rhs;
            if (expr(*r.args[0], 0) == lhs) {
                if (r.binOp == BinOp::Add && r.args[1]->isIntConst(1)) {
                    line("++" + lhs + ";");
                    return;
                }
                if (r.binOp == BinOp::Sub && r.args[1]->isIntConst(1)) {
                    line("--" + lhs + ";");
                    return;
                }
                const char* opText = nullptr;
                switch (r.binOp) {
                case BinOp::Add: opText = "+="; break;
                case BinOp::Sub: opText = "-="; break;
                case BinOp::Mul: opText = "*="; break;
                case BinOp::Div: opText = "/="; break;
                case BinOp::Mod: opText = "%="; break;
                case BinOp::And: opText = "&="; break;
                case BinOp::Or: opText = "|="; break;
                case BinOp::Xor: opText = "^="; break;
                case BinOp::Shl: opText = "<<="; break;
                case BinOp::Shr: opText = ">>="; break;
                default: break;
                }
                if (opText) {
                    line(lhs + " " + opText + " " + expr(*r.args[1], 0) + ";");
                    return;
                }
            }
        }
        line(lhs + " = " + expr(*s.rhs, 0) + ";");
        return;
    }
    case StmtKind::ExprStmt:
        line(expr(*s.expr, 0) + ";");
        return;
    case StmtKind::Return:
        if (s.expr) line("return " + expr(*s.expr, 0) + ";");
        else line("return;");
        return;
    case StmtKind::Break:
        line("break;");
        return;
    case StmtKind::Continue:
        line("continue;");
        return;
    case StmtKind::Goto:
        line("goto " + s.label + ";");
        return;
    case StmtKind::Label: {
        // Labels sit one level out so they stand clear of the code.
        int saved = indent_;
        indent_ = std::max(0, indent_ - 1);
        line(s.label + ":");
        indent_ = saved;
        return;
    }
    case StmtKind::If: {
        line("if (" + expr(*s.expr, 0) + ")");
        stmtAsBlock(s.thenBranch.get());
        if (s.elseBranch) {
            if (s.elseBranch->kind == StmtKind::If) {
                // else if, without nesting a whole block.
                const Stmt& ei = *s.elseBranch;
                line("else if (" + expr(*ei.expr, 0) + ")");
                stmtAsBlock(ei.thenBranch.get());
                const Stmt* tail = ei.elseBranch.get();
                while (tail && tail->kind == StmtKind::If) {
                    line("else if (" + expr(*tail->expr, 0) + ")");
                    stmtAsBlock(tail->thenBranch.get());
                    tail = tail->elseBranch.get();
                }
                if (tail && !tail->isEmpty()) {
                    line("else");
                    stmtAsBlock(tail);
                }
            } else if (!s.elseBranch->isEmpty()) {
                line("else");
                stmtAsBlock(s.elseBranch.get());
            }
        }
        return;
    }
    case StmtKind::While:
        if (s.expr && s.expr->kind == ExprKind::IntConst && s.expr->intValue == 1) line("while (true)");
        else line("while (" + expr(*s.expr, 0) + ")");
        stmtAsBlock(s.loopBody.get());
        return;
    case StmtKind::DoWhile:
        line("do");
        stmtAsBlock(s.loopBody.get());
        {
            // Attach the condition to the closing brace.
            std::string text = os_.str();
            size_t pos = text.rfind("}\n");
            if (pos != std::string::npos) {
                text = text.substr(0, pos + 1) + " while (" + expr(*s.expr, 0) + ");\n";
                os_.str(text);
                os_.seekp(0, std::ios_base::end);
            }
        }
        return;
    case StmtKind::For: {
        std::string init, step;
        if (s.init && s.init->kind == StmtKind::Assign) init = expr(*s.init->lhs, 0) + " = " + expr(*s.init->rhs, 0);
        if (s.step && s.step->kind == StmtKind::Assign) {
            const Stmt& st = *s.step;
            std::string lhs = expr(*st.lhs, 0);
            if (st.rhs->kind == ExprKind::Binary && st.rhs->args.size() == 2 &&
                expr(*st.rhs->args[0], 0) == lhs) {
                if (st.rhs->binOp == BinOp::Add && st.rhs->args[1]->isIntConst(1)) step = "++" + lhs;
                else if (st.rhs->binOp == BinOp::Sub && st.rhs->args[1]->isIntConst(1)) step = "--" + lhs;
                else if (st.rhs->binOp == BinOp::Add) step = lhs + " += " + expr(*st.rhs->args[1], 0);
                else if (st.rhs->binOp == BinOp::Sub) step = lhs + " -= " + expr(*st.rhs->args[1], 0);
            }
            if (step.empty()) step = lhs + " = " + expr(*st.rhs, 0);
        }
        line("for (" + init + "; " + (s.expr ? expr(*s.expr, 0) : "") + "; " + step + ")");
        stmtAsBlock(s.loopBody.get());
        return;
    }
    case StmtKind::Switch: {
        line("switch (" + expr(*s.expr, 0) + ")");
        openBrace();
        for (const auto& c : s.cases) {
            if (c.values.empty()) {
                line("default:");
            } else {
                for (i64 v : c.values) line("case " + std::to_string(v) + ":");
            }
            ++indent_;
            if (c.body) stmt(*c.body);
            --indent_;
            os_ << "\n";
        }
        closeBrace();
        return;
    }
    }
}

std::string Writer::signatureOf(const Function& fn) {
    std::string sig = (fn.returnType ? fn.returnType->spell() : "void") + " ";
    if (!fn.convention.empty()) sig += fn.convention + " ";
    sig += applyPrefix(fn.name) + "(";
    for (size_t i = 0; i < fn.params.size(); ++i) {
        if (i) sig += ", ";
        sig += declaration(fn.params[i].type, fn.params[i].name);
    }
    if (fn.variadic) sig += fn.params.empty() ? "..." : ", ...";
    if (fn.params.empty() && !fn.variadic) sig += "void";
    return sig + ")";
}

std::string Writer::function(const Function& fn) {
    if (opt_.emitConfidence)
        line(strfmt("/* confidence: %s */", types::confidenceName(fn.confidence)));
    for (const auto& n : fn.notes) line("/* " + n + " */");
    if (fn.gotoCount) line(strfmt("/* %d goto%s: this region has no structured form */", fn.gotoCount,
                                  fn.gotoCount == 1 ? "" : "s"));
    line(signatureOf(fn));
    openBrace();
    for (const auto& d : fn.declarations) stmt(*d);
    if (!fn.declarations.empty()) os_ << "\n";
    if (fn.body) stmt(*fn.body);
    closeBrace();
    return os_.str();
}

} // namespace

std::string writeFunction(const Function& fn, const WriterOptions& opt) {
    Writer w(opt);
    return w.function(fn);
}

std::string writeDeclaration(const Function& fn, const WriterOptions& opt) {
    Writer w(opt);
    return w.signatureOf(fn) + ";";
}

std::string writeProgram(const std::vector<const Function*>& functions,
                         const std::vector<const types::Type*>& structs, const WriterOptions& opt) {
    std::ostringstream os;
    os << writePreamble();
    os << writeStructs(structs);
    // Globals the recovered code refers to but that live outside it.
    std::set<std::string> globals;
    std::map<std::string, std::set<std::string>> globalSpellings;
    std::map<std::string, types::TypeRef> globalOneType;
    std::function<void(const ast::Expr*)> scanExpr = [&](const ast::Expr* e) {
        if (!e) return;
        if (e->kind == ast::ExprKind::GlobalRef && !e->text.empty()) {
            std::string n = sanitizeIdentifier(e->text);
            globals.insert(n);
            if (e->type && e->type->kind != types::Kind::Unknown && !e->type->isStruct()) {
                globalSpellings[n].insert(e->type->spell());
                globalOneType[n] = e->type;
            } else {
                globalSpellings[n].insert("");   // an address-of, or an unknown width
            }
        }
        for (const auto& a : e->args) scanExpr(a.get());
    };
    std::function<void(const ast::Stmt&)> scanStmt = [&](const ast::Stmt& st) {
        scanExpr(st.expr.get());
        scanExpr(st.lhs.get());
        scanExpr(st.rhs.get());
        scanExpr(st.declInit.get());
        for (const auto& c : st.body) scanStmt(*c);
        if (st.thenBranch) scanStmt(*st.thenBranch);
        if (st.elseBranch) scanStmt(*st.elseBranch);
        if (st.loopBody) scanStmt(*st.loopBody);
        if (st.init) scanStmt(*st.init);
        if (st.step) scanStmt(*st.step);
        for (const auto& c : st.cases)
            if (c.body) scanStmt(*c.body);
    };
    for (const Function* fn : functions) {
        if (fn->body) scanStmt(*fn->body);
        for (const auto& d : fn->declarations) scanStmt(*d);
    }
    std::set<std::string> defined;
    for (const Function* fn : functions) defined.insert(sanitizeIdentifier(fn->name));
    GlobalKinds globalKinds;
    for (const auto& g : globals) {
        auto it = globalSpellings.find(g);
        if (it != globalSpellings.end() && it->second.size() == 1 && !it->second.begin()->empty())
            globalKinds[g] = globalOneType[g];
    }
    if (!globals.empty()) {
        os << "/* Data outside the recovered code. */\n";
        for (const auto& g : globals) {
            if (defined.count(g)) continue;
            auto it = globalKinds.find(g);
            if (it != globalKinds.end()) os << "extern " << it->second->spell(g) << ";\n";
            else os << "extern BYTE " << g << "[];\n";
        }
        os << "\n";
    }
    os << "/* Forward declarations, so the order of definitions does not matter. */\n";
    for (const Function* fn : functions) {
        Writer w(opt, &globalKinds);
        os << w.signatureOf(*fn) << ";\n";
    }
    os << "\n";
    for (const Function* fn : functions) {
        Writer w(opt, &globalKinds);
        os << w.function(*fn) << "\n";
    }
    return os.str();
}

std::string writeStructs(const std::vector<const types::Type*>& structs) {
    std::ostringstream os;
    for (const types::Type* st : structs) {
        if (!st || st->fields.empty()) continue;
        os << "#pragma pack(push, 1)\n";
        os << "struct " << sanitizeIdentifier(st->name) << " {\n";
        for (const auto& f : st->fields) {
            os << "    " << (f.type ? f.type->spell(f.name) : "void* " + f.name) << ";";
            os << strfmt("  /* +0x%llx, %u bytes%s */", (unsigned long long)f.offset, f.size,
                         f.accessed ? "" : ", not accessed");
            os << "\n";
        }
        os << "};\n#pragma pack(pop)\n\n";
    }
    return os.str();
}

std::string writePreamble() {
    std::ostringstream defs;
    defs << "\n/* Constants the recovered code uses by name. */\n";
    for (const auto& c : ast::kNamedConstants)
        defs << strfmt("#define %s 0x%llx%s\n", c.name, (unsigned long long)c.value,
                       c.bits > 32 ? "ULL" : "u");
    return std::string(R"(/* Recovered by decomp. Types use the Windows spellings. */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef char CHAR;
typedef unsigned char BYTE;
typedef short SHORT;
typedef unsigned short WORD;
typedef int INT;
typedef unsigned int DWORD;
typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef void* HANDLE;
typedef void* HWND;
typedef void* HMODULE;
typedef size_t SIZE_T;
typedef long LONG;
typedef unsigned long ULONG;
typedef int BOOL;
typedef unsigned short WCHAR;

/* Operations the machine has and C does not. On MSVC these are intrinsics. */
#if !defined(_MSC_VER)
static inline DWORD _rotl(DWORD v, int n) { n &= 31; return n ? (v << n) | (v >> (32 - n)) : v; }
static inline DWORD _rotr(DWORD v, int n) { n &= 31; return n ? (v >> n) | (v << (32 - n)) : v; }
static inline ULONGLONG _rotl64(ULONGLONG v, int n) { n &= 63; return n ? (v << n) | (v >> (64 - n)) : v; }
static inline ULONGLONG _rotr64(ULONGLONG v, int n) { n &= 63; return n ? (v >> n) | (v << (64 - n)) : v; }
static inline DWORD _byteswap_ulong(DWORD v) { return __builtin_bswap32(v); }
static inline ULONGLONG _byteswap_uint64(ULONGLONG v) { return __builtin_bswap64(v); }
static inline LONGLONG __mulh(LONGLONG a, LONGLONG b) { return (LONGLONG)(((__int128)a * b) >> 64); }
static inline ULONGLONG __umulh(ULONGLONG a, ULONGLONG b) { return (ULONGLONG)(((unsigned __int128)a * b) >> 64); }
static inline DWORD __popcnt(DWORD v) { return (DWORD)__builtin_popcount(v); }
#endif
static inline ULONGLONG _byteswap(ULONGLONG v) { return __builtin_bswap64(v); }
static inline DWORD _tzcnt_u32(DWORD v) { return v ? (DWORD)__builtin_ctz(v) : 32u; }
static inline DWORD _lzcnt_u32(DWORD v) { return v ? (DWORD)__builtin_clz(v) : 32u; }
static inline DWORD _bit_scan_reverse(DWORD v) { return v ? (DWORD)(31 - __builtin_clz(v)) : 0u; }
static inline bool _parity8(DWORD v) { return (__builtin_popcount(v & 0xFF) & 1) == 0; }

/* An instruction with no model. The recovered code names it rather than
   pretending to know what it does. */
extern LONGLONG __unmodelled(const char* mnemonic, ...);
)") + defs.str();
}

} // namespace dc::cgen
