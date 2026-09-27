#include "cgen/cwriter.h"

#include <cmath>
#include <cstdio>
#include <sstream>

namespace dc::cgen {

using namespace dc::ast;

namespace {

class Writer {
public:
    explicit Writer(const WriterOptions& opt) : opt_(opt) {}

    std::string function(const Function& fn);

private:
    void line(const std::string& s);
    void raw(const std::string& s);
    void openBrace();
    void closeBrace(const char* suffix = "");
    void stmt(const Stmt& s);
    void stmtAsBlock(const Stmt* s);
    std::string expr(const Expr& e, int parentPrec = 0);
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

std::string Writer::declaration(types::TypeRef t, const std::string& name) {
    if (!t) return "void* " + name;
    return t->spell(name);
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

std::string Writer::expr(const Expr& e, int parentPrec) {
    switch (e.kind) {
    case ExprKind::IntConst:
    case ExprKind::FloatConst:
        return constant(e);
    case ExprKind::StringLit:
        return (e.wide ? "L\"" : "\"") + escapeCString(e.text) + "\"";
    case ExprKind::VarRef:
    case ExprKind::GlobalRef:
    case ExprKind::FuncRef:
        return e.text;
    case ExprKind::Raw: {
        if (e.args.empty()) return e.text;
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
        return expr(*e.args[0], 15) + "[" + expr(*e.args[1], 0) + "]";
    case ExprKind::Call: {
        std::string s = expr(*e.args[0], 15) + "(";
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
        std::string lhs = expr(*e.args[0], prec);
        std::string rhs = expr(*e.args[1], prec + 1);
        std::string s = lhs + " " + binOpText(e.binOp) + " " + rhs;
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
        if (s.isConst) d = "const " + d;
        if (s.declInit) d += " = " + expr(*s.declInit, 0);
        line(d + ";");
        return;
    }
    case StmtKind::Assign: {
        std::string lhs = expr(*s.lhs, 0);
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

std::string Writer::function(const Function& fn) {
    if (opt_.emitConfidence)
        line(strfmt("/* confidence: %s */", types::confidenceName(fn.confidence)));
    for (const auto& n : fn.notes) line("/* " + n + " */");
    if (fn.gotoCount) line(strfmt("/* %d goto%s: this region has no structured form */", fn.gotoCount,
                                  fn.gotoCount == 1 ? "" : "s"));

    std::string sig = (fn.returnType ? fn.returnType->spell() : "void") + " ";
    if (!fn.convention.empty()) sig += fn.convention + " ";
    sig += fn.name + "(";
    for (size_t i = 0; i < fn.params.size(); ++i) {
        if (i) sig += ", ";
        sig += declaration(fn.params[i].type, fn.params[i].name);
    }
    if (fn.variadic) sig += fn.params.empty() ? "..." : ", ...";
    if (fn.params.empty() && !fn.variadic) sig += "void";
    sig += ")";
    line(sig);
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

std::string writeStructs(const std::vector<const types::Type*>& structs) {
    std::ostringstream os;
    for (const types::Type* st : structs) {
        if (!st || st->fields.empty()) continue;
        os << "#pragma pack(push, 1)\n";
        os << "struct " << st->name << " {\n";
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
    return "/* Recovered by decomp. Types use the Windows spellings. */\n"
           "#include <stdint.h>\n"
           "#include <stdbool.h>\n"
           "\n"
           "typedef char CHAR;\n"
           "typedef unsigned char BYTE;\n"
           "typedef short SHORT;\n"
           "typedef unsigned short WORD;\n"
           "typedef int INT;\n"
           "typedef unsigned int DWORD;\n"
           "typedef long long LONGLONG;\n"
           "typedef unsigned long long ULONGLONG;\n"
           "typedef void* HANDLE;\n"
           "\n";
}

} // namespace dc::cgen
