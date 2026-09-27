// High-level AST.
//
// This is the shape the C backend prints. It holds no registers, no SSA
// values and no basic blocks - only the constructs a C programmer writes.
#pragma once

#include "types/type_system.h"

#include <memory>
#include <string>
#include <vector>

namespace dc::ast {

// --- expressions -----------------------------------------------------------

enum class ExprKind : u8 {
    IntConst,
    FloatConst,
    StringLit,
    VarRef,
    GlobalRef,
    FuncRef,
    Unary,
    Binary,
    Ternary,
    Call,
    Cast,
    Deref,      // *p
    AddrOf,     // &x
    Member,     // p->field  /  x.field
    Index,      // a[i]
    Undefined,  // a value the analysis could not recover
    Raw,        // verbatim text, for intrinsics
};

enum class UnOp : u8 { Neg, Not, LogicalNot, Plus };
enum class BinOp : u8 {
    Add, Sub, Mul, Div, Mod,
    And, Or, Xor, Shl, Shr,
    Eq, Ne, Lt, Le, Gt, Ge,
    LogicalAnd, LogicalOr,
    Comma,
};

const char* unOpText(UnOp op);
const char* binOpText(BinOp op);
// C operator precedence; higher binds tighter.
int precedenceOf(BinOp op);
int unaryPrecedence();
bool isRightAssociative(BinOp op);

struct Expr;
using ExprPtr = std::unique_ptr<Expr>;

struct Expr {
    ExprKind kind = ExprKind::Undefined;
    types::TypeRef type = nullptr;

    // IntConst / FloatConst
    u64 intValue = 0;
    double floatValue = 0;
    bool isSignedConst = true;
    std::string constName;       // a recognised constant printed by name
    // StringLit
    std::string text;            // also Raw, VarRef name, Member field name
    bool wide = false;
    // VarRef / GlobalRef / FuncRef
    int varId = -1;
    u64 address = 0;
    // operators
    UnOp unOp = UnOp::Neg;
    BinOp binOp = BinOp::Add;
    std::vector<ExprPtr> args;   // operands, call arguments
    bool arrow = false;          // Member: -> rather than .
    bool rawIsCall = false;      // Raw: print as name(), even with no arguments
    u64 memberOffset = 0;

    static ExprPtr intConst(types::TypeRef t, u64 v, bool isSigned = true);
    static ExprPtr floatConst(types::TypeRef t, double v);
    static ExprPtr stringLit(types::TypeRef t, std::string s, bool wide);
    static ExprPtr var(types::TypeRef t, int id, std::string name);
    static ExprPtr global(types::TypeRef t, u64 addr, std::string name);
    static ExprPtr func(types::TypeRef t, u64 addr, std::string name);
    static ExprPtr unary(types::TypeRef t, UnOp op, ExprPtr a);
    static ExprPtr binary(types::TypeRef t, BinOp op, ExprPtr a, ExprPtr b);
    static ExprPtr ternary(types::TypeRef t, ExprPtr c, ExprPtr a, ExprPtr b);
    static ExprPtr call(types::TypeRef t, ExprPtr callee, std::vector<ExprPtr> args);
    static ExprPtr cast(types::TypeRef t, ExprPtr a);
    static ExprPtr deref(types::TypeRef t, ExprPtr a);
    static ExprPtr addrOf(types::TypeRef t, ExprPtr a);
    static ExprPtr member(types::TypeRef t, ExprPtr base, std::string field, bool arrow, u64 offset);
    static ExprPtr index(types::TypeRef t, ExprPtr base, ExprPtr idx);
    static ExprPtr undefined(types::TypeRef t);
    static ExprPtr raw(types::TypeRef t, std::string text, std::vector<ExprPtr> args = {},
                       bool isCall = false);

    ExprPtr clone() const;
    bool isIntConst(u64 v) const { return kind == ExprKind::IntConst && intValue == v; }
    bool isSimple() const;  // needs no parentheses in any context
};

// --- statements ------------------------------------------------------------

enum class StmtKind : u8 {
    Compound, Decl, ExprStmt, Assign, If, While, DoWhile, For, Switch,
    Return, Break, Continue, Goto, Label, Comment, Empty,
};

struct Stmt;
using StmtPtr = std::unique_ptr<Stmt>;

struct SwitchCase {
    std::vector<i64> values;   // empty means default
    StmtPtr body;
    bool fallsThrough = false;
};

struct Stmt {
    StmtKind kind = StmtKind::Empty;

    std::vector<StmtPtr> body;     // Compound
    ExprPtr expr;                  // ExprStmt / Return / Switch / If / While condition
    ExprPtr lhs, rhs;              // Assign
    StmtPtr thenBranch, elseBranch;
    StmtPtr loopBody;
    StmtPtr init, step;            // For
    std::vector<SwitchCase> cases;
    std::string label;             // Goto / Label
    std::string text;              // Comment
    // Decl
    int varId = -1;
    types::TypeRef declType = nullptr;
    std::string declName;
    ExprPtr declInit;
    bool isConst = false;
    u64 address = 0;               // provenance

    static StmtPtr compound(std::vector<StmtPtr> body);
    static StmtPtr exprStmt(ExprPtr e);
    static StmtPtr assign(ExprPtr lhs, ExprPtr rhs);
    static StmtPtr decl(int varId, types::TypeRef t, std::string name, ExprPtr init, bool isConst);
    static StmtPtr ifStmt(ExprPtr cond, StmtPtr thenB, StmtPtr elseB);
    static StmtPtr whileStmt(ExprPtr cond, StmtPtr body);
    static StmtPtr doWhile(StmtPtr body, ExprPtr cond);
    static StmtPtr forStmt(StmtPtr init, ExprPtr cond, StmtPtr step, StmtPtr body);
    static StmtPtr switchStmt(ExprPtr value, std::vector<SwitchCase> cases);
    static StmtPtr ret(ExprPtr value);
    static StmtPtr brk();
    static StmtPtr cont();
    static StmtPtr gotoStmt(std::string label);
    static StmtPtr labelStmt(std::string label);
    static StmtPtr comment(std::string text);
    static StmtPtr empty();

    bool isEmpty() const;
};

// --- function --------------------------------------------------------------

struct Param {
    types::TypeRef type = nullptr;
    std::string name;
    bool used = true;
};

struct Function {
    std::string name;
    u64 address = 0;
    types::TypeRef returnType = nullptr;
    std::vector<Param> params;
    bool variadic = false;
    std::string convention;          // empty for the default
    StmtPtr body;
    std::vector<StmtPtr> declarations;  // variables declared at the top
    types::Confidence confidence = types::Confidence::Medium;
    std::vector<std::string> notes;
    int gotoCount = 0;
};

} // namespace dc::ast
