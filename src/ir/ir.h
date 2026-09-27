// Architecture-independent decompiler IR.
//
// The IR is a value graph in (eventually) SSA form. Every instruction defines
// at most one value, identified by its index. Machine registers exist only in
// the pre-SSA form as explicit ReadLoc/WriteLoc operations on abstract
// locations; SSA construction removes them, and nothing downstream refers to
// registers again.
//
// Design notes that matter for output quality:
//   * IR types carry only a width and a class (int / float / pointer). The
//     semantic C type is recovered separately, so the IR never forces a cast
//     that the source did not perform.
//   * Casts are explicit but minimal: the lifter emits one only when the
//     machine genuinely changes width, and the demanded-bits pass removes
//     those whose result is never observed at the wider width.
//   * Flags are not locations unless they are live across a block boundary;
//     conditions are materialised from the recorded defining operation.
#pragma once

#include "analysis/graph.h"
#include "support/common.h"

#include <array>
#include <deque>
#include <memory>
#include <unordered_map>

namespace dc::ir {

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

enum class TypeKind : u8 { Void, Int, Float, Ptr };

struct Type {
    TypeKind kind = TypeKind::Void;
    u16 bits = 0;

    constexpr Type() = default;
    constexpr Type(TypeKind k, u16 b) : kind(k), bits(b) {}
    static constexpr Type voidTy() { return {TypeKind::Void, 0}; }
    static constexpr Type i(u16 b) { return {TypeKind::Int, b}; }
    static constexpr Type f(u16 b) { return {TypeKind::Float, b}; }
    static constexpr Type ptr(u16 b) { return {TypeKind::Ptr, b}; }
    bool operator==(const Type& o) const { return kind == o.kind && bits == o.bits; }
    bool operator!=(const Type& o) const { return !(*this == o); }
    bool isVoid() const { return kind == TypeKind::Void; }
    bool isInt() const { return kind == TypeKind::Int; }
    bool isFloat() const { return kind == TypeKind::Float; }
    bool isPtr() const { return kind == TypeKind::Ptr; }
    bool isIntLike() const { return kind == TypeKind::Int || kind == TypeKind::Ptr; }
    unsigned bytes() const { return (bits + 7) / 8; }
    std::string str() const;
};

constexpr Type kI1 = Type::i(1);
constexpr Type kI8 = Type::i(8);
constexpr Type kI16 = Type::i(16);
constexpr Type kI32 = Type::i(32);
constexpr Type kI64 = Type::i(64);
constexpr Type kI128 = Type::i(128);
constexpr Type kF32 = Type::f(32);
constexpr Type kF64 = Type::f(64);

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

enum class Op : u8 {
    // Leaves
    Const,        // imm
    Undef,        // an undefined value (never observed by correct code)
    Arg,          // incoming function parameter, aux = parameter index
    EntryValue,   // the value a location held on entry (loc names it)
    GlobalAddr,   // address of a global, imm = VA
    FrameAddr,    // address of a stack object, imm = frame offset (signed)
    Phi,          // one argument per predecessor, in block predecessor order

    // Pre-SSA location access (removed by SSA construction)
    ReadLoc,      // loc
    WriteLoc,     // loc, args[0] = value

    // Integer arithmetic
    Add, Sub, Mul, UDiv, SDiv, URem, SRem,
    And, Or, Xor, Shl, LShr, AShr, Rol, Ror,
    Not, Neg,
    // Wide helpers (result is 2*operand width)
    MulHiU, MulHiS,

    // Comparisons: result is i1
    CmpEq, CmpNe, CmpUlt, CmpUle, CmpUgt, CmpUge, CmpSlt, CmpSle, CmpSgt, CmpSge,

    // Casts
    Trunc, ZExt, SExt, Bitcast, IntToPtr, PtrToInt,

    // Floating point
    FAdd, FSub, FMul, FDiv, FNeg, FAbs, FSqrt, FMin, FMax,
    FCmpEq, FCmpNe, FCmpLt, FCmpLe, FCmpGt, FCmpGe, FCmpUno,
    SIToFP, UIToFP, FPToSI, FPToUI, FPExt, FPTrunc,

    // Memory
    Load,         // args[0] = address
    Store,        // args[0] = address, args[1] = value

    // Selection
    Select,       // args[0] = i1 condition, args[1] = true, args[2] = false

    // Calls
    Call,         // args = arguments; callee in CallInfo
    Intrinsic,    // named opaque operation (bswap, cpuid, unsupported insn, ...)

    // Terminators
    Jump,         // successor 0
    Branch,       // args[0] = i1 condition; successors: true, false
    Switch,       // args[0] = index; successors from the block's edges
    Return,       // args[0] = value (optional)
    Unreachable,  // ud2 / noreturn call fallthrough

    Count
};

const char* opName(Op op);
bool isTerminator(Op op);
bool isCommutative(Op op);
bool isComparison(Op op);
bool isFloatOp(Op op);
bool isCast(Op op);
bool hasSideEffects(Op op); // stores, calls, volatile intrinsics
Op invertComparison(Op op); // CmpEq <-> CmpNe etc.
Op swapComparisonOperands(Op op); // a<b  <->  b>a

// ---------------------------------------------------------------------------
// Abstract locations (pre-SSA only)
// ---------------------------------------------------------------------------

enum class LocKind : u8 {
    None,
    Reg,     // index = x86::Family, sub-register handled by the lifter
    Flag,    // index = FlagBit
    Stack,   // index = stack slot id (see StackFrame)
    Temp,    // index = lifter temporary
};

enum FlagBit : u8 { FlagCF = 0, FlagPF, FlagAF, FlagZF, FlagSF, FlagOF, FlagDF, FlagCount };
const char* flagName(FlagBit f);

struct Loc {
    LocKind kind = LocKind::None;
    u16 index = 0;
    u16 size = 0; // in bytes, for Reg/Stack

    bool operator==(const Loc& o) const { return kind == o.kind && index == o.index && size == o.size; }
    bool valid() const { return kind != LocKind::None; }
    std::string str() const;
    // Key identifying the SSA variable this location belongs to.
    u32 key() const { return ((u32)kind << 24) | (u32)index; }
};

struct LocHash {
    size_t operator()(const Loc& l) const { return ((size_t)l.kind << 32) ^ ((size_t)l.index << 8) ^ l.size; }
};

// ---------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------

using ValueId = u32;
constexpr ValueId kNoValue = 0xFFFFFFFFu;

struct CallInfo {
    u64 target = 0;               // direct callee VA, 0 if indirect
    ValueId indirectTarget = kNoValue;
    std::string name;             // resolved name if known
    bool isImport = false;
    bool noReturn = false;
    bool variadic = false;
    std::vector<Type> paramTypes; // as inferred / known from the API database
    Type returnType = Type::voidTy();
    // Locations the arguments came from, used by argument recovery reporting.
    std::vector<std::string> argNotes;
};

struct Inst {
    Op op = Op::Undef;
    Type type;
    ValueId id = kNoValue;
    int block = -1;
    u64 imm = 0;             // Const value / global VA / frame offset
    u32 aux = 0;             // arg index, memory access size, intrinsic id
    u64 addr = 0;            // machine address this came from (provenance)
    Loc loc;                 // ReadLoc / WriteLoc
    std::vector<ValueId> args;
    std::unique_ptr<CallInfo> call;
    std::string text;        // intrinsic name / comment
    bool dead = false;

    bool isTerminator() const { return ir::isTerminator(op); }
    bool definesValue() const { return !type.isVoid(); }
};

// ---------------------------------------------------------------------------
// Blocks and functions
// ---------------------------------------------------------------------------

struct Block {
    int id = -1;
    u64 addr = 0;                 // machine address of the first instruction
    std::vector<ValueId> insts;   // in order; terminator last
    std::vector<int> preds;
    std::vector<int> succs;
    // Switch case labels parallel to succs (empty for non-switch blocks).
    std::vector<std::vector<i64>> caseValues;
    int defaultSucc = -1;
    std::string label;
};

class Function {
public:
    explicit Function(std::string name = {}) : name_(std::move(name)) {}

    const std::string& name() const { return name_; }
    void setName(std::string n) { name_ = std::move(n); }
    u64 entryAddr() const { return entryAddr_; }
    void setEntryAddr(u64 a) { entryAddr_ = a; }

    int addBlock(u64 addr = 0);
    int blockCount() const { return (int)blocks_.size(); }
    Block& block(int i) { return blocks_[i]; }
    const Block& block(int i) const { return blocks_[i]; }
    std::vector<Block>& blocks() { return blocks_; }
    const std::vector<Block>& blocks() const { return blocks_; }
    int entryBlock() const { return 0; }

    // Instruction creation. The instruction is appended to `block` unless
    // `before` names an insertion point.
    ValueId add(int block, Inst inst);
    ValueId insertBefore(ValueId anchor, Inst inst);
    Inst& inst(ValueId v) { return insts_[v]; }
    const Inst& inst(ValueId v) const { return insts_[v]; }
    size_t instCount() const { return insts_.size(); }
    bool valid(ValueId v) const { return v < insts_.size(); }

    // Convenience builders.
    ValueId constInt(int block, Type t, u64 value, u64 addr = 0);
    ValueId undef(int block, Type t);
    ValueId binary(int block, Op op, Type t, ValueId a, ValueId b, u64 addr = 0);
    ValueId unary(int block, Op op, Type t, ValueId a, u64 addr = 0);
    ValueId cast(int block, Op op, Type t, ValueId a, u64 addr = 0);
    ValueId load(int block, Type t, ValueId addrVal, u64 addr = 0);
    ValueId store(int block, ValueId addrVal, ValueId value, u64 addr = 0);
    ValueId readLoc(int block, Loc l, Type t, u64 addr = 0);
    ValueId writeLoc(int block, Loc l, ValueId value, u64 addr = 0);

    void addEdge(int from, int to);
    void setSuccessors(int block, std::vector<int> succs);
    // Rebuilds predecessor lists (and phi argument order) from succs.
    void recomputePreds();

    // Removes instructions marked dead and compacts block instruction lists.
    void removeDeadInsts();
    // Drops blocks not reachable from the entry, renumbering the rest.
    void pruneUnreachableBlocks();
    // The CFG as a generic digraph (block ids match).
    Digraph cfg() const;
    void replaceAllUses(ValueId from, ValueId to);
    // All users of a value. Recomputed on demand (analysis passes cache it).
    std::unordered_map<ValueId, std::vector<ValueId>> buildUses() const;

    // Parameters (filled by calling-convention recovery).
    struct Param {
        std::string name;
        Type type;
        ValueId value = kNoValue; // the Arg instruction
        std::string location;     // e.g. "rcx", "stack+0x28" (debug only)
        bool used = false;
    };
    std::vector<Param>& params() { return params_; }
    const std::vector<Param>& params() const { return params_; }
    Type& returnType() { return returnType_; }
    const Type& returnType() const { return returnType_; }
    bool& variadic() { return variadic_; }
    bool variadic() const { return variadic_; }

    // Diagnostics recorded during lifting (unsupported instructions etc).
    std::vector<std::string>& notes() { return notes_; }
    const std::vector<std::string>& notes() const { return notes_; }

    std::string print(bool withAddresses = true) const;
    // Structural validation; returns the list of problems found.
    std::vector<std::string> verify() const;

private:
    std::string name_;
    u64 entryAddr_ = 0;
    std::vector<Block> blocks_;
    std::deque<Inst> insts_;
    std::vector<Param> params_;
    Type returnType_ = Type::voidTy();
    bool variadic_ = false;
    std::vector<std::string> notes_;
};

std::string valueName(ValueId v);

} // namespace dc::ir
