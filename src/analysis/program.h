// Program database: the loaded image, decoded instructions and every
// discovered function with its basic blocks and control-flow graph.
#pragma once

#include "analysis/graph.h"
#include "arch/x86/x86.h"
#include "disasm/disassembler.h"
#include "pe/pe_image.h"

#include <map>
#include <memory>
#include <set>
#include <unordered_map>

namespace dc {

enum class EdgeKind : u8 {
    Fallthrough,   // sequential flow into a leader
    True,          // conditional branch taken
    False,         // conditional branch not taken
    Jump,          // unconditional direct jump
    Switch,        // jump-table case (see caseValues)
    Return,        // to the virtual exit node
};
const char* edgeKindName(EdgeKind k);

struct CfgEdge {
    int target = -1;
    EdgeKind kind = EdgeKind::Fallthrough;
    std::vector<i64> caseValues; // Switch edges: indices that select this target
    bool isDefault = false;      // Switch edge taken when the index is out of range
};

struct CallSite {
    u64 address = 0;               // address of the call instruction
    u64 target = 0;                // direct target (0 if indirect)
    const pe::Import* import = nullptr; // resolved import (direct thunk or call [iat])
    bool indirect = false;
    bool noReturn = false;
};

struct JumpTable {
    u64 jumpAddress = 0;     // the indirect jmp
    u64 loadAddress = 0;     // instruction that reads the table
    x86::Family indexFamily = x86::Family::None; // register holding the case index
    // Address of the instruction that leaves the index in indexFamily. The
    // index must be read right after it, because later instructions reuse the
    // register for the table base. Zero means "at the start of the block".
    u64 indexAddress = 0;
    u64 tableAddress = 0;
    unsigned entrySize = 4;
    bool relative = false;   // entries are offsets added to relativeBase
    u64 relativeBase = 0;
    bool bounded = false;    // count came from a bounds check
    u64 defaultTarget = 0;   // taken when the bounds check fails (0 = unknown)
    std::vector<u64> targets; // target for index 0..n-1
};

enum class Terminator : u8 {
    Fallthrough,    // falls into the next block
    Branch,         // conditional jump
    Jump,           // direct jump inside the function
    Switch,         // resolved jump table
    IndirectJump,   // unresolved indirect jump
    Return,
    TailCall,       // jump to another function / import
    NoReturnCall,   // call that never returns
    Halt,           // hlt/ud2/int3
    DecodeError,    // ran into undecodable bytes
};
const char* terminatorName(Terminator t);

struct BasicBlock {
    int id = -1;
    u64 start = 0;
    u64 end = 0; // one past the last instruction
    std::vector<x86::Instruction> insns;
    std::vector<CfgEdge> succs;
    std::vector<int> preds;
    std::vector<CallSite> calls;
    Terminator term = Terminator::Fallthrough;
    u64 tailTarget = 0;                  // TailCall target (0 if indirect)
    const pe::Import* tailImport = nullptr;
    int jumpTable = -1;                  // index into Function::jumpTables

    const x86::Instruction& last() const { return insns.back(); }
};

struct Function {
    u64 entry = 0;
    std::string name;
    std::vector<BasicBlock> blocks; // blocks[0] is the entry block
    std::map<u64, int> blockAt;     // start address -> block index
    std::vector<JumpTable> jumpTables;
    std::set<u64> callees;
    bool returns = true;            // false if no path reaches a return
    bool isImportThunk = false;
    const pe::Import* thunkImport = nullptr;
    bool isThunk = false;           // single jmp to another function
    u64 thunkTarget = 0;
    bool hasUnresolvedIndirect = false;
    bool hasDecodeErrors = false;
    bool fromExport = false;

    int blockContaining(u64 addr) const;
    int exitNode() const { return (int)blocks.size(); }
    // CFG as a graph; with the virtual exit node appended when withExit.
    Digraph graph(bool withExit = true) const;
    size_t instructionCount() const;
};

class Program {
public:
    explicit Program(std::unique_ptr<pe::Image> image);
    ~Program();

    const pe::Image& image() const { return *image_; }
    bool is64() const { return image_->is64(); }
    unsigned pointerSize() const { return is64() ? 8 : 4; }
    Disassembler& disassembler() { return *dis_; }

    // Cached decoding; nullptr for invalid / unmapped addresses.
    const x86::Instruction* instructionAt(u64 va);

    // Step 2/3: discover functions, blocks and CFGs.
    void discoverFunctions();
    // Ensures a function exists at va (e.g. requested on the command line).
    Function* ensureFunction(u64 va);

    const std::map<u64, std::unique_ptr<Function>>& functions() const { return functions_; }
    Function* functionAt(u64 va);
    const Function* functionAt(u64 va) const;
    const Function* functionContaining(u64 va) const;

    // Naming.
    std::string nameForAddress(u64 va) const;
    std::optional<std::string> symbolName(u64 va) const;

    // Imports reached through a call/jmp operand: "call [rip+X]" or a
    // direct call to a "jmp [iat]" thunk.
    const pe::Import* importForIat(u64 iatVa) const { return image_->importByIat(iatVa); }
    const pe::Import* importViaThunk(u64 target) const;

    bool isNoReturnImport(const pe::Import* imp) const;
    bool isNoReturnTarget(u64 target) const;

private:
    std::unique_ptr<Function> buildFunction(u64 entry);
    bool resolveJumpTable(const std::map<u64, const x86::Instruction*>& insns, const x86::Instruction& jmp, JumpTable& out);
    void collectSeeds();
    void computeReturns();

    std::unique_ptr<pe::Image> image_;
    std::unique_ptr<Disassembler> dis_;
    std::unordered_map<u64, std::unique_ptr<x86::Instruction>> insnCache_;
    std::map<u64, std::unique_ptr<Function>> functions_;
    std::set<u64> knownEntries_;      // all function entries known so far
    std::set<u64> noReturnFunctions_;
    std::map<u64, std::string> symbols_;
    std::vector<std::pair<u32, u32>> pdataRanges_; // sorted [begin, end) RVAs
    std::map<u64, const pe::Import*> importThunks_; // thunk address -> import
};

} // namespace dc
