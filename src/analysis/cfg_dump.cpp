#include "analysis/cfg_dump.h"

#include <sstream>

namespace dc {

std::string dumpFunctionList(const Program& prog) {
    std::ostringstream os;
    size_t n = 0;
    for (const auto& [va, f] : prog.functions())
        if (!f->isImportThunk) ++n;
    os << "Functions discovered: " << n << "\n";
    for (const auto& [va, f] : prog.functions()) {
        if (f->isImportThunk) continue;
        os << "\nFunction " << f->name << " @ " << hex(va);
        if (!f->returns) os << " [noreturn]";
        if (f->isThunk) os << " [thunk -> " << prog.nameForAddress(f->thunkTarget) << "]";
        if (f->hasUnresolvedIndirect) os << " [unresolved indirect jump]";
        if (f->hasDecodeErrors) os << " [decode errors]";
        os << "\n";
        for (const auto& b : f->blocks) os << "    Block " << hex(b.start) << "\n";
    }
    return os.str();
}

std::string dumpFunctionBlocks(const Function& f, bool withInstructions) {
    std::ostringstream os;
    for (const auto& b : f.blocks) {
        os << "  Block " << hex(b.start) << "  (" << terminatorName(b.term) << ")\n";
        if (withInstructions)
            for (const auto& in : b.insns) os << "    " << hex(in.address) << ": " << in.text() << "\n";
    }
    return os.str();
}

std::string dumpCfg(const Program& prog, const Function& f) {
    std::ostringstream os;
    Digraph g = f.graph(true);
    DomTree dom = DomTree::build(g);
    Digraph rg = g.reversed(f.exitNode());
    DomTree pdom = DomTree::build(rg);
    LoopInfo loops = LoopInfo::build(g, dom);
    auto blockName = [&](int id) -> std::string {
        if (id == f.exitNode()) return "EXIT";
        return "Block " + hex(f.blocks[id].start);
    };

    os << "Function " << f.name << " @ " << hex(f.entry) << "\n";
    os << "  blocks: " << f.blocks.size() << ", instructions: " << f.instructionCount()
       << ", loops: " << loops.loops.size() << (loops.irreducible ? " (irreducible)" : "") << "\n\n";
    for (const auto& b : f.blocks) {
        os << blockName(b.id);
        if (b.id == 0) os << " (entry)";
        os << "  [" << terminatorName(b.term) << "]";
        if (int li = loops.loopOf(b.id); li >= 0) {
            os << "  loop#" << li;
            if (loops.loops[li].header == b.id) os << " header";
        }
        os << "\n";
        if (dom.idom(b.id) >= 0) os << " │ idom: " << blockName(dom.idom(b.id)) << "\n";
        if (pdom.reachable(b.id) && pdom.idom(b.id) >= 0) os << " │ ipdom: " << blockName(pdom.idom(b.id)) << "\n";
        for (const auto& cs : b.calls) {
            os << " │ call " << hex(cs.address) << " → ";
            if (cs.import) os << cs.import->displayName();
            else if (cs.indirect) os << "<indirect>";
            else os << prog.nameForAddress(cs.target);
            if (cs.noReturn) os << " [noreturn]";
            os << "\n";
        }
        std::vector<std::string> lines;
        for (const auto& e : b.succs) {
            std::string label = edgeKindName(e.kind);
            std::string line;
            if (e.kind == EdgeKind::Switch) {
                std::string cases;
                for (size_t i = 0; i < e.caseValues.size(); ++i) {
                    if (i) cases += ",";
                    if (i >= 8) { cases += "..."; break; }
                    cases += std::to_string(e.caseValues[i]);
                }
                line = "case " + cases + " → " + blockName(e.target);
            } else if (e.kind == EdgeKind::Return) {
                line = "return → EXIT";
            } else if (e.kind == EdgeKind::Fallthrough || e.kind == EdgeKind::Jump) {
                line = "→ " + blockName(e.target);
            } else {
                label.resize(5, ' ');
                line = label + " → " + blockName(e.target);
            }
            lines.push_back(line);
        }
        if (b.term == Terminator::TailCall) {
            std::string t = b.tailImport ? b.tailImport->displayName()
                            : b.tailTarget ? prog.nameForAddress(b.tailTarget) : "<indirect>";
            lines.push_back("tail call → " + t);
        }
        if (b.term == Terminator::Switch && b.jumpTable >= 0) {
            const JumpTable& jt = f.jumpTables[b.jumpTable];
            if (jt.defaultTarget) lines.insert(lines.begin(), "(default via bounds check → Block " + hex(jt.defaultTarget) + ")");
        }
        for (size_t i = 0; i < lines.size(); ++i)
            os << (i + 1 == lines.size() ? " └── " : " ├── ") << lines[i] << "\n";
        os << "\n";
    }
    for (size_t i = 0; i < loops.loops.size(); ++i) {
        const Loop& l = loops.loops[i];
        os << "loop#" << i << ": header " << blockName(l.header) << ", depth " << l.depth << ", " << l.blocks.size()
           << " blocks, latches:";
        for (int x : l.latches) os << " " << hex(f.blocks[x].start);
        os << ", exits:";
        for (int x : l.exits) os << " " << (x == f.exitNode() ? std::string("EXIT") : hex(f.blocks[x].start));
        os << "\n";
    }
    return os.str();
}

} // namespace dc
