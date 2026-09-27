#include "test_framework.h"

#include "analysis/graph.h"
#include "analysis/program.h"

#include <algorithm>

using namespace dc;

TEST(graph_dominators_diamond) {
    // 0 -> 1,2 ; 1,2 -> 3
    Digraph g(4);
    g.addEdge(0, 1); g.addEdge(0, 2); g.addEdge(1, 3); g.addEdge(2, 3);
    DomTree d = DomTree::build(g);
    CHECK_EQ(d.idom(1), 0);
    CHECK_EQ(d.idom(2), 0);
    CHECK_EQ(d.idom(3), 0);
    CHECK(d.dominates(0, 3));
    CHECK(!d.dominates(1, 3));
    auto df = d.frontiers(g);
    CHECK(df[1].size() == 1 && df[1][0] == 3);
    CHECK(df[2].size() == 1 && df[2][0] == 3);
    CHECK(df[0].empty());
    // Post-dominators via the reversed graph.
    DomTree pd = DomTree::build(g.reversed(3));
    CHECK_EQ(pd.idom(0), 3);
    CHECK_EQ(pd.idom(1), 3);
}

TEST(graph_loops_nested) {
    // 0 -> 1 ; 1 -> 2 ; 2 -> 2 (self loop), 2 -> 3 ; 3 -> 1, 3 -> 4
    Digraph g(5);
    g.addEdge(0, 1); g.addEdge(1, 2); g.addEdge(2, 2); g.addEdge(2, 3); g.addEdge(3, 1); g.addEdge(3, 4);
    DomTree d = DomTree::build(g);
    LoopInfo li = LoopInfo::build(g, d);
    CHECK_EQ(li.loops.size(), (size_t)2);
    CHECK(!li.irreducible);
    int outer = -1, inner = -1;
    for (int i = 0; i < 2; ++i) (li.loops[i].header == 1 ? outer : inner) = i;
    REQUIRE(outer >= 0 && inner >= 0);
    CHECK_EQ(li.loops[inner].header, 2);
    CHECK_EQ(li.loops[inner].parent, outer);
    CHECK_EQ(li.loops[inner].depth, 2);
    CHECK_EQ(li.loopOf(2), inner);
    CHECK_EQ(li.loopOf(3), outer);
    CHECK_EQ(li.loopOf(4), -1);
    CHECK(li.loops[outer].exits == std::vector<int>{4});
}

TEST(graph_irreducible_detection) {
    // 0 -> 1, 0 -> 2, 1 <-> 2 : two-entry cycle.
    Digraph g(3);
    g.addEdge(0, 1); g.addEdge(0, 2); g.addEdge(1, 2); g.addEdge(2, 1);
    DomTree d = DomTree::build(g);
    LoopInfo li = LoopInfo::build(g, d);
    CHECK(li.irreducible);
    CHECK(li.loops.empty());
}

static Program& corpus() {
    static std::unique_ptr<Program> p = [] {
        auto prog = std::make_unique<Program>(pe::Image::loadFile(dctest::corpusPath("behemoth.dll")));
        prog->discoverFunctions();
        return prog;
    }();
    return *p;
}

static const Function* byName(const char* name) {
    for (const auto& [va, f] : corpus().functions())
        if (f->name == name) return f.get();
    return nullptr;
}

TEST(discovery_finds_all_exports) {
    const auto& img = corpus().image();
    for (const auto& e : img.exports()) {
        const Function* f = corpus().functionAt(img.rvaToVa(e.rva));
        CHECK(f != nullptr);
        if (f) CHECK_EQ(f->name, e.name);
    }
}

TEST(discovery_fnv1a_blocks) {
    const Function* f = byName("fnv1a_hash");
    REQUIRE(f);
    // test/je, loop pre-header, loop body, ret, empty-input return.
    CHECK_EQ(f->blocks.size(), (size_t)5);
    CHECK_EQ(f->blocks[0].start, 0x2D6311390ull);
    CHECK(f->blocks[0].term == Terminator::Branch);
    Digraph g = f->graph(true);
    DomTree d = DomTree::build(g);
    LoopInfo li = LoopInfo::build(g, d);
    CHECK_EQ(li.loops.size(), (size_t)1);
    int loopBlock = f->blockAt.at(0x2D63113A0ull);
    CHECK_EQ(li.loops[0].header, loopBlock);
    int returns = 0;
    for (const auto& b : f->blocks) returns += b.term == Terminator::Return;
    CHECK_EQ(returns, 2);
}

TEST(discovery_vm_exec_jump_table) {
    const Function* f = byName("vm_exec");
    REQUIRE(f);
    CHECK(!f->hasUnresolvedIndirect);
    REQUIRE(f->jumpTables.size() == 1);
    const JumpTable& jt = f->jumpTables[0];
    CHECK(jt.bounded);
    CHECK_EQ(jt.targets.size(), (size_t)16);
    CHECK(jt.relative);
    CHECK_EQ(jt.tableAddress, 0x2D6316000ull);
    CHECK(jt.indexFamily == x86::Family::F_RAX);
    CHECK_EQ(jt.defaultTarget, 0x2D6311C93ull);
    int sw = f->blockContaining(0x2D63119A7ull);
    REQUIRE(sw >= 0);
    CHECK(f->blocks[sw].term == Terminator::Switch);
    size_t cases = 0;
    for (const auto& e : f->blocks[sw].succs) cases += e.caseValues.size();
    CHECK_EQ(cases, (size_t)16);
}

TEST(discovery_calls_and_thunks) {
    const Function* enc = byName("encode_packet");
    REQUIRE(enc);
    bool sawMemcpy = false;
    for (const auto& b : enc->blocks)
        for (const auto& c : b.calls)
            if (c.import && c.import->name == "memcpy") sawMemcpy = true;
    CHECK(sawMemcpy);
    const Function* td = byName("tree_depth");
    REQUIRE(td);
    CHECK(td->callees.count(td->entry)); // recursion
    CHECK(td->returns);
}

TEST(discovery_noreturn_propagation) {
    // __report_error ends in abort(); callers must not fall through the call.
    const Function* rep = byName("__report_error");
    REQUIRE(rep);
    CHECK(!rep->returns);
}
