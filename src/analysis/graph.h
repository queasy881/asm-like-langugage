// Generic directed-graph algorithms used by both the machine CFG and the IR:
// orderings, dominators, post-dominators, dominance frontiers, natural loops.
#pragma once

#include "support/common.h"

namespace dc {

struct Digraph {
    int entry = 0;
    std::vector<std::vector<int>> succ;
    std::vector<std::vector<int>> pred;

    explicit Digraph(int n = 0) : succ(n), pred(n) {}
    int size() const { return (int)succ.size(); }
    int addNode() {
        succ.emplace_back();
        pred.emplace_back();
        return size() - 1;
    }
    void addEdge(int a, int b) {
        succ[a].push_back(b);
        pred[b].push_back(a);
    }
    Digraph reversed(int newEntry) const;
};

// Reverse post-order of nodes reachable from the entry.
std::vector<int> reversePostOrder(const Digraph& g);
std::vector<bool> reachableFrom(const Digraph& g, int start);

class DomTree {
public:
    // Builds the (post)dominator tree over nodes reachable from g.entry.
    static DomTree build(const Digraph& g);

    int idom(int n) const { return idom_[n]; }       // -1 for root / unreachable
    bool reachable(int n) const { return pre_[n] >= 0; }
    bool dominates(int a, int b) const;               // reflexive
    bool strictlyDominates(int a, int b) const { return a != b && dominates(a, b); }
    const std::vector<int>& children(int n) const { return children_[n]; }
    const std::vector<int>& rpo() const { return rpo_; }
    int root() const { return root_; }
    int size() const { return (int)idom_.size(); }
    // Nearest common dominator.
    int commonDominator(int a, int b) const;
    // Dominance frontier of every node.
    std::vector<std::vector<int>> frontiers(const Digraph& g) const;
    int depth(int n) const { return depth_[n]; }

private:
    int root_ = 0;
    std::vector<int> idom_;
    std::vector<int> rpo_;
    std::vector<int> rpoIndex_;
    std::vector<std::vector<int>> children_;
    std::vector<int> pre_, post_, depth_;
};

struct Loop {
    int header = -1;
    std::vector<int> blocks;     // includes header, sorted
    std::vector<int> latches;    // sources of back edges
    std::vector<int> exits;      // blocks outside the loop targeted from inside (sorted, unique)
    int parent = -1;             // index of enclosing loop, -1 if outermost
    std::vector<int> children;
    int depth = 1;
    bool contains(int b) const;
};

struct LoopInfo {
    std::vector<Loop> loops;
    std::vector<int> innermost;  // per node: innermost loop index or -1
    bool irreducible = false;    // a retreating edge that is not a back edge exists
    std::vector<std::pair<int, int>> irreducibleEdges;

    static LoopInfo build(const Digraph& g, const DomTree& dom);
    int loopOf(int node) const { return node < (int)innermost.size() ? innermost[node] : -1; }
    bool isHeader(int node) const;
};

} // namespace dc
