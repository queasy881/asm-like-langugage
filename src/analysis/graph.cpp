#include "analysis/graph.h"

#include <algorithm>
#include <functional>
#include <map>

namespace dc {

Digraph Digraph::reversed(int newEntry) const {
    Digraph r(size());
    r.entry = newEntry;
    for (int a = 0; a < size(); ++a)
        for (int b : succ[a]) r.addEdge(b, a);
    return r;
}

std::vector<int> reversePostOrder(const Digraph& g) {
    std::vector<int> order;
    if (g.size() == 0) return order;
    std::vector<char> state(g.size(), 0);
    // Iterative DFS to survive very large functions.
    std::vector<std::pair<int, size_t>> stack;
    stack.push_back({g.entry, 0});
    state[g.entry] = 1;
    while (!stack.empty()) {
        auto& [n, i] = stack.back();
        if (i < g.succ[n].size()) {
            int s = g.succ[n][i++];
            if (!state[s]) {
                state[s] = 1;
                stack.push_back({s, 0});
            }
        } else {
            order.push_back(n);
            stack.pop_back();
        }
    }
    std::reverse(order.begin(), order.end());
    return order;
}

std::vector<bool> reachableFrom(const Digraph& g, int start) {
    std::vector<bool> seen(g.size(), false);
    if (start < 0 || start >= g.size()) return seen;
    std::vector<int> work{start};
    seen[start] = true;
    while (!work.empty()) {
        int n = work.back();
        work.pop_back();
        for (int s : g.succ[n])
            if (!seen[s]) { seen[s] = true; work.push_back(s); }
    }
    return seen;
}

DomTree DomTree::build(const Digraph& g) {
    DomTree t;
    int n = g.size();
    t.root_ = g.entry;
    t.idom_.assign(n, -1);
    t.children_.assign(n, {});
    t.pre_.assign(n, -1);
    t.post_.assign(n, -1);
    t.depth_.assign(n, 0);
    t.rpoIndex_.assign(n, -1);
    if (n == 0) return t;
    t.rpo_ = reversePostOrder(g);
    for (size_t i = 0; i < t.rpo_.size(); ++i) t.rpoIndex_[t.rpo_[i]] = (int)i;

    // Cooper, Harvey, Kennedy: "A Simple, Fast Dominance Algorithm".
    std::vector<int> doms(n, -1);
    doms[g.entry] = g.entry;
    auto intersect = [&](int a, int b) {
        while (a != b) {
            while (t.rpoIndex_[a] > t.rpoIndex_[b]) a = doms[a];
            while (t.rpoIndex_[b] > t.rpoIndex_[a]) b = doms[b];
        }
        return a;
    };
    bool changed = true;
    while (changed) {
        changed = false;
        for (int b : t.rpo_) {
            if (b == g.entry) continue;
            int newIdom = -1;
            for (int p : g.pred[b]) {
                if (t.rpoIndex_[p] < 0 || doms[p] < 0) continue;
                newIdom = newIdom < 0 ? p : intersect(p, newIdom);
            }
            if (newIdom >= 0 && doms[b] != newIdom) {
                doms[b] = newIdom;
                changed = true;
            }
        }
    }
    for (int b : t.rpo_) {
        if (b == g.entry) continue;
        t.idom_[b] = doms[b];
        if (doms[b] >= 0) t.children_[doms[b]].push_back(b);
    }
    for (auto& c : t.children_)
        std::sort(c.begin(), c.end(), [&](int a, int b) { return t.rpoIndex_[a] < t.rpoIndex_[b]; });
    // Pre/post numbering of the dominator tree for O(1) dominance queries.
    int counter = 0;
    std::vector<std::pair<int, size_t>> stack{{g.entry, 0}};
    t.pre_[g.entry] = counter++;
    while (!stack.empty()) {
        auto& [node, i] = stack.back();
        if (i < t.children_[node].size()) {
            int c = t.children_[node][i++];
            t.pre_[c] = counter++;
            t.depth_[c] = t.depth_[node] + 1;
            stack.push_back({c, 0});
        } else {
            t.post_[node] = counter++;
            stack.pop_back();
        }
    }
    return t;
}

bool DomTree::dominates(int a, int b) const {
    if (a < 0 || b < 0 || a >= size() || b >= size()) return false;
    if (pre_[a] < 0 || pre_[b] < 0) return false;
    return pre_[a] <= pre_[b] && post_[b] <= post_[a];
}

int DomTree::commonDominator(int a, int b) const {
    if (a < 0) return b;
    if (b < 0) return a;
    while (!dominates(a, b)) {
        a = idom_[a];
        if (a < 0) return root_;
    }
    return a;
}

std::vector<std::vector<int>> DomTree::frontiers(const Digraph& g) const {
    std::vector<std::vector<int>> df(g.size());
    for (int b = 0; b < g.size(); ++b) {
        if (!reachable(b)) continue;
        int reachablePreds = 0;
        for (int p : g.pred[b])
            if (reachable(p)) ++reachablePreds;
        if (reachablePreds < 2) continue;
        for (int p : g.pred[b]) {
            if (!reachable(p)) continue;
            int runner = p;
            while (runner >= 0 && runner != idom_[b]) {
                auto& v = df[runner];
                if (v.empty() || v.back() != b) {
                    if (std::find(v.begin(), v.end(), b) == v.end()) v.push_back(b);
                }
                runner = idom_[runner];
            }
        }
    }
    return df;
}

bool Loop::contains(int b) const { return std::binary_search(blocks.begin(), blocks.end(), b); }

bool LoopInfo::isHeader(int node) const {
    for (const auto& l : loops)
        if (l.header == node) return true;
    return false;
}

LoopInfo LoopInfo::build(const Digraph& g, const DomTree& dom) {
    LoopInfo li;
    int n = g.size();
    li.innermost.assign(n, -1);
    // Collect back edges grouped by header.
    std::map<int, std::vector<int>> backEdges;
    for (int u = 0; u < n; ++u) {
        if (!dom.reachable(u)) continue;
        for (int h : g.succ[u])
            if (dom.dominates(h, u)) backEdges[h].push_back(u);
    }
    // Detect irreducibility: retreating DFS edges that are not back edges.
    {
        std::vector<int> rpoIdx(n, -1);
        const auto& rpo = dom.rpo();
        for (size_t i = 0; i < rpo.size(); ++i) rpoIdx[rpo[i]] = (int)i;
        for (int u = 0; u < n; ++u) {
            if (rpoIdx[u] < 0) continue;
            for (int v : g.succ[u]) {
                if (rpoIdx[v] >= 0 && rpoIdx[v] <= rpoIdx[u] && !dom.dominates(v, u)) {
                    li.irreducible = true;
                    li.irreducibleEdges.push_back({u, v});
                }
            }
        }
    }
    for (auto& [h, latches] : backEdges) {
        Loop l;
        l.header = h;
        l.latches = latches;
        std::vector<bool> in(n, false);
        in[h] = true;
        std::vector<int> work;
        for (int u : latches)
            if (!in[u]) { in[u] = true; work.push_back(u); }
        while (!work.empty()) {
            int x = work.back();
            work.pop_back();
            for (int p : g.pred[x])
                if (!in[p] && dom.reachable(p)) { in[p] = true; work.push_back(p); }
        }
        for (int b = 0; b < n; ++b)
            if (in[b]) l.blocks.push_back(b);
        std::vector<int> exits;
        for (int b : l.blocks)
            for (int s : g.succ[b])
                if (!in[s]) exits.push_back(s);
        std::sort(exits.begin(), exits.end());
        exits.erase(std::unique(exits.begin(), exits.end()), exits.end());
        l.exits = std::move(exits);
        li.loops.push_back(std::move(l));
    }
    // Nesting: a loop's parent is the smallest loop strictly containing its header set.
    std::vector<int> order(li.loops.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = (int)i;
    std::sort(order.begin(), order.end(), [&](int a, int b) { return li.loops[a].blocks.size() > li.loops[b].blocks.size(); });
    for (int idx : order) {
        Loop& l = li.loops[idx];
        int best = -1;
        for (int other = 0; other < (int)li.loops.size(); ++other) {
            if (other == idx) continue;
            const Loop& o = li.loops[other];
            if (o.blocks.size() <= l.blocks.size()) continue;
            if (!o.contains(l.header)) continue;
            if (best < 0 || li.loops[best].blocks.size() > o.blocks.size()) best = other;
        }
        l.parent = best;
    }
    for (int i = 0; i < (int)li.loops.size(); ++i)
        if (li.loops[i].parent >= 0) li.loops[li.loops[i].parent].children.push_back(i);
    for (int idx : order) { // outer loops first
        Loop& l = li.loops[idx];
        l.depth = l.parent >= 0 ? li.loops[l.parent].depth + 1 : 1;
        for (int b : l.blocks) li.innermost[b] = idx; // inner loops overwrite later
    }
    return li;
}

} // namespace dc
