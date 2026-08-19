//! Deterministic graph analytics over the symbol call graph and the module
//! dependency graph. Everything here is pure graph theory on adjacency lists -
//! no I/O, no randomness (label propagation and PageRank iterate in fixed
//! node order), so results are byte-stable across runs.

use std::collections::VecDeque;

/// Results of analysing one directed graph (nodes 0..n, edges as (from,to)).
pub struct GraphAnalytics {
    /// PageRank per node (importance under the random-surfer model).
    pub pagerank: Vec<f64>,
    /// Articulation points: nodes whose removal increases the number of
    /// connected components (single points of failure) in the undirected
    /// projection.
    pub articulation: Vec<bool>,
    /// Topological layer per node on the DAG condensation (0 = deepest
    /// leaf/sink); nodes in a cycle share their SCC's layer.
    pub layer: Vec<u32>,
    /// Community id per node (label propagation on the undirected projection).
    pub community: Vec<usize>,
    /// Length (in edges) of the longest simple path along the condensation -
    /// the "critical depth" of the call graph.
    pub critical_depth: u32,
    /// Back-edges: edges pointing from a lower layer to a higher one, i.e.
    /// up-calls that violate the natural layering.
    pub layering_violations: usize,
}

pub fn analyse_digraph(n: usize, edges: &[(usize, usize)]) -> GraphAnalytics {
    let mut out: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut inc: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut undirected: Vec<Vec<usize>> = vec![Vec::new(); n];
    for &(a, b) in edges {
        if a >= n || b >= n || a == b {
            continue;
        }
        out[a].push(b);
        inc[b].push(a);
        undirected[a].push(b);
        undirected[b].push(a);
    }

    let pagerank = pagerank(n, &out, &inc);
    let articulation = articulation_points(n, &undirected);
    let (comp, layer, critical_depth, sccs) = layering(n, &out);
    let community = label_propagation(n, &undirected);

    // Layering violation = edge whose target sits in a *higher* layer than its
    // source, and the two are in different SCCs (intra-cycle edges excluded).
    let mut layering_violations = 0usize;
    for &(a, b) in edges {
        if a < n && b < n && a != b && comp[a] != comp[b] && layer[b] > layer[a] {
            layering_violations += 1;
        }
    }
    let _ = sccs;

    GraphAnalytics {
        pagerank,
        articulation,
        layer,
        community,
        critical_depth,
        layering_violations,
    }
}

/// PageRank via power iteration (damping 0.85, 60 iterations, fixed order).
fn pagerank(n: usize, out: &[Vec<usize>], inc: &[Vec<usize>]) -> Vec<f64> {
    if n == 0 {
        return Vec::new();
    }
    let d = 0.85;
    let base = (1.0 - d) / n as f64;
    let mut rank = vec![1.0 / n as f64; n];
    let out_deg: Vec<f64> = out.iter().map(|o| o.len().max(1) as f64).collect();
    for _ in 0..60 {
        // Dangling mass (nodes with no out-edges) is redistributed uniformly.
        let dangling: f64 = (0..n)
            .filter(|&i| out[i].is_empty())
            .map(|i| rank[i])
            .sum::<f64>()
            * d
            / n as f64;
        let mut next = vec![base + dangling; n];
        for i in 0..n {
            let mut acc = 0.0;
            for &j in &inc[i] {
                acc += rank[j] / out_deg[j];
            }
            next[i] += d * acc;
        }
        rank = next;
    }
    rank
}

/// Articulation points on the undirected projection (iterative DFS lowlink).
fn articulation_points(n: usize, adj: &[Vec<usize>]) -> Vec<bool> {
    let mut disc = vec![usize::MAX; n];
    let mut low = vec![0usize; n];
    let mut is_art = vec![false; n];
    let mut timer = 0usize;

    for start in 0..n {
        if disc[start] != usize::MAX {
            continue;
        }
        // Stack frames: (node, parent, child-iterator index).
        let mut stack: Vec<(usize, isize, usize)> = vec![(start, -1, 0)];
        let mut root_children = 0usize;
        while let Some(&mut (u, parent, ref mut ci)) = stack.last_mut() {
            if *ci == 0 {
                disc[u] = timer;
                low[u] = timer;
                timer += 1;
            }
            if *ci < adj[u].len() {
                let v = adj[u][*ci];
                *ci += 1;
                if v as isize == parent {
                    continue;
                }
                if disc[v] == usize::MAX {
                    if parent == -1 {
                        root_children += 1;
                    }
                    stack.push((v, u as isize, 0));
                } else {
                    low[u] = low[u].min(disc[v]);
                }
            } else {
                stack.pop();
                if let Some(&mut (p, _, _)) = stack.last_mut() {
                    low[p] = low[p].min(low[u]);
                    // Non-root p is an articulation point if a child can't
                    // reach an ancestor of p.
                    let p_disc = disc[p];
                    if !stack.is_empty() && low[u] >= p_disc && !stack.is_empty() {
                        // p is not the root iff it has its own parent frame,
                        // which is any frame below it; the root is index 0.
                        if p != start {
                            is_art[p] = true;
                        }
                    }
                }
            }
        }
        if root_children > 1 {
            is_art[start] = true;
        }
    }
    is_art
}

/// Tarjan SCC + longest-path layering on the condensation.
/// Returns (component id per node, layer per node, critical depth, scc list).
fn layering(n: usize, out: &[Vec<usize>]) -> (Vec<usize>, Vec<u32>, u32, Vec<Vec<usize>>) {
    // Tarjan, iteratively
    let mut index = vec![usize::MAX; n];
    let mut low = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut comp = vec![usize::MAX; n];
    let mut stack: Vec<usize> = Vec::new();
    let mut sccs: Vec<Vec<usize>> = Vec::new();
    let mut next_index = 0usize;

    for start in 0..n {
        if index[start] != usize::MAX {
            continue;
        }
        let mut work: Vec<(usize, usize)> = vec![(start, 0)];
        while let Some(&mut (v, ref mut ci)) = work.last_mut() {
            if *ci == 0 {
                index[v] = next_index;
                low[v] = next_index;
                next_index += 1;
                stack.push(v);
                on_stack[v] = true;
            }
            if *ci < out[v].len() {
                let w = out[v][*ci];
                *ci += 1;
                if index[w] == usize::MAX {
                    work.push((w, 0));
                } else if on_stack[w] {
                    low[v] = low[v].min(index[w]);
                }
            } else {
                if low[v] == index[v] {
                    let cid = sccs.len();
                    let mut members = Vec::new();
                    loop {
                        let w = stack.pop().unwrap();
                        on_stack[w] = false;
                        comp[w] = cid;
                        members.push(w);
                        if w == v {
                            break;
                        }
                    }
                    sccs.push(members);
                }
                work.pop();
                if let Some(&mut (p, _)) = work.last_mut() {
                    low[p] = low[p].min(low[v]);
                }
            }
        }
    }

    // Condensation edges
    let c = sccs.len();
    let mut cadj: Vec<Vec<usize>> = vec![Vec::new(); c];
    let mut cindeg = vec![0u32; c];
    for u in 0..n {
        for &v in &out[u] {
            if comp[u] != comp[v] {
                cadj[comp[u]].push(comp[v]);
            }
        }
    }
    for e in &mut cadj {
        e.sort_unstable();
        e.dedup();
    }
    for e in &cadj {
        for &v in e {
            cindeg[v] += 1;
        }
    }

    // Longest-path layer on the DAG: Kahn topo, layer = max pred + 1
    let mut clayer = vec![0u32; c];
    let mut q: VecDeque<usize> = (0..c).filter(|&i| cindeg[i] == 0).collect();
    let mut indeg = cindeg.clone();
    let mut critical = 0u32;
    while let Some(u) = q.pop_front() {
        for &v in &cadj[u] {
            clayer[v] = clayer[v].max(clayer[u] + 1);
            critical = critical.max(clayer[v]);
            indeg[v] -= 1;
            if indeg[v] == 0 {
                q.push_back(v);
            }
        }
    }

    let layer: Vec<u32> = (0..n).map(|i| clayer[comp[i]]).collect();
    (comp, layer, critical, sccs)
}

/// Deterministic label propagation for community detection. Each node adopts
/// the most common label among its neighbours; ties break to the lowest label.
/// Iterates in fixed ascending node order until stable (or 20 rounds), then
/// labels are compacted to 0..k.
fn label_propagation(n: usize, adj: &[Vec<usize>]) -> Vec<usize> {
    let mut label: Vec<usize> = (0..n).collect();
    for _ in 0..20 {
        let mut changed = false;
        for u in 0..n {
            if adj[u].is_empty() {
                continue;
            }
            let mut counts: std::collections::HashMap<usize, usize> =
                std::collections::HashMap::new();
            for &v in &adj[u] {
                *counts.entry(label[v]).or_default() += 1;
            }
            // Pick highest count, ties -> lowest label id (deterministic).
            let best = counts
                .into_iter()
                .fold(None, |acc: Option<(usize, usize)>, (lab, cnt)| match acc {
                    Some((bl, bc)) if bc > cnt || (bc == cnt && bl <= lab) => Some((bl, bc)),
                    _ => Some((lab, cnt)),
                })
                .map(|(l, _)| l)
                .unwrap_or(label[u]);
            if best != label[u] {
                label[u] = best;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    // Compact labels to a dense 0..k in first-appearance order.
    let mut remap = std::collections::HashMap::new();
    let mut next = 0usize;
    label
        .iter()
        .map(|&l| {
            *remap.entry(l).or_insert_with(|| {
                let id = next;
                next += 1;
                id
            })
        })
        .collect()
}

/// BFS reachable set from a set of seed nodes over `out` adjacency.
pub fn reachable_from(n: usize, out: &[Vec<usize>], seeds: &[usize]) -> Vec<bool> {
    let mut seen = vec![false; n];
    let mut q: VecDeque<usize> = VecDeque::new();
    for &s in seeds {
        if s < n && !seen[s] {
            seen[s] = true;
            q.push_back(s);
        }
    }
    while let Some(u) = q.pop_front() {
        for &v in &out[u] {
            if !seen[v] {
                seen[v] = true;
                q.push_back(v);
            }
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn articulation_on_bridge() {
        // 0-1-2 chain: node 1 is an articulation point.
        let a = analyse_digraph(3, &[(0, 1), (1, 2)]);
        assert!(a.articulation[1]);
        assert!(!a.articulation[0]);
        assert!(!a.articulation[2]);
    }

    #[test]
    fn layering_is_topological() {
        // 0 -> 1 -> 2: layers strictly increase along the DAG.
        let a = analyse_digraph(3, &[(0, 1), (1, 2)]);
        assert!(a.layer[1] > a.layer[0]);
        assert!(a.layer[2] > a.layer[1]);
        assert_eq!(a.critical_depth, 2);
    }

    #[test]
    fn pagerank_favors_hubs() {
        // Everyone points at node 3.
        let a = analyse_digraph(4, &[(0, 3), (1, 3), (2, 3)]);
        assert!(a.pagerank[3] > a.pagerank[0]);
    }

    #[test]
    fn communities_split_disconnected() {
        // Two disjoint triangles -> two communities.
        let a = analyse_digraph(6, &[(0, 1), (1, 2), (2, 0), (3, 4), (4, 5), (5, 3)]);
        assert_eq!(a.community[0], a.community[1]);
        assert_ne!(a.community[0], a.community[3]);
    }
}
