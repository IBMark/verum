//! `verum map` - the system cartographer.
//!
//! Builds the complete picture of how a codebase fits together: a file-level
//! dependency graph with weighted edges, the symbol-level call graph with
//! degrees, entry points and dangerous sinks, strongly-connected module
//! cycles (Tarjan), Laravel routes, and every discovered flow (dangerous
//! chains + inter-procedural taint paths). Output as a text summary, a JSON
//! dump, or a self-contained interactive HTML explorer.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;

use verum_nucleus::{CallTarget, Ir, SymbolId, SymbolKind};

#[derive(Serialize)]
struct MapModule {
    path: String,
    lang: String,
    lines: u32,
    symbols: usize,
    /// Afferent coupling: modules that depend on this one.
    ca: usize,
    /// Efferent coupling: modules this one depends on.
    ce: usize,
    /// Martin instability Ce/(Ca+Ce): 0 = maximally depended-on, 1 = unstable.
    instability: f32,
    /// PageRank importance within the module dependency graph.
    rank: f32,
    /// Single point of failure: removing it disconnects the module graph.
    spof: bool,
    /// Emergent community id (label propagation).
    community: usize,
    /// Topological layer (0 = leaf/sink); back-edges are layering violations.
    layer: u32,
    /// Part of a dependency cycle.
    in_cycle: bool,
}

#[derive(Serialize)]
struct MapSymbol {
    name: String,
    fq: String,
    kind: String,
    module: usize,
    line: u32,
    ins: usize,
    outs: usize,
    entry: bool,
    sink: Option<&'static str>,
    /// PageRank importance within the symbol call graph (x 1000, for display).
    rank: f32,
    /// Reachable from any entry point through resolved calls.
    reachable: bool,
}

#[derive(Serialize)]
struct MapHop {
    file: String,
    line: u32,
    desc: String,
}

#[derive(Serialize)]
struct MapFlow {
    kind: String,
    severity: String,
    message: String,
    hops: Vec<MapHop>,
}

#[derive(Serialize)]
struct MapRoute {
    method: String,
    path: String,
    middleware: Vec<String>,
    file: String,
    line: u32,
    resolved: bool,
}

#[derive(Serialize)]
struct MapMeta {
    files: usize,
    lines: u64,
    symbols: usize,
    calls: usize,
    resolved_calls: usize,
    build_ms: u64,
}

#[derive(Serialize)]
pub struct MapData {
    version: String,
    generated_epoch: u64,
    root: String,
    meta: MapMeta,
    modules: Vec<MapModule>,
    /// (from module, to module, call count) - cross-file resolved calls.
    module_edges: Vec<(usize, usize, usize)>,
    /// (client module, server module, seam count) - cross-language HTTP seams
    /// linking a frontend `fetch`/`axios` call to the backend route file that
    /// serves it. These are the only edges that cross the language boundary.
    seam_edges: Vec<(usize, usize, usize)>,
    /// Strongly-connected components of the module graph with >= 2 members.
    cycles: Vec<Vec<usize>>,
    symbols: Vec<MapSymbol>,
    /// Resolved call edges between listed symbols (caller idx, callee idx).
    sym_edges: Vec<(usize, usize)>,
    unresolved_calls: usize,
    chains: Vec<MapFlow>,
    taints: Vec<MapFlow>,
    routes: Vec<MapRoute>,
    analytics: MapAnalytics,
    perf: Vec<PerfSignal>,
}

/// One performance-relevant construct with its objective impacts.
#[derive(Serialize)]
struct PerfSignal {
    kind: String,
    file: String,
    line: u32,
    message: String,
    fix: String,
    /// One entry per affected objective: (objective, +weight hurts / -weight helps).
    impacts: Vec<(String, i8)>,
}

/// Architecture-wide health numbers derived from the graphs.
#[derive(Serialize)]
struct MapAnalytics {
    /// Longest dependency chain through the module condensation.
    module_depth: u32,
    /// Longest resolved call chain through the symbol condensation.
    call_depth: u32,
    /// Module edges that point "up" the layering (dependency-direction smells).
    layering_violations: usize,
    /// Emergent module communities discovered by label propagation.
    communities: usize,
    /// Symbols with no path from any entry point (graph-level dead subgraphs).
    unreachable_symbols: usize,
    /// Single-point-of-failure modules.
    spof_modules: usize,
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .into_owned()
}

pub fn build_map_data(ir: &Ir, root: &Path) -> MapData {
    // Modules are files, indexed in sorted order for stable output
    let mut module_paths: Vec<&PathBuf> = ir.files.keys().collect();
    module_paths.sort();
    let module_idx: HashMap<&PathBuf, usize> = module_paths
        .iter()
        .enumerate()
        .map(|(i, p)| (*p, i))
        .collect();

    // Skip file-scope pseudo symbols - they're wiring, not code
    let mut sym_list: Vec<(SymbolId, &verum_nucleus::Symbol)> = ir
        .symbols
        .iter()
        .filter(|(_, s)| !s.name.starts_with("__file_scope_") && module_idx.contains_key(&s.file))
        .map(|(id, s)| (*id, s))
        .collect();
    sym_list.sort_by(|a, b| {
        (&a.1.file, a.1.line_start, &a.1.name).cmp(&(&b.1.file, b.1.line_start, &b.1.name))
    });
    let sym_idx: HashMap<SymbolId, usize> = sym_list
        .iter()
        .enumerate()
        .map(|(i, (id, _))| (*id, i))
        .collect();

    let mut sym_edges: Vec<(usize, usize)> = Vec::new();
    let mut module_edge_w: HashMap<(usize, usize), usize> = HashMap::new();
    let mut resolved_calls = 0usize;
    let mut unresolved_calls = 0usize;

    for call in &ir.calls {
        match &call.callee {
            CallTarget::Resolved(target) => {
                resolved_calls += 1;
                let callee_sym = ir.symbols.get(target);
                if let (Some(&a), Some(&b)) = (sym_idx.get(&call.caller), sym_idx.get(target)) {
                    if a != b {
                        sym_edges.push((a, b));
                    }
                }
                // Module edge: attribute by call site file -> callee's file.
                if let (Some(&ma), Some(mb)) = (
                    module_idx.get(&call.file),
                    callee_sym.and_then(|s| module_idx.get(&s.file)),
                ) {
                    if ma != *mb {
                        *module_edge_w.entry((ma, *mb)).or_default() += 1;
                    }
                }
            }
            _ => unresolved_calls += 1,
        }
    }
    sym_edges.sort();
    sym_edges.dedup();

    let mut module_edges: Vec<(usize, usize, usize)> = module_edge_w
        .into_iter()
        .map(|((a, b), w)| (a, b, w))
        .collect();
    module_edges.sort();

    let ns = sym_list.len();
    let mut ins = vec![0usize; ns];
    let mut outs = vec![0usize; ns];
    let mut sym_out_adj: Vec<Vec<usize>> = vec![Vec::new(); ns];
    for (a, b) in &sym_edges {
        outs[*a] += 1;
        ins[*b] += 1;
        sym_out_adj[*a].push(*b);
    }
    let sym_an = crate::graph::analyse_digraph(ns, &sym_edges);

    // Reachability from entry points - graph-level dead-subgraph detection
    let entry_seeds: Vec<usize> = sym_list
        .iter()
        .enumerate()
        .filter(|(_, (_, s))| s.is_entry_point)
        .map(|(i, _)| i)
        .collect();
    let reachable = crate::graph::reachable_from(ns, &sym_out_adj, &entry_seeds);
    let unreachable_symbols = reachable.iter().filter(|r| !**r).count();
    let sr_max = sym_an
        .pagerank
        .iter()
        .cloned()
        .fold(0.0_f64, f64::max)
        .max(1e-9);

    let nm = module_paths.len();
    let module_edge_pairs: Vec<(usize, usize)> =
        module_edges.iter().map(|(a, b, _)| (*a, *b)).collect();
    let mut mod_out_adj: Vec<Vec<usize>> = vec![Vec::new(); nm];
    let mut ca = vec![0usize; nm];
    let mut ce = vec![0usize; nm];
    for (a, b, _) in &module_edges {
        mod_out_adj[*a].push(*b);
        ce[*a] += 1; // efferent: a depends on b
        ca[*b] += 1; // afferent: b is depended on by a
    }
    let mod_an = crate::graph::analyse_digraph(nm, &module_edge_pairs);
    let mr_max = mod_an
        .pagerank
        .iter()
        .cloned()
        .fold(0.0_f64, f64::max)
        .max(1e-9);

    // Cycles: SCCs of two or more modules
    let cycles: Vec<Vec<usize>> = tarjan_sccs(&mod_out_adj)
        .into_iter()
        .filter(|scc| scc.len() >= 2)
        .collect();
    let mut mod_in_cycle = vec![false; nm];
    for scc in &cycles {
        for &m in scc {
            mod_in_cycle[m] = true;
        }
    }
    let communities: usize = mod_an
        .community
        .iter()
        .copied()
        .max()
        .map(|m| m + 1)
        .unwrap_or(0);

    let chain_findings = verum_lumen::chains::analyse(ir);
    let chains: Vec<MapFlow> = chain_findings
        .iter()
        .map(|f| MapFlow {
            kind: "chain".to_string(),
            severity: format!("{:?}", f.severity),
            message: f.message.clone(),
            hops: f
                .related
                .iter()
                .map(|r| MapHop {
                    file: rel(root, &r.file),
                    line: r.line,
                    desc: r.description.clone(),
                })
                .collect(),
        })
        .collect();

    let (_, taint_paths) = verum_lumen::taint::analyse_with_paths(ir);
    let taints: Vec<MapFlow> = taint_paths
        .iter()
        .map(|p| {
            let mut hops: Vec<MapHop> = p
                .hops
                .iter()
                .map(|h| MapHop {
                    file: rel(root, &h.file),
                    line: h.line,
                    desc: h.transforms.join(", "),
                })
                .collect();
            hops.push(MapHop {
                file: rel(root, &p.sink_file),
                line: p.sink_line,
                desc: format!("{} sink", verum_lumen::taint::sink_label(&p.sink)),
            });
            MapFlow {
                kind: "taint".to_string(),
                severity: "High".to_string(),
                message: format!(
                    "User input -> {} ({}:{})",
                    verum_lumen::taint::sink_label(&p.sink),
                    rel(root, &p.sink_file),
                    p.sink_line
                ),
                hops,
            }
        })
        .collect();

    let perf: Vec<PerfSignal> = verum_lumen::rust_insights::analyse(ir)
        .iter()
        .map(|f| {
            let impacts = verum_lumen::rust_insights::impacts_for(&f.kind)
                .into_iter()
                .map(|im| {
                    let signed = match im.direction {
                        verum_nucleus::Direction::Hurts => im.weight as i8,
                        verum_nucleus::Direction::Helps => -(im.weight as i8),
                    };
                    (im.objective.label().to_string(), signed)
                })
                .collect();
            PerfSignal {
                kind: format!("{:?}", f.kind),
                file: rel(root, &f.file),
                line: f.line_start,
                message: f.message.clone(),
                fix: f.suggestion.clone(),
                impacts,
            }
        })
        .collect();

    let routes: Vec<MapRoute> = ir
        .routes
        .iter()
        .map(|r| MapRoute {
            method: format!("{:?}", r.method).to_uppercase(),
            path: r.path.clone(),
            middleware: r.middleware.clone(),
            file: rel(root, &r.file),
            line: r.line,
            resolved: r.controller.is_some(),
        })
        .collect();

    // Cross-language seam edges: the frontend module making an HTTP call -> the
    // backend module whose route serves it. No resolved *code* edge ever crosses
    // languages, so without these the frontend and backend sit as disconnected
    // galaxies; these are the wires between them.
    let (seam_pairs, _oc, _or) = verum_mappa::endpoints::reconcile_seams(ir);
    let mut seam_w: std::collections::HashMap<(usize, usize), usize> =
        std::collections::HashMap::new();
    for s in &seam_pairs {
        if let (Some(&ca), Some(&cb)) = (
            module_idx.get(&&s.call.file),
            module_idx.get(&&s.route.file),
        ) {
            if ca != cb {
                *seam_w.entry((ca, cb)).or_default() += 1;
            }
        }
    }
    let mut seam_edges: Vec<(usize, usize, usize)> =
        seam_w.into_iter().map(|((a, b), w)| (a, b, w)).collect();
    seam_edges.sort();

    MapData {
        version: env!("CARGO_PKG_VERSION").to_string(),
        generated_epoch: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        root: root.to_string_lossy().into_owned(),
        meta: MapMeta {
            files: ir.metadata.total_files,
            lines: ir.metadata.total_lines,
            symbols: sym_list.len(),
            calls: ir.calls.len(),
            resolved_calls,
            build_ms: ir.metadata.build_time_ms,
        },
        modules: module_paths
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let info = &ir.files[*p];
                let denom = (ca[i] + ce[i]) as f32;
                MapModule {
                    path: rel(root, p),
                    lang: format!("{:?}", info.language),
                    lines: info.line_count,
                    symbols: info.symbols.len(),
                    ca: ca[i],
                    ce: ce[i],
                    instability: if denom > 0.0 {
                        ce[i] as f32 / denom
                    } else {
                        0.0
                    },
                    rank: (mod_an.pagerank[i] / mr_max) as f32,
                    spof: mod_an.articulation[i],
                    community: mod_an.community[i],
                    layer: mod_an.layer[i],
                    in_cycle: mod_in_cycle[i],
                }
            })
            .collect(),
        module_edges,
        seam_edges,
        cycles,
        symbols: sym_list
            .iter()
            .enumerate()
            .map(|(i, (_, s))| MapSymbol {
                name: s.name.clone(),
                fq: s.fully_qualified.clone(),
                kind: format!("{:?}", s.kind),
                module: module_idx[&s.file],
                line: s.line_start,
                ins: ins[i],
                outs: outs[i],
                entry: s.is_entry_point
                    || matches!(s.kind, SymbolKind::Function | SymbolKind::Method)
                        && s.name == "main",
                sink: verum_lumen::chains::sink_category(&s.name),
                rank: (sym_an.pagerank[i] / sr_max) as f32,
                reachable: reachable[i],
            })
            .collect(),
        sym_edges,
        unresolved_calls,
        chains,
        taints,
        routes,
        analytics: MapAnalytics {
            module_depth: mod_an.critical_depth,
            call_depth: sym_an.critical_depth,
            layering_violations: mod_an.layering_violations,
            communities,
            unreachable_symbols,
            spof_modules: mod_an.articulation.iter().filter(|a| **a).count(),
        },
        perf,
    }
}

/// The objectives a named profile optimises for.
fn profile_objectives(profile: &str) -> Vec<&'static str> {
    match profile {
        "latency" | "lowest-latency" => vec!["latency"],
        "throughput" | "fastest-throughput" => vec!["throughput"],
        "memory" | "lowest-memory" => vec!["memory"],
        "cpu" | "lowest-cpu" => vec!["cpu"],
        "realtime" | "real-time" => vec!["latency", "determinism"],
        _ => vec!["latency", "throughput", "memory", "cpu", "determinism"],
    }
}

/// Iterative Tarjan strongly-connected components.
fn tarjan_sccs(adj: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let n = adj.len();
    let mut index = vec![usize::MAX; n];
    let mut low = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<usize> = Vec::new();
    let mut next_index = 0usize;
    let mut sccs: Vec<Vec<usize>> = Vec::new();

    // Explicit DFS stack: (node, child position).
    for start in 0..n {
        if index[start] != usize::MAX {
            continue;
        }
        let mut work: Vec<(usize, usize)> = vec![(start, 0)];
        while let Some(&mut (v, ref mut child)) = work.last_mut() {
            if *child == 0 {
                index[v] = next_index;
                low[v] = next_index;
                next_index += 1;
                stack.push(v);
                on_stack[v] = true;
            }
            if *child < adj[v].len() {
                let w = adj[v][*child];
                *child += 1;
                if index[w] == usize::MAX {
                    work.push((w, 0));
                } else if on_stack[w] {
                    low[v] = low[v].min(index[w]);
                }
            } else {
                if low[v] == index[v] {
                    let mut scc = Vec::new();
                    loop {
                        let w = stack.pop().expect("tarjan stack invariant");
                        on_stack[w] = false;
                        scc.push(w);
                        if w == v {
                            break;
                        }
                    }
                    scc.sort_unstable();
                    sccs.push(scc);
                }
                work.pop();
                if let Some(&mut (parent, _)) = work.last_mut() {
                    low[parent] = low[parent].min(low[v]);
                }
            }
        }
    }
    sccs.sort();
    sccs
}

const MAP_HTML_TEMPLATE: &str = include_str!("../assets/map.html");

pub fn render(data: &MapData, format: &str, profile: &str) -> Result<String> {
    match format {
        "json" => Ok(serde_json::to_string_pretty(data)?),
        "html" => {
            let json = serde_json::to_string(data)?.replace("</", "<\\/");
            Ok(MAP_HTML_TEMPLATE.replace("__VERUM_MAP_DATA__", &json))
        }
        _ => Ok(render_text(data, profile)),
    }
}

/// Rank the performance signals against a profile's objectives and print the
/// biggest latency/throughput/... hits (and any deliberate trade-offs that help).
fn render_profile(out: &mut String, data: &MapData, profile: &str) {
    use std::fmt::Write;
    let objs = profile_objectives(profile);
    let score = |s: &PerfSignal| -> i32 {
        s.impacts
            .iter()
            .filter(|(o, _)| objs.contains(&o.as_str()))
            .map(|(_, w)| *w as i32)
            .sum()
    };
    let mut hurts: Vec<(&PerfSignal, i32)> = data
        .perf
        .iter()
        .map(|s| (s, score(s)))
        .filter(|(_, sc)| *sc > 0)
        .collect();
    hurts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.file.cmp(&b.0.file)));
    let helps: Vec<&PerfSignal> = data
        .perf
        .iter()
        .filter(|s| {
            s.impacts
                .iter()
                .any(|(o, w)| objs.contains(&o.as_str()) && *w < 0)
        })
        .collect();

    let _ = writeln!(
        out,
        "\n  {} Optimisation profile: {} (objectives: {})",
        "◆".cyan().bold(),
        profile.replace('-', " "),
        objs.join(", ")
    );
    if hurts.is_empty() {
        let _ = writeln!(
            out,
            "     {}  nothing detected working against this goal",
            "✓".green()
        );
    } else {
        let _ = writeln!(
            out,
            "     {} biggest hits (impact · construct · location):",
            "->".cyan()
        );
        for (s, sc) in hurts.iter().take(15) {
            let _ = writeln!(
                out,
                "     {:>2}  {}  {} - {}:{}",
                sc, s.kind, s.message, s.file, s.line
            );
            let _ = writeln!(out, "         ↳ {}", s.fix);
        }
        if hurts.len() > 15 {
            let _ = writeln!(out, "     ... {} more", hurts.len() - 15);
        }
    }
    if !helps.is_empty() {
        let _ = writeln!(
            out,
            "\n     {} trade-offs that aid this goal at another's expense:",
            "↔".yellow()
        );
        for s in helps.iter().take(6) {
            let _ = writeln!(
                out,
                "     {} {} - {}:{}",
                "↔".yellow(),
                s.message,
                s.file,
                s.line
            );
        }
    }
    let _ = writeln!(out);
}

fn render_text(data: &MapData, profile: &str) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let m = &data.meta;
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  {} System map - {} modules, {} symbols, {} calls ({} resolved, {} unresolved)",
        "->".cyan().bold(),
        data.modules.len(),
        m.symbols,
        m.calls,
        m.resolved_calls,
        data.unresolved_calls
    );
    let _ = writeln!(
        out,
        "     {} module dependencies, {} flows mapped ({} chains, {} taint paths), {} routes",
        data.module_edges.len(),
        data.chains.len() + data.taints.len(),
        data.chains.len(),
        data.taints.len(),
        data.routes.len()
    );

    let mut hubs: Vec<(usize, &MapSymbol)> =
        data.symbols.iter().map(|s| (s.ins + s.outs, s)).collect();
    hubs.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.fq.cmp(&b.1.fq)));
    let _ = writeln!(out, "\n  {} Top hubs (in+out degree):", "->".cyan());
    for (deg, s) in hubs.iter().take(10) {
        let _ = writeln!(
            out,
            "     {:>4}  {}  {}:{}",
            deg, s.fq, data.modules[s.module].path, s.line
        );
    }

    let mut edges = data.module_edges.clone();
    edges.sort_by(|a, b| b.2.cmp(&a.2));
    let _ = writeln!(out, "\n  {} Heaviest module dependencies:", "->".cyan());
    for (a, b, w) in edges.iter().take(10) {
        let _ = writeln!(
            out,
            "     {:>4}  {} -> {}",
            w, data.modules[*a].path, data.modules[*b].path
        );
    }

    if data.cycles.is_empty() {
        let _ = writeln!(
            out,
            "\n  {}  No module-level dependency cycles",
            "✓".green()
        );
    } else {
        let _ = writeln!(
            out,
            "\n  {}  {} module-level dependency cycles:",
            "⚠".yellow(),
            data.cycles.len()
        );
        for scc in data.cycles.iter().take(10) {
            let names: Vec<&str> = scc.iter().map(|i| data.modules[*i].path.as_str()).collect();
            let _ = writeln!(out, "     {} {}", "↺".yellow(), names.join(" ↔ "));
        }
    }

    let entries = data.symbols.iter().filter(|s| s.entry).count();
    let sinks = data.symbols.iter().filter(|s| s.sink.is_some()).count();
    let _ = writeln!(
        out,
        "\n  {} entry points, {} sink-named symbols",
        entries, sinks
    );

    let a = &data.analytics;
    let _ = writeln!(out, "\n  {} Architecture analytics:", "->".cyan());
    let _ = writeln!(
        out,
        "     call-graph depth {}, module-graph depth {}, {} communities",
        a.call_depth, a.module_depth, a.communities
    );
    let _ = writeln!(
        out,
        "     {} layering violations, {} single-point-of-failure modules, {} unreachable symbols",
        a.layering_violations, a.spof_modules, a.unreachable_symbols
    );

    let mut central: Vec<&MapSymbol> = data.symbols.iter().collect();
    central.sort_by(|x, y| {
        y.rank
            .partial_cmp(&x.rank)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let _ = writeln!(out, "\n  {} Most central symbols (PageRank):", "->".cyan());
    for s in central.iter().take(8) {
        let _ = writeln!(
            out,
            "     {:.3}  {}  {}:{}",
            s.rank, s.fq, data.modules[s.module].path, s.line
        );
    }

    // Martin metrics: most depended-on first, then most stable
    let mut mods: Vec<&MapModule> = data.modules.iter().filter(|m| m.ca + m.ce > 0).collect();
    mods.sort_by(|x, y| {
        y.ca.cmp(&x.ca)
            .then(x.instability.partial_cmp(&y.instability).unwrap())
    });
    let _ = writeln!(
        out,
        "\n  {} Most depended-on modules (Ca / instability):",
        "->".cyan()
    );
    for m in mods.iter().take(8) {
        let _ = writeln!(
            out,
            "     Ca={:>2} Ce={:>2} I={:.2}{}  {}",
            m.ca,
            m.ce,
            m.instability,
            if m.spof { " [SPOF]" } else { "" },
            m.path
        );
    }

    if !data.perf.is_empty() {
        render_profile(&mut out, data, profile);
    }
    out
}

pub async fn cmd_map(path: &Path, format: &str, profile: &str, out: Option<&Path>) -> Result<()> {
    let config = crate::make_atlas_config(path);
    let root = config.root.clone();
    let ir = verum_mappa::Atlas::new(config)
        .build()
        .context("Atlas failed to map codebase")?;

    let data = build_map_data(&ir, &root);
    let rendered = render(&data, format, profile)?;

    match out {
        Some(out_path) => {
            std::fs::write(out_path, &rendered)
                .with_context(|| format!("Failed to write {}", out_path.display()))?;
            println!("  {}  Map written to {}", "✓".green(), out_path.display());
        }
        None => println!("{}", rendered),
    }
    Ok(())
}
