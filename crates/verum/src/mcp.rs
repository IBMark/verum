//! `verum mcp` - serve the fact layer over MCP (stdio) so AI agents can query
//! the call graph, liveness, duplicates, and audit results as tools.
//!
//! Protocol: newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP stdio
//! transport). stdout carries protocol messages only - all logging goes to
//! stderr, and the analysis itself never prints.
//!
//! Answers must reflect the tree as it is *now* (agents edit files mid-session
//! and ask again), so every tool call re-checks a cheap mtime/size fingerprint
//! of the tree and re-maps only when something actually changed.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::{json, Value};
use walkdir::WalkDir;

use verum_lumen::{Prism, PrismResult};
use verum_mappa::Atlas;
use verum_nucleus::{CallTarget, FindingKind, Ir, Objective, Severity, Symbol, SymbolId};

use crate::{load_standard_from_file, make_atlas_config};

pub fn cmd_mcp(path: &Path) -> Result<()> {
    let root = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut server = Server { root, cache: None };

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");

        // Requests carry an id and get a response; notifications don't.
        let Some(id) = id else { continue };

        let reply = match method {
            "initialize" => Ok(initialize_result(&msg)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tool_definitions() })),
            "tools/call" => Ok(server.tools_call(msg.get("params"))),
            _ => Err((-32601i64, format!("method not found: {method}"))),
        };

        let envelope = match reply {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, message)) => json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": code, "message": message }
            }),
        };
        let mut out = stdout.lock();
        writeln!(out, "{envelope}")?;
        out.flush()?;
    }
    Ok(())
}

fn initialize_result(msg: &Value) -> Value {
    let requested = msg
        .pointer("/params/protocolVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("2024-11-05");
    json!({
        "protocolVersion": requested,
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": "verum-mcp",
            "version": env!("CARGO_PKG_VERSION"),
        }
    })
}

struct Cache {
    fingerprint: u64,
    ir: Ir,
    /// Full analysis is computed lazily: navigation tools (callers, impact,
    /// definition...) only need the IR, which maps in map-time. Only the analysis
    /// tools (audit, dead_code, duplicates, perf_advice) pay for prism, and then
    /// only once per tree state.
    prism: Option<PrismResult>,
}

struct Server {
    root: PathBuf,
    cache: Option<Cache>,
}

/// Tools that read analysis findings; everything else works off the IR alone.
fn needs_prism(tool: &str) -> bool {
    matches!(
        tool,
        "overview" | "dead_code" | "audit" | "audit_delta" | "duplicates" | "perf_advice"
    )
}

impl Server {
    /// Ensure the IR reflects the tree as it is now, re-mapping only on change.
    /// A changed tree invalidates any cached analysis too.
    fn ensure_ir(&mut self) -> Result<(), String> {
        let fingerprint = tree_fingerprint(&self.root);
        let stale = self
            .cache
            .as_ref()
            .is_none_or(|c| c.fingerprint != fingerprint);
        if stale {
            let config = make_atlas_config(&self.root);
            let ir = Atlas::new(config)
                .build()
                .map_err(|e| format!("atlas failed: {e}"))?;
            self.cache = Some(Cache {
                fingerprint,
                ir,
                prism: None,
            });
        }
        Ok(())
    }

    /// Compute and cache prism analysis for the current IR if not already done.
    fn ensure_prism(&mut self) -> Result<(), String> {
        self.ensure_ir()?;
        let cache = self.cache.as_mut().unwrap();
        if cache.prism.is_none() {
            let standard = load_standard_from_file(&self.root);
            let prism = Prism::analyse_at(&cache.ir, &standard, Some(&self.root))
                .map_err(|e| format!("prism failed: {e}"))?;
            cache.prism = Some(prism);
        }
        Ok(())
    }

    fn tools_call(&mut self, params: Option<&Value>) -> Value {
        let name = params
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("");
        let empty = json!({});
        let args = params
            .and_then(|p| p.get("arguments"))
            .unwrap_or(&empty)
            .clone();

        let outcome = self.dispatch(name, &args);
        match outcome {
            Ok(value) => json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&value)
                        .unwrap_or_else(|_| value.to_string()),
                }]
            }),
            Err(message) => json!({
                "content": [{ "type": "text", "text": message }],
                "isError": true
            }),
        }
    }

    fn dispatch(&mut self, name: &str, args: &Value) -> Result<Value, String> {
        // audit_delta shells out to git before analysis; everything else works
        // off the cached IR + findings.
        let root = self.root.clone();
        if needs_prism(name) {
            self.ensure_prism()?;
        } else {
            self.ensure_ir()?;
        }
        let cache = self.cache.as_ref().unwrap();
        let ir = &cache.ir;
        // Real analysis for prism tools (ensure_prism ran above); an empty
        // stand-in the navigation branches hold but never read.
        let empty_prism;
        let prism = match cache.prism.as_ref() {
            Some(p) => p,
            None => {
                empty_prism = PrismResult::default();
                &empty_prism
            }
        };

        match name {
            "overview" => Ok(overview(ir, prism, &root)),
            "find_symbol" => {
                let query = require_str(args, "query")?;
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
                let mut ids = resolve_query(ir, query);
                let total = ids.len();
                ids.truncate(limit);
                let matches: Vec<Value> =
                    ids.iter().map(|id| symbol_json(ir, &root, *id)).collect();
                Ok(json!({ "total_matches": total, "returned": matches.len(), "symbols": matches }))
            }
            "definition_of" => {
                let query = require_str(args, "query")?;
                let ids = resolve_query(ir, query);
                let syms: Vec<&Symbol> = ids.iter().filter_map(|id| ir.symbols.get(id)).collect();
                let provenance = if syms.iter().any(|s| s.fully_qualified == query) {
                    "exact_fully_qualified"
                } else if syms.iter().any(|s| s.name == query) {
                    "exact_name"
                } else {
                    "substring"
                };
                let listed: Vec<Value> = ids
                    .iter()
                    .take(20)
                    .map(|id| symbol_json(ir, &root, *id))
                    .collect();
                Ok(json!({
                    "query": query,
                    "provenance": provenance,
                    "total_matches": ids.len(),
                    "definitions": listed,
                }))
            }
            "references_of" => {
                let query = require_str(args, "query")?;
                let id = resolve_unique(ir, &root, query)?;
                let sym_name = ir
                    .symbols
                    .get(&id)
                    .map(|s| s.name.clone())
                    .unwrap_or_default();

                let resolved: Vec<Value> = direct_callers(ir, id)
                    .iter()
                    .map(|(caller, file, line)| {
                        json!({
                            "caller": symbol_json(ir, &root, *caller),
                            "site": format!("{}:{}", rel(&root, file), line),
                        })
                    })
                    .collect();

                // Name-based references: unresolved/dynamic calls whose final
                // segment matches. Weaker provenance than a resolved edge -
                // reported separately so the consumer knows the difference.
                let mut name_matches: Vec<Value> = ir
                    .calls
                    .iter()
                    .filter(|c| {
                        let n = match &c.callee {
                            CallTarget::Unresolved(n)
                            | CallTarget::Dynamic(n)
                            | CallTarget::Magic(n) => n,
                            CallTarget::Resolved(_) => return false,
                        };
                        final_segment(n) == sym_name
                    })
                    .map(|c| {
                        json!({
                            "caller": symbol_json(ir, &root, c.caller),
                            "site": format!("{}:{}", rel(&root, &c.file), c.line),
                        })
                    })
                    .collect();
                name_matches.truncate(100);

                Ok(json!({
                    "symbol": symbol_json(ir, &root, id),
                    "resolved_references": resolved,
                    "name_match_references": name_matches,
                }))
            }
            "callers_of" => {
                let query = require_str(args, "query")?;
                let id = resolve_unique(ir, &root, query)?;
                let callers = direct_callers(ir, id);
                let sites: Vec<Value> = callers
                    .iter()
                    .map(|(caller, file, line)| {
                        json!({
                            "caller": symbol_json(ir, &root, *caller),
                            "call_site": format!("{}:{}", rel(&root, file), line),
                        })
                    })
                    .collect();
                Ok(json!({
                    "symbol": symbol_json(ir, &root, id),
                    "direct_callers": sites.len(),
                    "callers": sites,
                }))
            }
            "callees_of" => {
                let query = require_str(args, "query")?;
                let id = resolve_unique(ir, &root, query)?;
                let mut resolved = Vec::new();
                let mut unresolved = Vec::new();
                let mut dynamic = Vec::new();
                for call in ir.calls.iter().filter(|c| c.caller == id) {
                    match &call.callee {
                        CallTarget::Resolved(callee) => {
                            resolved.push(json!({
                                "callee": symbol_json(ir, &root, *callee),
                                "call_site": format!("{}:{}", rel(&root, &call.file), call.line),
                            }));
                        }
                        CallTarget::Unresolved(n) => unresolved.push(n.clone()),
                        CallTarget::Dynamic(n) | CallTarget::Magic(n) => dynamic.push(n.clone()),
                    }
                }
                unresolved.sort();
                unresolved.dedup();
                dynamic.sort();
                dynamic.dedup();
                Ok(json!({
                    "symbol": symbol_json(ir, &root, id),
                    "resolved": resolved,
                    "unresolved_names": unresolved,
                    "dynamic": dynamic,
                }))
            }
            "impact_of" => {
                let query = require_str(args, "query")?;
                let id = resolve_unique(ir, &root, query)?;
                let impacted = transitive_callers(ir, id);
                let mut files: Vec<String> = impacted
                    .iter()
                    .filter_map(|sid| ir.symbols.get(sid))
                    .map(|s| rel(&root, &s.file))
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                files.sort();
                let mut symbols: Vec<&Symbol> = impacted
                    .iter()
                    .filter_map(|sid| ir.symbols.get(sid))
                    .collect();
                symbols.sort_by(|a, b| (&a.file, a.line_start).cmp(&(&b.file, b.line_start)));
                let listed: Vec<Value> = symbols
                    .iter()
                    .take(100)
                    .map(|s| symbol_json(ir, &root, s.id))
                    .collect();
                Ok(json!({
                    "symbol": symbol_json(ir, &root, id),
                    "transitively_impacted_symbols": impacted.len(),
                    "impacted_files": files,
                    "impacted": listed,
                    "note": if impacted.len() > 100 { "impacted list capped at 100" } else { "" },
                }))
            }
            "dead_code" => {
                let dead: Vec<Value> = prism
                    .findings
                    .iter()
                    .filter(|f| {
                        matches!(
                            f.kind,
                            FindingKind::DeadFunction
                                | FindingKind::DeadClass
                                | FindingKind::DeadFile
                                | FindingKind::UnreachableCode
                        )
                    })
                    .map(|f| finding_json(f, &root))
                    .collect();
                Ok(json!({ "count": dead.len(), "dead": dead }))
            }
            "audit" => {
                // main.rs's severity_rank: higher = more severe, so "at or
                // above the minimum" is rank >= min_rank.
                let min_rank = args
                    .get("min_severity")
                    .and_then(|v| v.as_str())
                    .map(parse_severity)
                    .transpose()?
                    .map(|s| crate::severity_rank(&s))
                    .unwrap_or(0);
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;

                let selected: Vec<&verum_nucleus::Finding> = prism
                    .findings
                    .iter()
                    .filter(|f| crate::severity_rank(&f.severity) >= min_rank)
                    .collect();
                let mut by_severity: HashMap<String, usize> = HashMap::new();
                for f in &selected {
                    *by_severity.entry(format!("{:?}", f.severity)).or_default() += 1;
                }
                let listed: Vec<Value> = selected
                    .iter()
                    .take(limit)
                    .map(|f| finding_json(f, &root))
                    .collect();
                Ok(json!({
                    "score": prism.score,
                    "total_findings": selected.len(),
                    "by_severity": by_severity,
                    "returned": listed.len(),
                    "findings": listed,
                }))
            }
            "audit_delta" => {
                let git_ref = require_str(args, "git_ref")?;
                let changed = changed_files(&root, git_ref)?;
                let findings: Vec<Value> = prism
                    .findings
                    .iter()
                    .filter(|f| {
                        std::fs::canonicalize(&f.file)
                            .map(|p| changed.contains(&p))
                            .unwrap_or(false)
                    })
                    .map(|f| finding_json(f, &root))
                    .collect();
                Ok(json!({
                    "git_ref": git_ref,
                    "changed_files": changed.len(),
                    "findings_in_changed_files": findings.len(),
                    "findings": findings,
                }))
            }
            "perf_advice" => {
                let profile = args
                    .get("profile")
                    .and_then(|v| v.as_str())
                    .unwrap_or("all");
                let objectives = profile_objectives(profile)?;
                Ok(perf_advice(ir, prism, &root, profile, &objectives))
            }
            "endpoints" => Ok(endpoints_view(ir, &root)),
            "duplicates" => {
                let groups: Vec<Value> = prism
                    .duplicate_groups
                    .iter()
                    .map(|g| {
                        let dups: Vec<Value> = g
                            .duplicates
                            .iter()
                            .map(|id| symbol_json(ir, &root, *id))
                            .collect();
                        json!({
                            "canonical": symbol_json(ir, &root, g.canonical),
                            "duplicates": dups,
                            "similarity": format!("{:?}", g.similarity),
                            "confidence": g.confidence,
                        })
                    })
                    .collect();
                Ok(json!({ "groups": groups.len(), "duplicate_groups": groups }))
            }
            other => Err(format!("unknown tool: {other}")),
        }
    }
}

/// Order-independent mtime/size fingerprint over every file the scan would
/// read. One stat per file, no parsing - cheap enough to run per tool call.
fn tree_fingerprint(root: &Path) -> u64 {
    let excludes = ["vendor", "node_modules", ".git", "target"];
    let mut acc: u64 = 0;
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let p = path.to_string_lossy();
        if excludes.iter().any(|x| p.contains(x)) {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let line = format!("{}|{}|{}", p, meta.len(), mtime);
            acc = acc.wrapping_add(verum_mappa::stable_hash(&line));
        }
    }
    acc
}

/// Match a query against symbols: exact FQ name, then exact short name, then
/// case-insensitive substring of the FQ name. Deterministic order.
fn resolve_query(ir: &Ir, query: &str) -> Vec<SymbolId> {
    let exact_fq: Vec<SymbolId> = ir
        .symbols
        .values()
        .filter(|s| s.fully_qualified == query)
        .map(|s| s.id)
        .collect();
    let pick = if !exact_fq.is_empty() {
        exact_fq
    } else {
        let exact_name: Vec<SymbolId> = ir
            .symbols
            .values()
            .filter(|s| s.name == query)
            .map(|s| s.id)
            .collect();
        if !exact_name.is_empty() {
            exact_name
        } else {
            let q = query.to_lowercase();
            ir.symbols
                .values()
                .filter(|s| s.fully_qualified.to_lowercase().contains(&q))
                .map(|s| s.id)
                .collect()
        }
    };
    let mut sorted = pick;
    sorted.sort_by_key(|id| {
        ir.symbols
            .get(id)
            .map(|s| (s.file.clone(), s.line_start, s.name.clone()))
    });
    sorted
}

/// A tool that needs one symbol refuses to guess between several - it returns
/// the candidates so the agent can re-ask with a fully qualified name.
fn resolve_unique(ir: &Ir, root: &Path, query: &str) -> Result<SymbolId, String> {
    let ids = resolve_query(ir, query);
    match ids.len() {
        0 => Err(format!("no symbol matches `{query}`")),
        1 => Ok(ids[0]),
        n => {
            let candidates: Vec<String> = ids
                .iter()
                .take(10)
                .filter_map(|id| ir.symbols.get(id))
                .map(|s| {
                    format!(
                        "{} ({}:{})",
                        s.fully_qualified,
                        rel(root, &s.file),
                        s.line_start
                    )
                })
                .collect();
            Err(format!(
                "`{query}` is ambiguous ({n} matches) - use a fully qualified name. Candidates: {}",
                candidates.join(", ")
            ))
        }
    }
}

fn direct_callers(ir: &Ir, id: SymbolId) -> Vec<(SymbolId, PathBuf, u32)> {
    let mut callers: Vec<(SymbolId, PathBuf, u32)> = ir
        .calls
        .iter()
        .filter(|c| matches!(&c.callee, CallTarget::Resolved(target) if *target == id))
        .map(|c| (c.caller, c.file.clone(), c.line))
        .collect();
    callers.sort_by(|a, b| (&a.1, a.2).cmp(&(&b.1, b.2)));
    callers
}

/// Reverse-BFS over resolved call edges: everything that transitively reaches
/// `id`, i.e. everything a change to `id` can affect.
fn transitive_callers(ir: &Ir, id: SymbolId) -> HashSet<SymbolId> {
    let mut reverse: HashMap<SymbolId, Vec<SymbolId>> = HashMap::new();
    for call in &ir.calls {
        if let CallTarget::Resolved(target) = &call.callee {
            reverse.entry(*target).or_default().push(call.caller);
        }
    }
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([id]);
    while let Some(current) = queue.pop_front() {
        if let Some(callers) = reverse.get(&current) {
            for caller in callers {
                if seen.insert(*caller) {
                    queue.push_back(*caller);
                }
            }
        }
    }
    seen.remove(&id);
    seen
}

/// Objectives a named profile optimises for. Unknown profile is an error so a
/// typo doesn't silently fall back to "everything".
fn profile_objectives(profile: &str) -> Result<Vec<Objective>, String> {
    use Objective::*;
    Ok(match profile {
        "latency" => vec![Latency],
        "throughput" => vec![Throughput],
        "memory" => vec![Memory],
        "cpu" => vec![Cpu],
        "realtime" | "real-time" => vec![Latency, Determinism],
        "all" => vec![Latency, Throughput, Memory, Cpu, Determinism],
        other => {
            return Err(format!(
            "unknown profile `{other}` - use latency | throughput | memory | cpu | realtime | all"
        ))
        }
    })
}

/// Opt-in performance advisory: surface the findings that hurt the chosen
/// objective(s), ranked by impact weight, grouped by construct, each with its
/// remediation. Reuses the same PerfImpact model the `map` command scores with.
fn perf_advice(
    ir: &Ir,
    prism: &PrismResult,
    root: &Path,
    profile: &str,
    objectives: &[Objective],
) -> Value {
    use verum_nucleus::Direction;

    // Score a finding for this profile: sum of Hurts weights on the objectives
    // we care about. Zero means it doesn't affect the profile - dropped.
    let relevance = |kind: &FindingKind| -> u32 {
        verum_lumen::rust_insights::impacts_for(kind)
            .into_iter()
            .filter(|imp| {
                objectives.contains(&imp.objective) && matches!(imp.direction, Direction::Hurts)
            })
            .map(|imp| imp.weight as u32)
            .sum()
    };

    let mut by_kind: HashMap<String, (u32, Vec<&verum_nucleus::Finding>)> = HashMap::new();
    for f in &prism.findings {
        let score = relevance(&f.kind);
        if score == 0 {
            continue;
        }
        let entry = by_kind
            .entry(format!("{:?}", f.kind))
            .or_insert((score, Vec::new()));
        entry.1.push(f);
    }

    let mut groups: Vec<(String, u32, Vec<&verum_nucleus::Finding>)> = by_kind
        .into_iter()
        .map(|(k, (score, fs))| (k, score, fs))
        .collect();
    // Highest per-occurrence impact first, then most occurrences.
    groups.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then(b.2.len().cmp(&a.2.len()))
            .then(a.0.cmp(&b.0))
    });

    let advisories: Vec<Value> = groups
        .iter()
        .map(|(kind, score, fs)| {
            let impacts: Vec<String> = verum_lumen::rust_insights::impacts_for(&fs[0].kind)
                .into_iter()
                .filter(|imp| objectives.contains(&imp.objective))
                .map(|imp| {
                    format!(
                        "{} {}",
                        match imp.direction {
                            Direction::Hurts => "hurts",
                            Direction::Helps => "helps",
                        },
                        imp.objective.label()
                    )
                })
                .collect();
            let mut locations: Vec<String> = fs
                .iter()
                .map(|f| format!("{}:{}", rel(root, &f.file), f.line_start))
                .collect();
            locations.sort();
            let shown = locations.len().min(8);
            json!({
                "construct": kind,
                "impact_weight": score,
                "affects": impacts,
                "occurrences": fs.len(),
                "advice": fs[0].suggestion,
                "locations": &locations[..shown],
                "more_locations": fs.len().saturating_sub(shown),
            })
        })
        .collect();

    // Design-mapping hints keyed to what's actually present in the tree.
    let has = |needle: &str| advisories.iter().any(|a| a["construct"] == needle);
    let mut mappings = Vec::new();
    let realtime =
        objectives.contains(&Objective::Latency) || objectives.contains(&Objective::Determinism);
    if realtime && has("UnboundedChannel") {
        mappings.push("Unbounded channels buffer latency without bound under load - for real-time/latency-critical paths prefer a bounded channel or a fixed-capacity ring buffer (e.g. `ringbuf`, `rtrb`) with an explicit drop-oldest policy.");
    }
    if realtime && has("LockOnHotPath") {
        mappings.push("Locks on a hot path serialize work and add tail latency - consider sharding, per-core state, an `arc-swap` snapshot, or a lock-free structure (`crossbeam`).");
    }
    if realtime && has("HotPathAllocation") {
        mappings.push("Per-message allocation on a hot path costs latency and jitter - reuse a buffer pool, slice `bytes::Bytes` off one recv buffer, or use an arena.");
    }
    if objectives.contains(&Objective::Throughput) && has("BlockingInAsync") {
        mappings.push("Blocking calls inside async stall the executor thread - move them to `spawn_blocking` or a dedicated thread pool to keep throughput up.");
    }

    json!({
        "profile": profile,
        "optimising_for": objectives.iter().map(|o| o.label()).collect::<Vec<_>>(),
        "note": "Advisory only - informational, not scored, and only produced when explicitly requested.",
        "advisories": advisories,
        "design_mappings": mappings,
        "language_note": if ir.metadata.language == verum_nucleus::Language::Rust {
            "Rust systems-code lens active."
        } else {
            "Perf lens is tuned for Rust; other languages get limited signal."
        },
    })
}

/// Cross-language endpoint reconciliation: which client HTTP calls hit which
/// routes, which frontend calls hit NO route (likely 404 bugs / typos), and
/// which routes NO client calls (possibly-dead endpoints).
fn endpoints_view(ir: &Ir, root: &Path) -> Value {
    use verum_mappa::endpoints::{method_key, path_pattern};

    let route_keys: HashSet<String> = ir
        .routes
        .iter()
        .flat_map(|r| {
            let p = path_pattern(&r.path);
            let m = method_key(&r.method);
            // an `any` route answers every verb
            if m == "any" {
                ["get", "post", "put", "patch", "delete"]
                    .iter()
                    .map(|v| format!("{v} {p}"))
                    .collect::<Vec<_>>()
            } else {
                vec![format!("{m} {p}")]
            }
        })
        .collect();

    let mut called_keys: HashSet<String> = HashSet::new();
    let mut orphan_calls = Vec::new();
    for c in &ir.http_calls {
        let key = format!("{} {}", method_key(&c.method), path_pattern(&c.path));
        called_keys.insert(key.clone());
        if !route_keys.contains(&key) {
            orphan_calls.push(json!({
                "method": method_key(&c.method).to_uppercase(),
                "path": c.path,
                "site": format!("{}:{}", rel(root, &c.file), c.line),
            }));
        }
    }

    let orphan_routes: Vec<Value> = ir
        .routes
        .iter()
        .filter(|r| {
            let m = method_key(&r.method);
            let p = path_pattern(&r.path);
            if m == "any" {
                !["get", "post", "put", "patch", "delete"]
                    .iter()
                    .any(|v| called_keys.contains(&format!("{v} {p}")))
            } else {
                !called_keys.contains(&format!("{m} {p}"))
            }
        })
        .map(|r| {
            json!({
                "method": method_key(&r.method).to_uppercase(),
                "path": r.path,
                "handler": r.controller.and_then(|id| ir.symbols.get(&id)).map(|s| s.fully_qualified.clone()),
                "site": format!("{}:{}", rel(root, &r.file), r.line),
            })
        })
        .collect();

    json!({
        "routes": ir.routes.len(),
        "client_http_calls": ir.http_calls.len(),
        "note": "Cross-language: client calls are matched to route handlers across the frontend/backend boundary.",
        "frontend_calls_with_no_route": orphan_calls,
        "routes_with_no_client_call": orphan_routes,
    })
}

fn overview(ir: &Ir, prism: &PrismResult, root: &Path) -> Value {
    let mut languages: HashMap<String, usize> = HashMap::new();
    for f in ir.files.values() {
        *languages.entry(format!("{:?}", f.language)).or_default() += 1;
    }

    // In-tree "roots": symbol names and the head segment of every module path.
    // An unresolved call whose head is one of these is a genuine resolution gap;
    // anything else calls into std/a dependency and is unresolvable by design.
    let mut in_tree_roots: HashSet<&str> = HashSet::new();
    for s in ir.symbols.values() {
        in_tree_roots.insert(s.name.as_str());
        if let Some(root) = s.fully_qualified.split("::").next() {
            in_tree_roots.insert(root);
        }
    }
    let call_head = |name: &str| -> String {
        name.chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect()
    };

    let (mut resolved, mut in_tree_unresolved, mut external, mut dynamic) = (0, 0, 0, 0);
    for c in &ir.calls {
        match &c.callee {
            CallTarget::Resolved(_) => resolved += 1,
            CallTarget::Unresolved(n) => {
                let head = call_head(n);
                if matches!(head.as_str(), "self" | "Self" | "crate" | "super")
                    || in_tree_roots.contains(head.as_str())
                {
                    in_tree_unresolved += 1;
                } else {
                    external += 1;
                }
            }
            CallTarget::Dynamic(_) | CallTarget::Magic(_) => dynamic += 1,
        }
    }
    // Resolution rate over calls that *could* resolve in-tree (excludes external
    // and dynamic), so it reflects the analyzer's actual reach, not the noise.
    let resolvable = resolved + in_tree_unresolved;
    let resolution_rate = if resolvable > 0 {
        (resolved as f64 / resolvable as f64 * 100.0).round() / 100.0
    } else {
        1.0
    };

    // Symbol graph analytics on resolved edges only. Nodes sorted for
    // deterministic indices.
    let mut ids: Vec<SymbolId> = ir.symbols.keys().copied().collect();
    ids.sort_by_key(|id| {
        ir.symbols
            .get(id)
            .map(|s| (s.file.clone(), s.line_start, s.name.clone()))
    });
    let index: HashMap<SymbolId, usize> = ids.iter().enumerate().map(|(i, id)| (*id, i)).collect();
    let edges: Vec<(usize, usize)> = ir
        .calls
        .iter()
        .filter_map(|c| match &c.callee {
            CallTarget::Resolved(t) => Some((*index.get(&c.caller)?, *index.get(t)?)),
            _ => None,
        })
        .collect();
    let analytics = crate::graph::analyse_digraph(ids.len(), &edges);

    let mut ranked: Vec<(usize, f64)> = analytics.pagerank.iter().copied().enumerate().collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let top: Vec<Value> = ranked
        .iter()
        .take(10)
        .filter_map(|(i, rank)| {
            let sym = ir.symbols.get(&ids[*i])?;
            Some(json!({
                "symbol": sym.fully_qualified,
                "file": rel(root, &sym.file),
                "pagerank": (rank * 10_000.0).round() / 10_000.0,
            }))
        })
        .collect();

    json!({
        "root": root.to_string_lossy(),
        "files": ir.metadata.total_files,
        "lines": ir.metadata.total_lines,
        "symbols": ir.symbols.len(),
        "languages": languages,
        "calls": {
            "resolved": resolved,
            "in_tree_unresolved": in_tree_unresolved,
            "external": external,
            "dynamic": dynamic,
            "in_tree_resolution_rate": resolution_rate,
        },
        "entry_points": ir.entry_points.len(),
        "routes": ir.routes.len(),
        "score": prism.score,
        "findings": prism.findings.len(),
        "call_graph": {
            "critical_depth": analytics.critical_depth,
            "layering_violations": analytics.layering_violations,
            "articulation_points": analytics.articulation.iter().filter(|a| **a).count(),
            "most_central": top,
        },
    })
}

fn changed_files(root: &Path, git_ref: &str) -> Result<HashSet<PathBuf>, String> {
    let run = |args: &[&str]| -> Result<String, String> {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .map_err(|e| format!("failed to run git: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    };

    let repo_root = PathBuf::from(run(&["rev-parse", "--show-toplevel"])?.trim().to_string());
    let diff = run(&["diff", "--name-only", git_ref, "--"])?;
    let untracked = run(&["ls-files", "--others", "--exclude-standard"])?;

    let mut files = HashSet::new();
    for line in diff.lines().chain(untracked.lines()) {
        if line.is_empty() {
            continue;
        }
        // Deleted files no longer canonicalize; they drop out here, which is
        // right - there is nothing left to have findings in.
        if let Ok(canon) = std::fs::canonicalize(repo_root.join(line)) {
            files.insert(canon);
        }
    }
    Ok(files)
}

fn symbol_json(ir: &Ir, root: &Path, id: SymbolId) -> Value {
    match ir.symbols.get(&id) {
        Some(s) => json!({
            "name": s.name,
            "fully_qualified": s.fully_qualified,
            "kind": format!("{:?}", s.kind),
            "location": format!("{}:{}", rel(root, &s.file), s.line_start),
            "visibility": format!("{:?}", s.visibility),
            "entry_point": s.is_entry_point,
        }),
        None => json!({ "missing_symbol": format!("{:?}", id) }),
    }
}

fn finding_json(f: &verum_nucleus::Finding, root: &Path) -> Value {
    json!({
        "id": f.id,
        "kind": format!("{:?}", f.kind),
        "severity": format!("{:?}", f.severity),
        "confidence": f.confidence,
        "location": format!("{}:{}", rel(root, &f.file), f.line_start),
        "message": f.message,
        "suggestion": f.suggestion,
    })
}

/// Last path segment of a call name across the qualifier styles the IR uses.
fn final_segment(name: &str) -> &str {
    let n = name.rsplit("::").next().unwrap_or(name);
    let n = n.rsplit("->").next().unwrap_or(n);
    let n = n.rsplit('.').next().unwrap_or(n);
    n.rsplit('\\').next().unwrap_or(n)
}

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing required argument: {key}"))
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        "info" => Ok(Severity::Info),
        other => Err(format!("unknown severity: {other}")),
    }
}

fn tool_definitions() -> Vec<Value> {
    let sym_query = json!({
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Symbol name - short (`getUserById`) or fully qualified (`App\\Helpers\\UserHelper::getUserById`)."
            }
        },
        "required": ["query"]
    });

    let mut tools = vec![
        json!({
            "name": "overview",
            "description": "Orient in the codebase: size, languages, call-graph shape (resolution rates, critical depth, most central symbols by PageRank), score, and finding count.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "find_symbol",
            "description": "Search symbols by name (exact, then substring). Returns kind, location, visibility, and entry-point status for each match.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Name or name fragment." },
                    "limit": { "type": "integer", "description": "Max results (default 20)." }
                },
                "required": ["query"]
            }
        }),
        json!({
            "name": "definition_of",
            "description": "Where is this symbol defined? Exact-match first (fully qualified, then short name), substring as fallback - the result says which tier matched.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Symbol name or name fragment." }
                },
                "required": ["query"]
            }
        }),
        json!({
            "name": "references_of",
            "description": "Every reference to this symbol: call sites from the resolved call graph, plus weaker name-based matches reported separately so you know the confidence of each.",
            "inputSchema": sym_query
        }),
        json!({
            "name": "callers_of",
            "description": "Who calls this symbol? Direct callers with exact call sites (file:line). Facts from the resolved call graph - no guessing.",
            "inputSchema": sym_query
        }),
        json!({
            "name": "callees_of",
            "description": "What does this symbol call? Resolved callees with call sites, plus unresolved and dynamic call names it makes.",
            "inputSchema": sym_query
        }),
        json!({
            "name": "impact_of",
            "description": "Blast radius: every symbol that transitively reaches this one, and the files they live in - what could break if it changes.",
            "inputSchema": sym_query
        }),
        json!({
            "name": "dead_code",
            "description": "Symbols with no resolved caller, no name-match caller, and no path from any entry point. Confidence-scored; dynamic-dispatch risk lowers confidence.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "audit",
            "description": "Full deterministic audit: security, dead code, duplicates, naming, complexity, infrastructure. Returns the score and findings (filterable, capped).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "min_severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info"], "description": "Only findings at or above this severity." },
                    "limit": { "type": "integer", "description": "Max findings listed (default 100); counts are always exact." }
                }
            }
        }),
        json!({
            "name": "audit_delta",
            "description": "Findings only in files changed vs a git ref (e.g. `HEAD`, `origin/main`) - the right scope for judging a diff. The whole tree is still analysed so cross-file facts stay correct.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "git_ref": { "type": "string", "description": "Base git ref to diff against." }
                },
                "required": ["git_ref"]
            }
        }),
        json!({
            "name": "perf_advice",
            "description": "OPT-IN performance advisory for a chosen profile (latency | throughput | memory | cpu | realtime | all). Surfaces the constructs that hurt that objective - hot-path allocations, locks, unbounded channels, blocking-in-async - ranked by impact, each with a concrete design fix (e.g. ring buffer vs unbounded channel). Informational; call it only when the user wants performance-tuning guidance.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "profile": {
                        "type": "string",
                        "enum": ["latency", "throughput", "memory", "cpu", "realtime", "all"],
                        "description": "What to optimise for. Defaults to all."
                    }
                }
            }
        }),
        json!({
            "name": "endpoints",
            "description": "Cross-language endpoint reconciliation: matches client HTTP calls (fetch/axios) to the backend route handlers that serve them, and flags frontend calls that hit NO route (likely 404s/typos) and routes with NO caller (possibly-dead endpoints) - findings no single-language tool can produce.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "duplicates",
            "description": "Duplicate implementations: exact, renamed (identifier-insensitive), and structural copies, grouped with a canonical pick per group.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
    ];
    // Every Verum tool is a read-only, side-effect-free query over the analyzed
    // tree. Advertise that through MCP tool annotations so a client can safely
    // auto-approve and cache the calls.
    for tool in &mut tools {
        if let Value::Object(map) = tool {
            map.insert(
                "annotations".into(),
                json!({
                    "readOnlyHint": true,
                    "idempotentHint": true,
                    "destructiveHint": false,
                    "openWorldHint": false
                }),
            );
        }
    }
    tools
}
