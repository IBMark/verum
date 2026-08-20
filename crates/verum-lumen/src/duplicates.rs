use std::collections::{HashMap, HashSet};

use verum_nucleus::{
    matchable_path, CallTarget, DuplicateGroup, Finding, FindingKind, Ir, Location, Severity,
    SimilarityKind, Symbol, SymbolId, SymbolKind,
};

/// Renamed/semantic grouping needs a body of at least this many lines
/// (line_end - line_start). One-liners normalize to the same token stream as
/// any other trivial accessor and would all group together.
const MIN_SPAN_FOR_RENAMED: u32 = 2;

/// Group duplicate functions/methods by exact, normalized and flow hash.
///
/// Deterministic: symbols are processed in (file, line) order and the canonical
/// member is the one with the most call sites, ties broken by position.
pub fn analyse(ir: &Ir) -> (Vec<Finding>, Vec<DuplicateGroup>) {
    let mut findings = Vec::new();
    let mut groups = Vec::new();

    let mut func_symbols: Vec<(SymbolId, &Symbol)> = ir
        .symbols
        .iter()
        .filter(|(_, sym)| {
            matches!(
                sym.kind,
                SymbolKind::Function | SymbolKind::Method | SymbolKind::StaticMethod
            )
        })
        // Entry points are trait-impl/provided methods, `main`, and framework
        // hooks - required-to-exist interface obligations (`is_write_vectored`,
        // `poll_flush`), not refactorable copy-paste. Test/bench/example setup
        // (`rt`, `main`, `bench_*`) is legitimately repetitive across files.
        // Both flood the duplicate report without being actionable.
        .filter(|(_, sym)| {
            if sym.is_entry_point {
                return false;
            }
            // `fixtures` are Verum's own analysis targets - never skip them.
            let p = matchable_path(&sym.file);
            if p.contains("fixtures") {
                return true;
            }
            !(p.contains("/benches/") || p.contains("/examples/") || p.contains("/tests/"))
        })
        .map(|(id, sym)| (*id, sym))
        .collect();
    func_symbols.sort_by(|a, b| {
        (&a.1.file, a.1.line_start, &a.1.name).cmp(&(&b.1.file, b.1.line_start, &b.1.name))
    });

    // Index every call once, by resolved id and by callee final-segment name,
    // so caller counts and call-site lookups are O(1) per symbol instead of a
    // full `ir.calls` scan per group member (that scan made duplicates the
    // dominant cost of an audit on large trees).
    let mut sites_by_id: HashMap<SymbolId, Vec<(std::path::PathBuf, u32)>> = HashMap::new();
    let mut sites_by_name: HashMap<String, Vec<(std::path::PathBuf, u32)>> = HashMap::new();
    for call in &ir.calls {
        match &call.callee {
            CallTarget::Resolved(id) => sites_by_id
                .entry(*id)
                .or_default()
                .push((call.file.clone(), call.line)),
            CallTarget::Unresolved(n) | CallTarget::Dynamic(n) | CallTarget::Magic(n) => {
                sites_by_name
                    .entry(final_segment(n).to_string())
                    .or_default()
                    .push((call.file.clone(), call.line))
            }
        }
    }
    // Canonical selection ranks members by raw call-site count, INCLUDING
    // repeated (file, line) pairs - snapshot the multiset sizes before the
    // buckets are deduplicated below, or canonical members would shift.
    let count_by_id: HashMap<SymbolId, usize> =
        sites_by_id.iter().map(|(id, v)| (*id, v.len())).collect();
    let count_by_name: HashMap<String, usize> = sites_by_name
        .iter()
        .map(|(n, v)| (n.clone(), v.len()))
        .collect();
    let caller_count = |id: SymbolId, sym: &Symbol| -> usize {
        count_by_id.get(&id).copied().unwrap_or(0)
            + count_by_name.get(sym.name.as_str()).copied().unwrap_or(0)
    };

    // Sort + dedup each shared bucket once, so call_sites_of can linearly
    // merge two already-sorted lists instead of re-sorting the same bucket
    // for every duplicate member (this dominated the pass's profile).
    for sites in sites_by_id.values_mut().chain(sites_by_name.values_mut()) {
        sites.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
        sites.dedup();
    }

    let mut grouped: HashSet<SymbolId> = HashSet::new();

    // (hash selector, similarity kind, finding kind, confidence, remappable)
    type Level = (fn(&Symbol) -> u64, SimilarityKind, FindingKind, f32, bool);
    let levels: [Level; 3] = [
        (
            |s| s.hash,
            SimilarityKind::Exact,
            FindingKind::ExactDuplicate,
            0.99,
            false,
        ),
        (
            |s| s.normalized_hash,
            SimilarityKind::Renamed,
            FindingKind::RenamedDuplicate,
            0.90,
            true,
        ),
        (
            |s| s.flow_hash,
            SimilarityKind::Semantic,
            FindingKind::SemanticDuplicate,
            0.70,
            true,
        ),
    ];

    for (hash_of, similarity, kind, confidence, needs_min_span) in levels {
        // Bucket in symbol order, remembering first-seen order for determinism.
        let mut buckets: HashMap<u64, Vec<(SymbolId, &Symbol)>> = HashMap::new();
        let mut bucket_order: Vec<u64> = Vec::new();
        for (id, sym) in &func_symbols {
            let h = hash_of(sym);
            if h == 0 || grouped.contains(id) {
                continue;
            }
            if needs_min_span && sym.line_end.saturating_sub(sym.line_start) < MIN_SPAN_FOR_RENAMED
            {
                continue;
            }
            let entry = buckets.entry(h).or_default();
            if entry.is_empty() {
                bucket_order.push(h);
            }
            entry.push((*id, sym));
        }

        for h in bucket_order {
            let members = &buckets[&h];
            if members.len() < 2 {
                continue;
            }
            // Most callers wins; ties go to the earliest member (they're
            // already position-sorted, hence usize::MAX - i).
            let canonical_idx = members
                .iter()
                .enumerate()
                .max_by_key(|(i, (id, sym))| (caller_count(*id, sym), usize::MAX - i))
                .map(|(i, _)| i)
                .unwrap_or(0);
            let (canonical, _) = members[canonical_idx];
            let duplicates: Vec<SymbolId> = members
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != canonical_idx)
                .map(|(_, (id, _))| *id)
                .collect();
            for (id, _) in members {
                grouped.insert(*id);
            }
            emit_group(
                ir,
                canonical,
                &duplicates,
                similarity.clone(),
                kind.clone(),
                confidence,
                &sites_by_id,
                &sites_by_name,
                &mut findings,
                &mut groups,
            );
        }
    }

    (findings, groups)
}

fn final_segment(name: &str) -> &str {
    let n = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let n = n.rsplit("::").next().unwrap_or(n);
    let n = n.rsplit("->").next().unwrap_or(n);
    n.rsplit('.').next().unwrap_or(n)
}

/// Call sites of a symbol (by resolved id or matching final name segment) -
/// the locations a remap would have to rewrite.
///
/// Both input buckets are pre-sorted and deduplicated by `analyse`, so this is
/// a linear merge (dropping cross-list (file, line) duplicates, exactly as the
/// old sort + dedup over the concatenation did).
fn call_sites_of(
    id: SymbolId,
    sym: &Symbol,
    sites_by_id: &HashMap<SymbolId, Vec<(std::path::PathBuf, u32)>>,
    sites_by_name: &HashMap<String, Vec<(std::path::PathBuf, u32)>>,
) -> Vec<Location> {
    let by_id: &[(std::path::PathBuf, u32)] =
        sites_by_id.get(&id).map(|v| v.as_slice()).unwrap_or(&[]);
    let by_name: &[(std::path::PathBuf, u32)] = sites_by_name
        .get(sym.name.as_str())
        .map(|v| v.as_slice())
        .unwrap_or(&[]);

    let description = format!("call to `{}`", sym.name);
    let loc = |(file, line): &(std::path::PathBuf, u32)| Location {
        file: file.clone(),
        line: *line,
        description: description.clone(),
    };

    let mut sites: Vec<Location> = Vec::with_capacity(by_id.len() + by_name.len());
    let (mut i, mut j) = (0, 0);
    while i < by_id.len() && j < by_name.len() {
        match (&by_id[i].0, by_id[i].1).cmp(&(&by_name[j].0, by_name[j].1)) {
            std::cmp::Ordering::Less => {
                sites.push(loc(&by_id[i]));
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                sites.push(loc(&by_name[j]));
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                sites.push(loc(&by_id[i]));
                i += 1;
                j += 1;
            }
        }
    }
    sites.extend(by_id[i..].iter().map(&loc));
    sites.extend(by_name[j..].iter().map(&loc));
    sites
}

#[allow(clippy::too_many_arguments)]
fn emit_group(
    ir: &Ir,
    canonical: SymbolId,
    duplicates: &[SymbolId],
    similarity: SimilarityKind,
    kind: FindingKind,
    confidence: f32,
    sites_by_id: &HashMap<SymbolId, Vec<(std::path::PathBuf, u32)>>,
    sites_by_name: &HashMap<String, Vec<(std::path::PathBuf, u32)>>,
    findings: &mut Vec<Finding>,
    groups: &mut Vec<DuplicateGroup>,
) {
    let canonical_sym = match ir.symbols.get(&canonical) {
        Some(s) => s,
        None => return,
    };

    let mut call_sites_to_remap = Vec::new();
    for dup_id in duplicates {
        if let Some(dup_sym) = ir.symbols.get(dup_id) {
            call_sites_to_remap.extend(call_sites_of(*dup_id, dup_sym, sites_by_id, sites_by_name));

            findings.push(Finding {
                fingerprint: String::new(),
                id: format!(
                    "dup-{}-{}",
                    canonical_sym.fully_qualified, dup_sym.fully_qualified
                ),
                kind: kind.clone(),
                severity: Severity::Medium,
                confidence,
                file: dup_sym.file.clone(),
                line_start: dup_sym.line_start,
                line_end: dup_sym.line_end,
                symbol: Some(*dup_id),
                message: format!(
                    "`{}` is a duplicate of `{}`",
                    dup_sym.name, canonical_sym.name
                ),
                suggestion: format!(
                    "Remap callers of `{}` to `{}` and remove the duplicate",
                    dup_sym.name, canonical_sym.name
                ),
                // Never auto-fixable: safe removal requires caller remapping.
                auto_fixable: false,
                related: vec![Location {
                    file: canonical_sym.file.clone(),
                    line: canonical_sym.line_start,
                    description: format!("Canonical: `{}`", canonical_sym.name),
                }],
            });
        }
    }

    groups.push(DuplicateGroup {
        canonical,
        duplicates: duplicates.to_vec(),
        similarity,
        call_sites_to_remap,
        confidence,
    });
}
