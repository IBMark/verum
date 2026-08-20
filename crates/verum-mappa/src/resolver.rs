use std::path::Path;

use rustc_hash::FxHashMap;

use verum_nucleus::{CallTarget, Ir, SymbolId, SymbolKind};

/// The class a symbol belongs to: itself if it is a class, else its parent.
fn enclosing_class(ir: &Ir, caller: SymbolId) -> Option<SymbolId> {
    let sym = ir.symbols.get(&caller)?;
    if matches!(
        sym.kind,
        SymbolKind::Class | SymbolKind::Trait | SymbolKind::Interface
    ) {
        Some(caller)
    } else {
        sym.parent
    }
}

/// Split `Class::method` / `Class->method` into (class, method) when the left
/// side is a bare class-like token (not `$this`/`self`/`static`/`parent`).
fn split_qualified(name: &str) -> Option<(&str, &str)> {
    let (cls, method) = name.rsplit_once("::").or_else(|| name.rsplit_once("->"))?;
    let cls = cls.rsplit(['\\', '/']).next().unwrap_or(cls);
    if cls.is_empty()
        || method.is_empty()
        || method.contains(['-', ':', '(', ' '])
        || cls.starts_with('$')
        || matches!(cls, "self" | "static" | "parent")
        || !cls.chars().next().is_some_and(|c| c.is_ascii_uppercase())
    {
        return None;
    }
    Some((cls, method))
}

/// Strip a receiver prefix from a call name, returning the bare method name if
/// the receiver is `$this` / `self` / `static` / `parent` (an intra-class call
/// that receiver-aware resolution can bind to the caller's own class).
fn self_method(name: &str) -> Option<&str> {
    // `$this->m` (PHP), `self::m`/`static::m`/`parent::m` (PHP + Rust paths),
    // `self.m` (Rust method call).
    for pfx in ["$this->", "self::", "static::", "parent::", "self."] {
        if let Some(rest) = name.strip_prefix(pfx) {
            if !rest.is_empty() && !rest.contains(['-', ':', '.', '(', ' ']) {
                return Some(rest);
            }
        }
    }
    None
}

/// Resolve unresolved call targets to known symbols.
///
/// Strategies, in order:
/// 1. Exact match on fully qualified name
/// 2. Unambiguous match on short name
/// 3. Unambiguous match on the final segment (after `\`, `::`, `->`, `.`)
/// 4. Suffix match: a call to "Foo\Bar" resolves to the FQ name ending in it
///
/// Resolution is deterministic: lookup tables are built from symbols in
/// (file, line, name) order, and a name shared by several symbols is only
/// resolved when exactly one candidate exists - guessing between same-named
/// methods across classes would attribute calls to a random symbol and change
/// between runs (HashMap iteration order is not stable).
///
/// Split into a read-only decision phase and an apply phase: decisions borrow
/// call names and index keys straight out of `ir`, and strategies 1-4 (plus
/// the receiver-free strategy 0b) depend only on `(name, call.file)`, so their
/// outcome is memoized per distinct pair instead of recomputed per call site.
pub fn resolve(ir: &mut Ir) {
    let decisions = decide_all(ir);
    for (idx, target) in decisions {
        ir.calls[idx].callee = target;
    }
}

/// Read-only phase: compute, in call order, every call whose target changes.
fn decide_all(ir: &Ir) -> Vec<(usize, CallTarget)> {
    let mut ordered: Vec<(SymbolId, &verum_nucleus::Symbol)> =
        ir.symbols.iter().map(|(id, s)| (*id, s)).collect();
    ordered.sort_by(|a, b| {
        (&a.1.file, a.1.line_start, &a.1.name).cmp(&(&b.1.file, b.1.line_start, &b.1.name))
    });

    let mut by_name: FxHashMap<&str, Vec<SymbolId>> = FxHashMap::default();
    // Several symbols can share one fully-qualified name - a private helper
    // repeated per module (Rust `hash_path`, Go `init`) is the common case.
    // Keeping only the first would bind every caller to one arbitrary
    // definition and leave the rest looking uncalled, so track them all.
    let mut by_fq: FxHashMap<&str, Vec<SymbolId>> = FxHashMap::default();
    // Suffix index: last segment of FQ name -> Vec of (FQ name, SymbolId)
    let mut by_suffix: FxHashMap<&str, Vec<(&str, SymbolId)>> = FxHashMap::default();

    // Receiver-aware indexes: methods keyed by parent class then method name
    // (nested so lookups work with a borrowed `&str`, no per-lookup String),
    // and classes by short name (for `new Class` / `Class::method`).
    let mut method_by_parent: FxHashMap<SymbolId, FxHashMap<&str, SymbolId>> = FxHashMap::default();
    let mut class_by_name: FxHashMap<&str, Vec<SymbolId>> = FxHashMap::default();

    for (id, sym) in &ordered {
        by_name.entry(sym.name.as_str()).or_default().push(*id);
        by_fq
            .entry(sym.fully_qualified.as_str())
            .or_default()
            .push(*id);

        match sym.kind {
            SymbolKind::Method | SymbolKind::StaticMethod => {
                if let Some(parent) = sym.parent {
                    method_by_parent
                        .entry(parent)
                        .or_default()
                        .entry(sym.name.as_str())
                        .or_insert(*id);
                }
            }
            SymbolKind::Class | SymbolKind::Trait | SymbolKind::Interface => {
                class_by_name
                    .entry(sym.name.as_str())
                    .or_default()
                    .push(*id);
            }
            _ => {}
        }

        let fq = sym.fully_qualified.as_str();
        if let Some(suffix) = fq.rsplit('\\').next() {
            by_suffix.entry(suffix).or_default().push((fq, *id));
        }
        if let Some(suffix) = fq.rsplit("::").next() {
            if suffix != fq {
                by_suffix.entry(suffix).or_default().push((fq, *id));
            }
        }
    }

    // File of each symbol, for disambiguating same-named definitions.
    let sym_file: FxHashMap<SymbolId, &Path> = ordered
        .iter()
        .map(|(id, s)| (*id, s.file.as_path()))
        .collect();

    // Resolve a set of same-named candidates against the call site. A lone
    // candidate wins outright; otherwise the definition in the caller's own
    // file wins, which is what module-private helpers actually bind to.
    // Still ambiguous means no edge - a wrong edge is worse than none, and
    // leaving it Unresolved lets name-based liveness keep every definition.
    let disambiguate = |ids: Option<&Vec<SymbolId>>, call_file: &Path| -> Option<SymbolId> {
        let ids = ids?;
        match ids.len() {
            0 => None,
            1 => Some(ids[0]),
            _ => {
                let mut local = ids
                    .iter()
                    .filter(|id| sym_file.get(*id).map(|f| *f == call_file).unwrap_or(false));
                let first = local.next()?;
                match local.next() {
                    Some(_) => None,
                    None => Some(*first),
                }
            }
        }
    };

    // Strategies 0b and 1-4, all functions of (name, call file) only.
    let decide_by_name_and_file = |name: &str, call_file: &Path| -> Option<SymbolId> {
        // Strategy 0b: `Class::method` / `Class->method` where Class is
        // a known, unambiguous class -> its method of that name.
        if let Some((cls, method)) = split_qualified(name) {
            if let Some(classes) = class_by_name.get(cls) {
                if classes.len() == 1 {
                    if let Some(id) = method_by_parent
                        .get(&classes[0])
                        .and_then(|methods| methods.get(method))
                    {
                        return Some(*id);
                    }
                }
            }
        }

        // Strategy 1: Exact FQ match
        if let Some(id) = disambiguate(by_fq.get(name), call_file) {
            return Some(id);
        }

        // Strategy 2: Unambiguous short name match
        if let Some(id) = disambiguate(by_name.get(name), call_file) {
            return Some(id);
        }

        // Strategy 3: Final segment (strip each qualifier in turn)
        let last_segment = {
            let n = name.rsplit('\\').next().unwrap_or(name);
            let n = n.rsplit("::").next().unwrap_or(n);
            let n = n.rsplit("->").next().unwrap_or(n);
            n.rsplit('.').next().unwrap_or(n)
        };

        if last_segment != name {
            if let Some(id) = disambiguate(by_fq.get(last_segment), call_file) {
                return Some(id);
            }
            if let Some(id) = disambiguate(by_name.get(last_segment), call_file) {
                return Some(id);
            }
        }

        // Strategy 4: Suffix index for partial namespace matches
        if let Some(candidates) = by_suffix.get(last_segment) {
            if candidates.len() == 1 {
                return Some(candidates[0].1);
            }
            // Multiple candidates: only a full suffix match on the
            // original (qualified) name is trustworthy.
            if name != last_segment {
                if let Some((_, id)) = candidates.iter().find(|(fq, _)| fq.ends_with(name)) {
                    return Some(*id);
                }
            }
        }

        // Otherwise leave as Unresolved - dead_code uses called_names
        // to still mark these as "alive" by name match
        None
    };

    // Precompute each caller's enclosing class for strategy 0a.
    let caller_class: FxHashMap<SymbolId, SymbolId> = ordered
        .iter()
        .filter_map(|(id, _)| enclosing_class(ir, *id).map(|c| (*id, c)))
        .collect();

    let mut decisions: Vec<(usize, CallTarget)> = Vec::new();
    let mut memo: FxHashMap<(&str, &Path), Option<SymbolId>> = FxHashMap::default();

    for (idx, call) in ir.calls.iter().enumerate() {
        if let CallTarget::Unresolved(name) = &call.callee {
            if name.contains("$$") || name == "call_user_func" || name == "call_user_func_array" {
                decisions.push((idx, CallTarget::Dynamic(name.clone())));
                continue;
            }

            // Strategy 0a: receiver-aware intra-class call
            // (`$this->m()`, `self::m()`, `static::m()`, `parent::m()`).
            // Bind to a method named `m` on the caller's own class - the
            // single biggest source of resolvable OO calls. Depends on the
            // caller, so it stays per call site, ahead of the memoized rest.
            if let Some(method) = self_method(name) {
                if let Some(class) = caller_class.get(&call.caller) {
                    if let Some(id) = method_by_parent
                        .get(class)
                        .and_then(|methods| methods.get(method))
                    {
                        decisions.push((idx, CallTarget::Resolved(*id)));
                        continue;
                    }
                }
            }

            let resolved = *memo
                .entry((name.as_str(), call.file.as_path()))
                .or_insert_with(|| decide_by_name_and_file(name, &call.file));
            if let Some(id) = resolved {
                decisions.push((idx, CallTarget::Resolved(id)));
            }
        }
    }

    decisions
}
