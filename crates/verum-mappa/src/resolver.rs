use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
pub fn resolve(ir: &mut Ir) {
    let mut ordered: Vec<(SymbolId, &verum_nucleus::Symbol)> =
        ir.symbols.iter().map(|(id, s)| (*id, s)).collect();
    ordered.sort_by(|a, b| {
        (&a.1.file, a.1.line_start, &a.1.name).cmp(&(&b.1.file, b.1.line_start, &b.1.name))
    });

    let mut by_name: HashMap<String, Vec<SymbolId>> = HashMap::new();
    // Several symbols can share one fully-qualified name - a private helper
    // repeated per module (Rust `hash_path`, Go `init`) is the common case.
    // Keeping only the first would bind every caller to one arbitrary
    // definition and leave the rest looking uncalled, so track them all.
    let mut by_fq: HashMap<String, Vec<SymbolId>> = HashMap::new();
    // Suffix index: last segment of FQ name -> Vec of (FQ name, SymbolId)
    let mut by_suffix: HashMap<String, Vec<(String, SymbolId)>> = HashMap::new();

    // Receiver-aware indexes: methods keyed by (parent class, method name),
    // and classes by short name (for `new Class` / `Class::method`).
    let mut method_by_parent: HashMap<(SymbolId, String), SymbolId> = HashMap::new();
    let mut class_by_name: HashMap<String, Vec<SymbolId>> = HashMap::new();

    for (id, sym) in &ordered {
        by_name.entry(sym.name.clone()).or_default().push(*id);
        by_fq
            .entry(sym.fully_qualified.clone())
            .or_default()
            .push(*id);

        match sym.kind {
            SymbolKind::Method | SymbolKind::StaticMethod => {
                if let Some(parent) = sym.parent {
                    method_by_parent
                        .entry((parent, sym.name.clone()))
                        .or_insert(*id);
                }
            }
            SymbolKind::Class | SymbolKind::Trait | SymbolKind::Interface => {
                class_by_name.entry(sym.name.clone()).or_default().push(*id);
            }
            _ => {}
        }

        let fq = &sym.fully_qualified;
        if let Some(suffix) = fq.rsplit('\\').next() {
            by_suffix
                .entry(suffix.to_string())
                .or_default()
                .push((fq.clone(), *id));
        }
        if let Some(suffix) = fq.rsplit("::").next() {
            if suffix != fq {
                by_suffix
                    .entry(suffix.to_string())
                    .or_default()
                    .push((fq.clone(), *id));
            }
        }
    }

    // File of each symbol, for disambiguating same-named definitions.
    let sym_file: HashMap<SymbolId, PathBuf> = ordered
        .iter()
        .map(|(id, s)| (*id, s.file.clone()))
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
                    .filter(|id| sym_file.get(*id).map(|f| f == call_file).unwrap_or(false));
                let first = local.next()?;
                match local.next() {
                    Some(_) => None,
                    None => Some(*first),
                }
            }
        }
    };

    // Precompute each caller's enclosing class so the mutable call loop below
    // doesn't need to borrow `ir.symbols` again.
    let caller_class: HashMap<SymbolId, SymbolId> = ordered
        .iter()
        .filter_map(|(id, _)| enclosing_class(ir, *id).map(|c| (*id, c)))
        .collect();

    for call in &mut ir.calls {
        if let CallTarget::Unresolved(name) = &call.callee {
            if name.contains("$$") || name == "call_user_func" || name == "call_user_func_array" {
                call.callee = CallTarget::Dynamic(name.clone());
                continue;
            }

            // Strategy 0a: receiver-aware intra-class call
            // (`$this->m()`, `self::m()`, `static::m()`, `parent::m()`).
            // Bind to a method named `m` on the caller's own class - the
            // single biggest source of resolvable OO calls.
            if let Some(method) = self_method(name) {
                if let Some(class) = caller_class.get(&call.caller) {
                    if let Some(id) = method_by_parent.get(&(*class, method.to_string())) {
                        call.callee = CallTarget::Resolved(*id);
                        continue;
                    }
                }
            }

            // Strategy 0b: `Class::method` / `Class->method` where Class is
            // a known, unambiguous class -> its method of that name.
            if let Some((cls, method)) = split_qualified(name) {
                if let Some(classes) = class_by_name.get(cls) {
                    if classes.len() == 1 {
                        if let Some(id) = method_by_parent.get(&(classes[0], method.to_string())) {
                            call.callee = CallTarget::Resolved(*id);
                            continue;
                        }
                    }
                }
            }

            // Strategy 1: Exact FQ match
            if let Some(id) = disambiguate(by_fq.get(name), &call.file) {
                call.callee = CallTarget::Resolved(id);
                continue;
            }

            // Strategy 2: Unambiguous short name match
            if let Some(id) = disambiguate(by_name.get(name), &call.file) {
                call.callee = CallTarget::Resolved(id);
                continue;
            }

            // Strategy 3: Final segment (strip each qualifier in turn)
            let last_segment = {
                let n = name.rsplit('\\').next().unwrap_or(name);
                let n = n.rsplit("::").next().unwrap_or(n);
                let n = n.rsplit("->").next().unwrap_or(n);
                n.rsplit('.').next().unwrap_or(n)
            };

            if last_segment != name {
                if let Some(id) = disambiguate(by_fq.get(last_segment), &call.file) {
                    call.callee = CallTarget::Resolved(id);
                    continue;
                }
                if let Some(id) = disambiguate(by_name.get(last_segment), &call.file) {
                    call.callee = CallTarget::Resolved(id);
                    continue;
                }
            }

            // Strategy 4: Suffix index for partial namespace matches
            if let Some(candidates) = by_suffix.get(last_segment) {
                if candidates.len() == 1 {
                    call.callee = CallTarget::Resolved(candidates[0].1);
                    continue;
                }
                // Multiple candidates: only a full suffix match on the
                // original (qualified) name is trustworthy.
                if name != last_segment {
                    if let Some((_, id)) = candidates.iter().find(|(fq, _)| fq.ends_with(name)) {
                        call.callee = CallTarget::Resolved(*id);
                    }
                }
            }

            // Otherwise leave as Unresolved - dead_code uses called_names
            // to still mark these as "alive" by name match
        }
    }
}
