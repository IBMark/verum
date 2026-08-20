use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use regex::Regex;

use verum_nucleus::{
    matchable_path, CallTarget, Finding, FindingKind, Framework, Ir, Language, Severity, SymbolId,
    SymbolKind, Visibility,
};

use crate::DeadCodeConfig;

/// Called by the runtime/framework, so never dead regardless of callers.
const MAGIC_METHODS: &[&str] = &[
    "__construct",
    "__destruct",
    "__get",
    "__set",
    "__call",
    "__callStatic",
    "__toString",
    "__invoke",
    "boot",
    "register",
    "handle",
    "up",
    "down",
    "run",
    "setUp",
    "tearDown",
];

/// Go methods called implicitly or through a standard-library interface, so a
/// static call graph never sees a caller. `Get*` protobuf accessors live in
/// generated `.pb.go` files, which are filtered as auxiliary paths elsewhere.
fn is_go_implicit_method(name: &str) -> bool {
    matches!(
        name,
        "init"
            | "String"
            | "GoString"
            | "Error"
            | "MarshalJSON"
            | "UnmarshalJSON"
            | "MarshalText"
            | "UnmarshalText"
            | "MarshalBinary"
            | "UnmarshalBinary"
            | "MarshalYAML"
            | "UnmarshalYAML"
            | "Read"
            | "Write"
            | "Close"
            | "Seek"
            | "Flush"
            | "ServeHTTP"
            | "Reset"
            | "Len"
            | "Less"
            | "Swap"
            | "ProtoReflect"
            | "ProtoMessage"
            | "Descriptor"
    )
}

/// Laravel framework methods that are called by the framework, not user code.
const LARAVEL_ENTRY_METHODS: &[&str] = &[
    // Service providers
    "boot",
    "register",
    "provides",
    "bindings",
    "singletons",
    // Commands
    "handle",
    "execute",
    "schedule",
    // Middleware
    "terminate",
    // Events / listeners
    "subscribe",
    "broadcastOn",
    "broadcastAs",
    "broadcastWith",
    "broadcastQueue",
    // Notifications
    "toMail",
    "toArray",
    "toDatabase",
    "toBroadcast",
    "toSlack",
    "via",
    // Validation
    "passes",
    "message",
    "messages",
    "rules",
    "authorize",
    // Jobs
    "failed",
    "retryUntil",
    "uniqueId",
    "tags",
    "middleware",
    // Model events
    "creating",
    "created",
    "updating",
    "updated",
    "deleting",
    "deleted",
    "saving",
    "saved",
    "restoring",
    "restored",
    "forceDeleted",
    // Route model binding
    "resolveRouteBinding",
    "resolveChildRouteBinding",
    "getRouteKeyName",
    "getRouteKey",
    // Policies
    "before",
    // Casts
    "get",
    "set",
    // Blade components
    "render",
    "shouldRender",
    // Fractal transformers
    "transform",
    // Standard resource controller actions (called via Route::resource)
    "index",
    "show",
    "create",
    "store",
    "edit",
    "update",
    "destroy",
    // Common controller methods
    "view",
    // Permission / gate methods
    "permission",
    "definition",
    // Eloquent
    "attributes",
    "getFacadeAccessor",
];

/// Eloquent accessors/mutators (getXAttribute/setXAttribute), scopes (scopeX)
/// and Fractal includes (includeX) - invoked by name convention, never directly.
fn is_laravel_magic_method(name: &str) -> bool {
    if name.starts_with("get") && name.ends_with("Attribute") && name.len() > 12 {
        return true;
    }
    if name.starts_with("set") && name.ends_with("Attribute") && name.len() > 12 {
        return true;
    }
    if name.starts_with("scope") && name.len() > 5 {
        let after = &name[5..];
        if after.chars().next().is_some_and(|c| c.is_uppercase()) {
            return true;
        }
    }
    if name.starts_with("include") && name.len() > 7 {
        let after = &name[7..];
        if after.chars().next().is_some_and(|c| c.is_uppercase()) {
            return true;
        }
    }
    false
}

fn matches_custom_patterns(name: &str, patterns: &[Regex]) -> bool {
    patterns.iter().any(|re| re.is_match(name))
}

/// PascalCase export in a JS/TS file - likely a React component rendered via JSX.
fn is_react_component(sym: &verum_nucleus::Symbol) -> bool {
    let path_str = matchable_path(&sym.file);
    let is_tsx_jsx = path_str.ends_with(".tsx")
        || path_str.ends_with(".jsx")
        || path_str.ends_with(".ts")
        || path_str.ends_with(".js");
    if !is_tsx_jsx {
        return false;
    }
    if matches!(sym.visibility, Visibility::Public) {
        if let Some(first) = sym.name.chars().next() {
            if first.is_uppercase() {
                return true;
            }
        }
    }
    false
}

/// `useXxx` function in a JS/TS file - React custom hook.
fn is_react_hook(sym: &verum_nucleus::Symbol) -> bool {
    if !matches!(sym.kind, SymbolKind::Function) {
        return false;
    }
    let path_str = matchable_path(&sym.file);
    let is_js_ts = path_str.ends_with(".tsx")
        || path_str.ends_with(".jsx")
        || path_str.ends_with(".ts")
        || path_str.ends_with(".js");
    if !is_js_ts {
        return false;
    }
    if sym.name.starts_with("use") && sym.name.len() > 3 {
        let after = &sym.name[3..];
        if after.chars().next().is_some_and(|c| c.is_uppercase()) {
            return true;
        }
    }
    false
}

fn is_in_laravel_framework_path(sym: &verum_nucleus::Symbol) -> bool {
    let path_str = matchable_path(&sym.file);
    path_str.contains("/Models/")
        || path_str.contains("/Listeners/")
        || path_str.contains("/Events/")
        || path_str.contains("/Observers/")
        || path_str.contains("/Policies/")
        || path_str.contains("/Providers/")
        || path_str.contains("/Console/")
        || path_str.contains("/Jobs/")
        || path_str.contains("/Notifications/")
        || path_str.contains("/Casts/")
        || path_str.contains("/Mail/")
        || path_str.contains("/Middleware/")
        || path_str.contains("/Transformers/")
}

/// Flag functions/methods with no caller: not called by resolved id or by name,
/// and not reachable by BFS from the entry points. Laravel/React conventions are
/// whitelisted first, since framework-invoked code has no visible caller.
pub fn analyse(ir: &Ir, config: &DeadCodeConfig) -> Vec<Finding> {
    // Dynamic dispatch only blinds the analysis where it can plausibly reach:
    // a symbol is at risk if its name appears in a dynamic call expression, or
    // its own file contains one. Scoping it per symbol keeps one stray
    // `call_user_func` from dropping every dead-code finding in the codebase
    // below the auto-fix bar.
    let dynamic_exprs: Vec<String> = ir
        .calls
        .iter()
        .filter_map(|c| match &c.callee {
            CallTarget::Dynamic(expr) => Some(expr.to_lowercase()),
            _ => None,
        })
        .collect();
    let dynamic_files: HashSet<&PathBuf> = ir
        .calls
        .iter()
        .filter(|c| matches!(&c.callee, CallTarget::Dynamic(_)))
        .map(|c| &c.file)
        .collect();

    let is_laravel = ir.framework == Framework::Laravel;

    // A bad pattern is a config error the user should see, not a silent drop.
    let custom_patterns: Vec<Regex> = config
        .laravel_magic_patterns
        .iter()
        .filter_map(|p| match Regex::new(p) {
            Ok(re) => Some(re),
            Err(e) => {
                eprintln!("warning: invalid dead_code pattern `{}` ignored: {}", p, e);
                None
            }
        })
        .collect();

    let config_entry_points: HashSet<&str> = config
        .laravel_entry_points
        .iter()
        .map(|s| s.as_str())
        .collect();

    // Source roots of Rust library crates, i.e. the directory holding a
    // `lib.rs`. A `pub` item under one of these is the crate's external API and
    // its callers are outside the analysed tree, so it cannot be proven dead.
    // Binary crates get no such pass: there `pub` grants no external reach.
    let rust_lib_roots: Vec<PathBuf> = ir
        .files
        .keys()
        .filter(|p| p.file_name().map(|n| n == "lib.rs").unwrap_or(false))
        .filter_map(|p| p.parent().map(|d| d.to_path_buf()))
        .collect();

    let mut called_ids: HashSet<SymbolId> = HashSet::new();
    let mut called_names: HashSet<String> = HashSet::new();
    let mut adj: HashMap<SymbolId, Vec<SymbolId>> = HashMap::new();

    for call in &ir.calls {
        match &call.callee {
            CallTarget::Resolved(target) => {
                called_ids.insert(*target);
                adj.entry(call.caller).or_default().push(*target);
            }
            CallTarget::Unresolved(name) => {
                // Index the short name too so `Foo::bar` / `obj.bar` match `bar`.
                called_names.insert(name.clone());
                if let Some(short) = name.rsplit("::").next() {
                    called_names.insert(short.to_string());
                }
                if let Some(short) = name.rsplit('.').next() {
                    called_names.insert(short.to_string());
                }
            }
            CallTarget::Dynamic(_) => {}
            CallTarget::Magic(name) => {
                called_names.insert(name.clone());
            }
        }
    }

    // BFS reachability, seeded from route controllers and entry points.
    let mut reachable: HashSet<SymbolId> = HashSet::new();
    let mut queue: VecDeque<SymbolId> = VecDeque::new();

    for route in &ir.routes {
        if let Some(controller) = &route.controller {
            queue.push_back(*controller);
        }
    }
    for id in &ir.entry_points {
        queue.push_back(*id);
    }
    for (id, sym) in &ir.symbols {
        if sym.is_entry_point {
            queue.push_back(*id);
        }
    }

    while let Some(current) = queue.pop_front() {
        if !reachable.insert(current) {
            continue;
        }
        if let Some(targets) = adj.get(&current) {
            for t in targets {
                if !reachable.contains(t) {
                    queue.push_back(*t);
                }
            }
        }
    }

    let mut findings = Vec::new();

    // Whether a file sits under a Rust lib-crate root, memoized per file:
    // symbols cluster by file, so this replaces a roots-scan per symbol with
    // one per distinct file.
    let mut under_lib_root: HashMap<&Path, bool> = HashMap::new();

    for (id, sym) in &ir.symbols {
        match &sym.kind {
            SymbolKind::Function | SymbolKind::Method | SymbolKind::StaticMethod => {}
            _ => continue,
        }

        if sym.is_entry_point {
            continue;
        }

        if MAGIC_METHODS.contains(&sym.name.as_str()) {
            continue;
        }

        // Skip constructors and dunders across languages: JS `constructor`,
        // Python `__init__`/`__str__`/..., Go/Rust `main`/`new`.
        if sym.name == "constructor"
            || sym.name == "main"
            || sym.name == "new"
            || (sym.name.starts_with("__") && sym.name.ends_with("__") && sym.name.len() > 4)
        {
            continue;
        }

        // Go framework hooks: `init` runs at package load, and the standard
        // interface methods (Stringer, error, json.Marshaler, io.Reader, sort,
        // protobuf, ...) are called through interfaces the static call graph
        // cannot see. Flagging them as dead is a false positive.
        if sym.language == Language::Go && is_go_implicit_method(&sym.name) {
            continue;
        }

        // Atlas pseudo-symbols (file scope, blade, provider, config).
        if sym.name.starts_with("__file_scope_")
            || sym.name.starts_with("blade::")
            || sym.name.starts_with("provider::")
            || sym.name.starts_with("config::")
        {
            continue;
        }

        // Skip test suites but not fixtures - fixtures are analysis targets.
        let path_str = matchable_path(&sym.file);
        if (path_str.contains("/tests/") && !path_str.contains("fixtures"))
            || path_str.ends_with("Test.php")
            || path_str.ends_with("_test.rs")
            || path_str.ends_with("_test.go")
            || path_str.ends_with(".test.ts")
            || path_str.ends_with(".test.tsx")
            || path_str.ends_with(".spec.ts")
            || path_str.ends_with(".spec.tsx")
        {
            continue;
        }

        if path_str.contains("vendor") || path_str.contains("node_modules") {
            continue;
        }

        if is_laravel {
            if LARAVEL_ENTRY_METHODS.contains(&sym.name.as_str()) {
                continue;
            }
            if is_laravel_magic_method(&sym.name) {
                continue;
            }
            if config_entry_points.contains(sym.name.as_str()) {
                continue;
            }
            if matches_custom_patterns(&sym.name, &custom_patterns) {
                continue;
            }
            // Public methods in conventional Laravel dirs (Models/, Jobs/, ...)
            // are usually framework-invoked.
            if is_in_laravel_framework_path(sym)
                && matches!(sym.kind, SymbolKind::Method | SymbolKind::StaticMethod)
                && matches!(sym.visibility, Visibility::Public)
            {
                continue;
            }
        }

        if matches!(sym.language, Language::Rust) {
            // Each file under benches/ or examples/ is its own compiled target
            // with its own entry point (the bench harness, or the example's
            // `main`). Its helpers are reached only from within that file and
            // via convention macros (criterion_group!/criterion_main!), so they
            // have no cross-file caller and can't be proven dead from the main
            // call graph.
            if path_str.contains("/benches/") || path_str.contains("/examples/") {
                continue;
            }
            // Published API of a lib crate - callers live downstream, so an
            // absent in-crate call proves nothing (rustc's dead_code lint stays
            // quiet for exported items too).
            if matches!(sym.visibility, Visibility::Public)
                && *under_lib_root
                    .entry(sym.file.as_path())
                    .or_insert_with(|| rust_lib_roots.iter().any(|root| sym.file.starts_with(root)))
            {
                continue;
            }
            // A leading underscore is Rust's own "intentionally unused" marker.
            if sym.name.starts_with('_') {
                continue;
            }
            // Platform-specific code lives in os-named files/dirs and is
            // `#[cfg(...)]`-gated (often at the module, in another file we can't
            // see from here). It's compiled and called only in that target's
            // build, so "uncalled in this checkout" doesn't mean dead - e.g. the
            // Windows `ctrl_*` console handlers on a Linux tree.
            const PLATFORM_MARKERS: &[&str] = &[
                "/windows/",
                "/unix/",
                "/wasm/",
                "/wasi/",
                "/linux/",
                "/macos/",
                "/bsd/",
                "/darwin/",
                "/android/",
                "/ios/",
            ];
            const PLATFORM_FILES: &[&str] = &[
                "windows.rs",
                "unix.rs",
                "wasm.rs",
                "wasi.rs",
                "linux.rs",
                "macos.rs",
            ];
            if PLATFORM_MARKERS.iter().any(|m| path_str.contains(m))
                || PLATFORM_FILES.iter().any(|f| path_str.ends_with(f))
            {
                continue;
            }
        }

        if matches!(sym.language, Language::TypeScript | Language::JavaScript) {
            if is_react_component(sym) {
                continue;
            }
            if is_react_hook(sym) {
                continue;
            }
            if sym.name == "submit"
                || sym.name == "reset"
                || sym.name == "validate"
                || sym.name == "callback"
            {
                continue;
            }
            // onX / handleX handlers are typically passed as props, so the call
            // site is invisible to us.
            if sym.name.starts_with("on")
                && sym.name.len() > 2
                && sym.name.chars().nth(2).is_some_and(|c| c.is_uppercase())
            {
                continue;
            }
            if sym.name.starts_with("handle")
                && sym.name.len() > 6
                && sym.name.chars().nth(6).is_some_and(|c| c.is_uppercase())
            {
                continue;
            }
        }

        let is_called = called_ids.contains(id);
        let name_called =
            called_names.contains(&sym.name) || called_names.contains(&sym.fully_qualified);
        let is_reachable = reachable.contains(id);

        if is_called || name_called || is_reachable {
            continue;
        }

        let name_lower = sym.name.to_lowercase();
        let dynamic_risk = dynamic_files.contains(&sym.file)
            || dynamic_exprs.iter().any(|e| e.contains(&name_lower));
        let confidence = if dynamic_risk { 0.60 } else { 0.95 };

        findings.push(Finding {
            fingerprint: String::new(),
            id: format!("dead-{}", sym.fully_qualified),
            kind: FindingKind::DeadFunction,
            severity: Severity::Medium,
            confidence,
            file: sym.file.clone(),
            line_start: sym.line_start,
            line_end: sym.line_end,
            symbol: Some(*id),
            message: format!("Dead code: `{}` is never called", sym.name),
            suggestion: format!("Remove `{}` or add a call to it", sym.name),
            auto_fixable: confidence >= 0.85,
            related: Vec::new(),
        });
    }

    findings
}
