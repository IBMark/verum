use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

use verum_nucleus::{
    Call, CallTarget, FileId, FileInfo, HttpCall, HttpMethod, Ir, Language, Route, Symbol,
    SymbolId, SymbolKind, Visibility,
};

/// Parse a Python file into a partial IR.
pub fn parse_file(path: &Path) -> Result<Ir> {
    let source =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let tree = crate::parser_pool::parse("python", || tree_sitter_python::LANGUAGE.into(), &source)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse {}", path.display()))?;

    let mut extractor = PythonExtractor {
        depth: 0,
        source: source.clone(),
        path: path.to_path_buf(),
        next_id: hash_path(path),
        current_class: None,
        current_function: None,
        file_scope: None,
        current_module: String::new(),
        router_prefixes: HashMap::new(),
        router_dependencies: HashMap::new(),
        symbol_guards: HashMap::new(),
        ir: Ir::new(),
    };

    extractor.walk_node(tree.root_node());

    let line_count = source.lines().count() as u32;
    let size_bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    let file_id = FileId(hash_path(path));
    let symbol_ids: Vec<SymbolId> = extractor.ir.symbols.keys().copied().collect();

    extractor.ir.files.insert(
        path.to_path_buf(),
        FileInfo {
            id: file_id,
            path: path.to_path_buf(),
            language: Language::Python,
            line_count,
            size_bytes,
            last_modified: 0,
            hash: hash_string(&source),
            symbols: symbol_ids,
        },
    );

    extractor.ir.metadata.total_files = 1;
    extractor.ir.metadata.total_lines = line_count as u64;

    Ok(extractor.ir)
}

struct PythonExtractor {
    /// Current `walk_node` recursion depth, checked against
    /// [`crate::MAX_RECURSION_DEPTH`] so a pathologically deep AST cannot
    /// overflow the stack (an abort no panic guard can catch).
    depth: usize,
    source: String,
    path: std::path::PathBuf,
    next_id: u64,
    current_class: Option<SymbolId>,
    current_function: Option<SymbolId>,
    file_scope: Option<SymbolId>,
    current_module: String,
    /// Variable name of an `APIRouter(prefix=...)` / `Blueprint(url_prefix=...)`
    /// -> its path prefix, so `@router.get("/x")` routes get the prefix applied.
    router_prefixes: HashMap<String, String>,
    /// Variable name of an `APIRouter(...)` / `FastAPI(...)` -> the auth
    /// dependencies declared on its constructor
    /// (`dependencies=[Depends(get_current_user)]`). FastAPI runs those for
    /// every route registered on the router, so each such route inherits them
    /// as middleware.
    router_dependencies: HashMap<String, Vec<String>>,
    /// Guards recorded per symbol: decorator guards on view functions/classes
    /// and DRF `permission_classes` class attributes. Copied onto routes that
    /// resolve to the symbol later in the file (Django `urls.py` entries, DRF
    /// router registrations, Tornado handler tables). Cross-file views never
    /// land here, so their routes keep an empty - "unknown" - middleware list.
    symbol_guards: HashMap<SymbolId, Vec<String>>,
    ir: Ir,
}

/// A route declared by a decorator on its handler: the verb, path, router
/// object name, and any `dependencies=[Depends(...)]` guards declared on the
/// decorator itself.
struct DecoratedRoute {
    method: HttpMethod,
    path: String,
    object: String,
    dependencies: Vec<String>,
}

impl PythonExtractor {
    fn alloc_id(&mut self) -> SymbolId {
        self.next_id += 1;
        SymbolId(self.next_id)
    }

    /// Get or create a file-scope pseudo symbol for top-level references.
    fn get_or_create_file_scope(&mut self) -> SymbolId {
        if let Some(id) = self.file_scope {
            return id;
        }
        let id = self.alloc_id();
        let symbol = Symbol {
            id,
            name: format!("__file_scope_{}", self.path.display()),
            fully_qualified: format!("__file_scope_{}", self.path.display()),
            kind: SymbolKind::Function,
            visibility: Visibility::Private,
            file: self.path.clone(),
            line_start: 1,
            line_end: 1,
            col_start: 0,
            col_end: 0,
            language: Language::Python,
            parent: None,
            hash: 0,
            normalized_hash: 0,
            flow_hash: 0,
            param_count: 0,
            is_entry_point: true,
            doc_comment: None,
        };
        self.ir.symbols.insert(id, symbol);
        self.file_scope = Some(id);
        id
    }

    fn fully_qualified(&self, name: &str) -> String {
        if self.current_module.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", self.current_module, name)
        }
    }

    fn node_text<'a>(&'a self, node: tree_sitter::Node<'a>) -> &'a str {
        node.utf8_text(self.source.as_bytes()).unwrap_or("")
    }

    fn hash_node(&self, node: tree_sitter::Node) -> (u64, u64) {
        let text = &self.source[node.start_byte()..node.end_byte()];
        (hash_string(text), hash_normalized(text))
    }

    /// Determine Python visibility from a name.
    /// - `__name__` (dunder) -> Public (magic method)
    /// - `__name` (name-mangled) -> Private
    /// - `_name` (single underscore) -> Private (convention)
    /// - otherwise -> Public
    fn python_visibility(name: &str) -> Visibility {
        if name.starts_with("__") && name.ends_with("__") && name.len() > 4 {
            Visibility::Public
        } else if name.starts_with('_') {
            // Both `__mangled` and `_convention` are private.
            Visibility::Private
        } else {
            Visibility::Public
        }
    }

    /// Extract the docstring from a function or class body if present.
    fn extract_docstring(&self, node: tree_sitter::Node) -> Option<String> {
        if let Some(body) = node.child_by_field_name("body") {
            if let Some(first_stmt) = body.child(0) {
                if first_stmt.kind() == "expression_statement" {
                    if let Some(expr) = first_stmt.child(0) {
                        if expr.kind() == "string" {
                            let text = self.node_text(expr).to_string();
                            let trimmed = text
                                .trim_start_matches("\"\"\"")
                                .trim_start_matches("'''")
                                .trim_end_matches("\"\"\"")
                                .trim_end_matches("'''")
                                .trim()
                                .to_string();
                            return Some(trimmed);
                        }
                    }
                }
            }
        }
        None
    }

    /// Depth-capped dispatch. A hostile file (10k nested parens, a
    /// megabyte-long `1+1+...` chain) parses into an AST deep enough that
    /// recursive descent overflows the stack, and a stack overflow ABORTS
    /// the process - no unwind, so the per-file panic guard cannot help.
    /// Nodes deeper than the fixed cap are skipped; the cutoff depends
    /// only on the input's AST shape (deterministic), and real code never
    /// comes within an order of magnitude of the cap.
    fn walk_node(&mut self, node: tree_sitter::Node) {
        if self.depth >= crate::MAX_RECURSION_DEPTH {
            return;
        }
        self.depth += 1;
        self.walk_node_inner(node);
        self.depth -= 1;
    }

    fn walk_node_inner(&mut self, node: tree_sitter::Node) {
        match node.kind() {
            "class_definition" => self.handle_class(node),
            "function_definition" => self.handle_function(node),
            "decorated_definition" => self.handle_decorated(node),
            "call" => self.handle_call(node),
            _ => {
                let child_count = node.child_count();
                for i in 0..child_count {
                    if let Some(child) = node.child(i as u32) {
                        self.walk_node(child);
                    }
                }
            }
        }
    }

    fn handle_class(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();
        let fq = self.fully_qualified(&name);
        let doc_comment = self.extract_docstring(node);

        let symbol = Symbol {
            id,
            name: name.clone(),
            fully_qualified: fq,
            kind: SymbolKind::Class,
            visibility: Visibility::Public,
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: Language::Python,
            parent: None,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count: 0,
            is_entry_point: false,
            doc_comment,
        };

        self.ir.symbols.insert(id, symbol);

        // DRF class-based views declare guards as a class attribute
        // (`permission_classes = [IsAuthenticated]`); record the class names
        // so routes that resolve to this class carry them as middleware.
        let attr_guards = self.class_permission_guards(node);
        if !attr_guards.is_empty() {
            self.symbol_guards
                .entry(id)
                .or_default()
                .extend(attr_guards);
        }

        let prev_class = self.current_class.take();
        self.current_class = Some(id);

        if let Some(body) = node.child_by_field_name("body") {
            let child_count = body.child_count();
            for i in 0..child_count {
                if let Some(child) = body.child(i as u32) {
                    self.walk_node(child);
                }
            }
        }

        self.current_class = prev_class;
    }

    fn handle_function(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();
        let doc_comment = self.extract_docstring(node);

        let (kind, fq, visibility, parent) = if let Some(class_id) = self.current_class {
            let fq = if let Some(class_sym) = self.ir.symbols.get(&class_id) {
                format!("{}.{}", class_sym.fully_qualified, name)
            } else {
                self.fully_qualified(&name)
            };
            let vis = Self::python_visibility(&name);

            (SymbolKind::Method, fq, vis, Some(class_id))
        } else {
            let fq = self.fully_qualified(&name);
            let vis = Self::python_visibility(&name);
            (SymbolKind::Function, fq, vis, None)
        };

        let param_count = count_python_params(node, &self.source);

        // pytest hooks (`pytest_configure`, `pytest_addoption`, ...) in a
        // conftest.py are called by the test runner through plugin discovery,
        // never by user code, so they must not read as dead. The conftest.py
        // gate keeps an unrelated `pytest_helper` in application code from
        // being exempted by name alone.
        let is_pytest_hook = name.starts_with("pytest_")
            && self.path.file_name().is_some_and(|f| f == "conftest.py");

        let symbol = Symbol {
            id,
            name,
            fully_qualified: fq,
            kind,
            visibility,
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: Language::Python,
            parent,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count,
            is_entry_point: is_pytest_hook,
            doc_comment,
        };

        self.ir.symbols.insert(id, symbol);

        let prev_func = self.current_function.take();
        self.current_function = Some(id);

        if let Some(body) = node.child_by_field_name("body") {
            let child_count = body.child_count();
            for i in 0..child_count {
                if let Some(child) = body.child(i as u32) {
                    self.walk_node(child);
                }
            }
        }

        self.current_function = prev_func;
    }

    fn handle_decorated(&mut self, node: tree_sitter::Node) {
        // decorated_definition wraps the decorators plus the real definition.
        if let Some(definition) = node.child_by_field_name("definition") {
            match definition.kind() {
                "class_definition" => {
                    // Class-level guards (`@method_decorator(login_required)`
                    // on a Django CBV) belong to the class symbol so routes
                    // that resolve to it inherit them. handle_class allocates
                    // the class's id first, so it is the next allocation.
                    let guards = self.guard_decorators(node);
                    let class_id = SymbolId(self.next_id + 1);
                    self.handle_class(definition);
                    if !guards.is_empty() {
                        self.symbol_guards
                            .entry(class_id)
                            .or_default()
                            .extend(guards);
                    }
                }
                "function_definition" => {
                    let mut is_static = false;
                    let child_count = node.child_count();
                    for i in 0..child_count {
                        if let Some(child) = node.child(i as u32) {
                            if child.kind() == "decorator" {
                                let text = self.node_text(child);
                                if text.contains("staticmethod") || text.contains("classmethod") {
                                    is_static = true;
                                }
                            }
                        }
                    }

                    // Web routes declared via decorators (`@app.get("/x")`,
                    // `@app.route("/x", methods=[...])`). The decorated function
                    // IS the handler, so its symbol becomes the controller.
                    // handle_function allocates the function's own id first
                    // (before walking its body), so the id it will receive is
                    // the next allocation.
                    let routes = self.route_decorators(node);

                    // The declared guard stack: sibling decorators
                    // (`@login_required`, `@jwt_required()`) plus FastAPI
                    // `Depends(...)` in the handler's own signature. Recorded
                    // as route middleware so the auth pass can tell "declared
                    // with no guard" apart from "guards not extracted".
                    let mut guards = self.guard_decorators(node);
                    guards.extend(self.depends_param_guards(definition));

                    let is_entry = self.entry_point_decorator(node);
                    let func_id = SymbolId(self.next_id + 1);

                    self.handle_function(definition);

                    if is_entry {
                        if let Some(sym) = self.ir.symbols.get_mut(&func_id) {
                            sym.is_entry_point = true;
                        }
                    }

                    if !guards.is_empty() {
                        self.symbol_guards.insert(func_id, guards.clone());
                    }

                    for r in routes {
                        let full_path = self.apply_prefix(&r.object, &r.path);
                        let mut middleware = guards.clone();
                        middleware.extend(r.dependencies);
                        // Router-level dependencies
                        // (`APIRouter(dependencies=[...])`) guard every route
                        // registered on that router.
                        if let Some(deps) = self.router_dependencies.get(&r.object) {
                            middleware.extend(deps.iter().cloned());
                        }
                        self.ir.routes.push(Route {
                            method: r.method,
                            path: full_path,
                            controller: Some(func_id),
                            middleware,
                            file: self.path.clone(),
                            line: definition.start_position().row as u32 + 1,
                        });
                    }

                    if is_static {
                        if let Some(func_id) = self.current_function {
                            if let Some(sym) = self.ir.symbols.get_mut(&func_id) {
                                sym.kind = SymbolKind::StaticMethod;
                            }
                        }
                        // current_function may already be restored; patch the
                        // last-allocated symbol too.
                        let last_id = SymbolId(self.next_id);
                        if let Some(sym) = self.ir.symbols.get_mut(&last_id) {
                            sym.kind = SymbolKind::StaticMethod;
                        }
                    }
                }
                _ => {
                    self.walk_node(definition);
                }
            }
        }
    }

    fn handle_call(&mut self, node: tree_sitter::Node) {
        let callee_name = node
            .child_by_field_name("function")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        // Top-level calls (module bootstrap like `main()`) have no enclosing
        // function/class; attribute them to the synthetic file scope so the
        // callee still counts as used and does not read as dead.
        let caller_id = self
            .current_function
            .or(self.current_class)
            .unwrap_or_else(|| self.get_or_create_file_scope());
        let target = if callee_name.contains("getattr") || callee_name.contains("eval") {
            CallTarget::Dynamic(callee_name.clone())
        } else {
            CallTarget::Unresolved(callee_name.clone())
        };

        self.ir.calls.push(Call {
            caller: caller_id,
            callee: target,
            file: self.path.clone(),
            line: node.start_position().row as u32 + 1,
            col: node.start_position().column as u32,
        });

        // `router = APIRouter(prefix="/api")` / `bp = Blueprint(..., url_prefix="/api")`
        // - remember the prefix (and any constructor-level auth dependencies)
        // keyed by the assigned variable name so route decorators on that
        // router pick them up.
        self.record_router_decl(node, &callee_name);

        // Django `path("users/<int:id>/", view)` / `re_path(...)` inside a
        // urls.py `urlpatterns` list -> a route (method Any).
        self.try_extract_django_route(node, &callee_name);

        // DRF `router.register("users", UserViewSet)` -> a route per ViewSet.
        self.try_extract_viewset_register(node, &callee_name);

        // aiohttp `app.router.add_get("/x", handler)` / `web.get("/x", handler)`.
        self.try_extract_aiohttp_route(node, &callee_name);

        // Tornado `Application([(r"/x", Handler), ...])` handler tables.
        self.try_extract_tornado_routes(node, &callee_name);

        // Client HTTP calls: `requests.get("http://.../x")`, `httpx.post(...)`,
        // `session.get("/x")`, aiohttp `session.get(...)`.
        self.try_extract_http_call(node, &callee_name, caller_id);

        if let Some(args) = node.child_by_field_name("arguments") {
            let child_count = args.child_count();
            for i in 0..child_count {
                if let Some(child) = args.child(i as u32) {
                    self.walk_node(child);
                }
            }
        }
    }

    /// The value (quotes/prefix stripped) of the first string-literal positional
    /// argument in an `argument_list` node.
    fn first_string_arg(&self, args: tree_sitter::Node) -> Option<String> {
        for i in 0..args.child_count() {
            let child = args.child(i as u32)?;
            if child.kind() == "string" {
                return Some(self.py_string_value(child));
            }
        }
        None
    }

    /// Extract the content of a Python `string` node, dropping the quotes and
    /// any prefix (`f"..."`, `b"..."`). Falls back to trimming quote chars.
    fn py_string_value(&self, node: tree_sitter::Node) -> String {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i as u32) {
                if child.kind() == "string_content" {
                    return self.node_text(child).to_string();
                }
            }
        }
        strip_quotes(self.node_text(node))
    }

    /// Read the `prefix="/api"` / `url_prefix="/api"` keyword argument value.
    fn prefix_kwarg(&self, args: tree_sitter::Node) -> Option<String> {
        for i in 0..args.child_count() {
            let child = args.child(i as u32)?;
            if child.kind() == "keyword_argument" {
                let name = child
                    .child_by_field_name("name")
                    .map(|n| self.node_text(n).to_string())
                    .unwrap_or_default();
                if name == "prefix" || name == "url_prefix" {
                    if let Some(value) = child.child_by_field_name("value") {
                        if value.kind() == "string" {
                            return Some(self.py_string_value(value));
                        }
                    }
                }
            }
        }
        None
    }

    /// HTTP verbs from a `methods=["GET", "POST"]` keyword argument.
    fn methods_kwarg(&self, args: tree_sitter::Node) -> Vec<HttpMethod> {
        let mut out = Vec::new();
        for i in 0..args.child_count() {
            let Some(child) = args.child(i as u32) else {
                continue;
            };
            if child.kind() != "keyword_argument" {
                continue;
            }
            let name = child
                .child_by_field_name("name")
                .map(|n| self.node_text(n).to_string())
                .unwrap_or_default();
            if name != "methods" {
                continue;
            }
            if let Some(value) = child.child_by_field_name("value") {
                for j in 0..value.child_count() {
                    if let Some(item) = value.child(j as u32) {
                        if item.kind() == "string" {
                            if let Some(m) = http_method_from_verb(&self.py_string_value(item)) {
                                out.push(m);
                            }
                        }
                    }
                }
            }
        }
        out
    }

    /// Parse the decorators of a `decorated_definition` for web routes.
    /// Returns one [`DecoratedRoute`] per route declared, carrying any
    /// `dependencies=[Depends(...)]` guards from the decorator itself.
    fn route_decorators(&self, decorated: tree_sitter::Node) -> Vec<DecoratedRoute> {
        let mut out = Vec::new();
        for i in 0..decorated.child_count() {
            let Some(child) = decorated.child(i as u32) else {
                continue;
            };
            if child.kind() != "decorator" {
                continue;
            }
            // Find the call node inside the decorator (`app.get("/x")`).
            let mut call = None;
            for j in 0..child.child_count() {
                if let Some(gc) = child.child(j as u32) {
                    if gc.kind() == "call" {
                        call = Some(gc);
                        break;
                    }
                }
            }
            let Some(call) = call else { continue };
            let Some(func) = call.child_by_field_name("function") else {
                continue;
            };
            if func.kind() != "attribute" {
                continue;
            }
            let object = func
                .child_by_field_name("object")
                .map(|n| self.node_text(n).to_string())
                .unwrap_or_default();
            let object = object.rsplit('.').next().unwrap_or(&object).to_string();
            let verb = func
                .child_by_field_name("attribute")
                .map(|n| self.node_text(n).to_string())
                .unwrap_or_default();

            let Some(args) = call.child_by_field_name("arguments") else {
                continue;
            };
            let Some(path) = self.first_string_arg(args) else {
                continue;
            };
            if path.is_empty() {
                continue;
            }

            let dependencies = self.dependencies_kwarg(args);

            if verb.eq_ignore_ascii_case("route") {
                // Flask/Sanic/Blueprint: one Route per declared method,
                // default GET.
                let mut methods = self.methods_kwarg(args);
                if methods.is_empty() {
                    methods.push(HttpMethod::Get);
                }
                for m in methods {
                    out.push(DecoratedRoute {
                        method: m,
                        path: path.clone(),
                        object: object.clone(),
                        dependencies: dependencies.clone(),
                    });
                }
            } else if let Some(method) = http_method_from_verb(&verb) {
                // FastAPI / Flask 2+ / Sanic verb decorators: `@app.get("/x")`.
                out.push(DecoratedRoute {
                    method,
                    path: path.clone(),
                    object: object.clone(),
                    dependencies,
                });
            }
        }
        out
    }

    /// Unwrap a decorator node to `(trailing_name, base_expr, call_args)`.
    /// `@login_required`, `@jwt_required()`, and `@celery.task(bind=True)` all
    /// yield their base name; the call layer's arguments come along so callers
    /// can look inside `@permission_classes([...])` and friends.
    fn decorator_parts<'a>(
        &self,
        decorator: tree_sitter::Node<'a>,
    ) -> Option<(String, tree_sitter::Node<'a>, Option<tree_sitter::Node<'a>>)> {
        let mut expr = None;
        for i in 0..decorator.child_count() {
            if let Some(child) = decorator.child(i as u32) {
                if child.kind() != "@" && child.kind() != "comment" {
                    expr = Some(child);
                    break;
                }
            }
        }
        let mut expr = expr?;
        let mut args = None;
        if expr.kind() == "call" {
            args = expr.child_by_field_name("arguments");
            expr = expr.child_by_field_name("function")?;
        }
        let name = match expr.kind() {
            "identifier" => self.node_text(expr).to_string(),
            "attribute" => self
                .node_text(expr.child_by_field_name("attribute")?)
                .to_string(),
            _ => return None,
        };
        Some((name, expr, args))
    }

    /// The declared guard stack of a decorated definition: every sibling
    /// decorator that is not the route declaration itself or a method-shaping
    /// builtin. Recording all of them (not just a known-auth list) keeps the
    /// extraction honest - deciding which names count as auth is the analysis
    /// pass's job. DRF's `@permission_classes([...])` and Django's
    /// `@method_decorator(guard, ...)` contribute the wrapped names instead of
    /// their own.
    fn guard_decorators(&self, decorated: tree_sitter::Node) -> Vec<String> {
        const NON_GUARDS: &[&str] = &[
            // Route declarations - extracted as routes, not guards.
            "route",
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
            "options",
            "websocket",
            // Method-shaping builtins - they say nothing about access control.
            "staticmethod",
            "classmethod",
            "property",
            "abstractmethod",
            "cached_property",
            // Entry-point markers, handled by entry_point_decorator.
            "task",
            "shared_task",
            "command",
            "group",
            "fixture",
        ];
        let mut out = Vec::new();
        for i in 0..decorated.child_count() {
            let Some(child) = decorated.child(i as u32) else {
                continue;
            };
            if child.kind() != "decorator" {
                continue;
            }
            let Some((name, _, args)) = self.decorator_parts(child) else {
                continue;
            };
            if name == "permission_classes" || name == "method_decorator" {
                if let Some(args) = args {
                    out.extend(self.callable_arg_names(args));
                }
                continue;
            }
            if NON_GUARDS.contains(&name.as_str()) {
                continue;
            }
            out.push(name);
        }
        out
    }

    /// Whether the decorators mark a framework entry point: Celery tasks
    /// (`@celery.task`, `@app.task`, `@shared_task`), click/Typer commands and
    /// groups (`@click.command()`, `@cli.group()`), pytest fixtures
    /// (`@pytest.fixture`). The framework invokes these by registration, so
    /// the static call graph never sees a caller - without the mark every task
    /// and CLI command reads as dead code. Bare `@task`/`@command`/`@group`
    /// are deliberately NOT matched: without the receiver there is no
    /// framework evidence, and a project-local decorator of the same name
    /// would silently exempt genuinely dead code.
    fn entry_point_decorator(&self, decorated: tree_sitter::Node) -> bool {
        for i in 0..decorated.child_count() {
            let Some(child) = decorated.child(i as u32) else {
                continue;
            };
            if child.kind() != "decorator" {
                continue;
            }
            let Some((name, expr, _)) = self.decorator_parts(child) else {
                continue;
            };
            let is_attr = expr.kind() == "attribute";
            match name.as_str() {
                "shared_task" | "fixture" => return true,
                "task" | "command" | "group" if is_attr => return true,
                _ => {}
            }
        }
        false
    }

    /// Dependency names from a `dependencies=[Depends(...), ...]` keyword
    /// argument (route decorator or APIRouter/FastAPI constructor).
    fn dependencies_kwarg(&self, args: tree_sitter::Node) -> Vec<String> {
        let mut out = Vec::new();
        for i in 0..args.child_count() {
            let Some(child) = args.child(i as u32) else {
                continue;
            };
            if child.kind() != "keyword_argument" {
                continue;
            }
            let name = child
                .child_by_field_name("name")
                .map(|n| self.node_text(n))
                .unwrap_or("");
            if name != "dependencies" {
                continue;
            }
            if let Some(value) = child.child_by_field_name("value") {
                self.collect_depends(value, &mut out, 0);
            }
        }
        out
    }

    /// FastAPI guards declared in the handler's own signature:
    /// `def h(user=Depends(get_current_user))`, `Security(...)`, and the
    /// `Annotated[User, Depends(...)]` type form.
    fn depends_param_guards(&self, definition: tree_sitter::Node) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(params) = definition.child_by_field_name("parameters") {
            self.collect_depends(params, &mut out, 0);
        }
        out
    }

    /// Collect `Depends(fn)` / `Security(fn)` dependency names anywhere under
    /// `node`. Keyword lists, parameter defaults, and `Annotated[...]` types
    /// all nest them differently, so a bounded subtree walk beats enumerating
    /// every shape.
    fn collect_depends(&self, node: tree_sitter::Node, out: &mut Vec<String>, depth: usize) {
        if depth > 32 {
            return;
        }
        if node.kind() == "call" {
            if let Some(func) = node.child_by_field_name("function") {
                let name = self.node_text(func);
                let name = name.rsplit('.').next().unwrap_or(name);
                if name == "Depends" || name == "Security" {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        if let Some(dep) = self.callable_arg_names(args).into_iter().next() {
                            out.push(dep);
                        }
                    }
                    return;
                }
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i as u32) {
                self.collect_depends(child, out, depth + 1);
            }
        }
    }

    /// Trailing names of the positional callables in an argument list, looking
    /// through one list/tuple layer - covers `([IsAuthenticated])` and
    /// `(login_required, name="dispatch")` alike. Keyword arguments are
    /// skipped: they configure, they don't guard.
    fn callable_arg_names(&self, args: tree_sitter::Node) -> Vec<String> {
        let mut out = Vec::new();
        for i in 0..args.child_count() {
            let Some(child) = args.child(i as u32) else {
                continue;
            };
            match child.kind() {
                "identifier" | "attribute" => {
                    let text = self.node_text(child);
                    out.push(text.rsplit('.').next().unwrap_or(text).to_string());
                }
                "list" | "tuple" | "set" => out.extend(self.list_callable_names(child)),
                _ => {}
            }
        }
        out
    }

    /// Trailing names of the callables in a `[A, B]` / `(A, B)` literal, the
    /// call layer stripped so `[IsAuthenticated]` and `[IsAuthenticated()]`
    /// read the same.
    fn list_callable_names(&self, node: tree_sitter::Node) -> Vec<String> {
        let mut out = Vec::new();
        for i in 0..node.child_count() {
            let Some(mut child) = node.child(i as u32) else {
                continue;
            };
            if child.kind() == "call" {
                if let Some(f) = child.child_by_field_name("function") {
                    child = f;
                }
            }
            if matches!(child.kind(), "identifier" | "attribute") {
                let text = self.node_text(child);
                out.push(text.rsplit('.').next().unwrap_or(text).to_string());
            }
        }
        out
    }

    /// DRF class attribute guards: `permission_classes = [IsAuthenticated]`
    /// on a class-based view / ViewSet body.
    fn class_permission_guards(&self, node: tree_sitter::Node) -> Vec<String> {
        let mut out = Vec::new();
        let Some(body) = node.child_by_field_name("body") else {
            return out;
        };
        for i in 0..body.child_count() {
            let Some(stmt) = body.child(i as u32) else {
                continue;
            };
            if stmt.kind() != "expression_statement" {
                continue;
            }
            let Some(assign) = stmt.child(0) else {
                continue;
            };
            if assign.kind() != "assignment" {
                continue;
            }
            let left = assign
                .child_by_field_name("left")
                .map(|n| self.node_text(n))
                .unwrap_or("");
            if left != "permission_classes" {
                continue;
            }
            if let Some(right) = assign.child_by_field_name("right") {
                out.extend(self.list_callable_names(right));
            }
        }
        out
    }

    /// Combine a router prefix (if the object is a known prefixed router) with a
    /// route path, normalising the result to a leading-slash URL path.
    fn apply_prefix(&self, object: &str, path: &str) -> String {
        let combined = match self.router_prefixes.get(object) {
            Some(prefix) => format!("{prefix}{path}"),
            None => path.to_string(),
        };
        let norm = normalize_url_path(&combined);
        if norm.is_empty() {
            "/".to_string()
        } else {
            norm
        }
    }

    /// Detect `x = APIRouter(...)` / `x = Blueprint(...)` / `x = FastAPI(...)`
    /// and record the declaration's route-relevant settings under the assigned
    /// variable name: the `prefix=`/`url_prefix=` path prefix, and any
    /// constructor-level `dependencies=[Depends(...)]` guards, which FastAPI
    /// applies to every route registered on the router/app.
    fn record_router_decl(&mut self, call: tree_sitter::Node, callee_name: &str) {
        let ctor = callee_name.rsplit('.').next().unwrap_or(callee_name);
        if ctor != "APIRouter" && ctor != "Blueprint" && ctor != "FastAPI" {
            return;
        }
        let Some(args) = call.child_by_field_name("arguments") else {
            return;
        };
        // The call's parent is the assignment; its left side is the var name.
        let Some(parent) = call.parent() else { return };
        if parent.kind() != "assignment" {
            return;
        }
        let Some(left) = parent.child_by_field_name("left") else {
            return;
        };
        let var = self.node_text(left).to_string();
        let var = var.rsplit('.').next().unwrap_or(&var).to_string();

        if let Some(prefix) = self.prefix_kwarg(args) {
            self.router_prefixes
                .insert(var.clone(), normalize_url_path(&prefix));
        }
        let deps = self.dependencies_kwarg(args);
        if !deps.is_empty() {
            self.router_dependencies.insert(var, deps);
        }
    }

    /// Django `path("users/<int:id>/", view)` / `re_path(...)` / `url(...)` in a
    /// `urls.py`. Best-effort: method Any, controller resolved by view name.
    fn try_extract_django_route(&mut self, call: tree_sitter::Node, callee_name: &str) {
        if !self.path.to_string_lossy().contains("urls") {
            return;
        }
        let func = callee_name.rsplit('.').next().unwrap_or(callee_name);
        if func != "path" && func != "re_path" && func != "url" {
            return;
        }
        let Some(args) = call.child_by_field_name("arguments") else {
            return;
        };
        let Some(raw) = self.first_string_arg(args) else {
            return;
        };
        let path = normalize_url_path(&raw);
        if path.is_empty() {
            return;
        }
        // Second positional argument is the view - resolve by trailing name.
        // Guards on the view (decorators, DRF `permission_classes`) become the
        // route's middleware; a cross-file view resolves to None and keeps an
        // empty - "unknown" - middleware list.
        let controller = self.view_arg(args).and_then(|(_, id)| id);
        self.ir.routes.push(Route {
            method: HttpMethod::Any,
            path,
            controller,
            middleware: self.guards_for(controller),
            file: self.path.clone(),
            line: call.start_position().row as u32 + 1,
        });
    }

    /// The recorded guards for a resolved controller symbol, or empty.
    fn guards_for(&self, controller: Option<SymbolId>) -> Vec<String> {
        controller
            .and_then(|id| self.symbol_guards.get(&id))
            .cloned()
            .unwrap_or_default()
    }

    /// The view/handler argument following the first string argument: its
    /// trailing name, plus the resolved symbol id when it names something in
    /// this file (`views.user_detail` -> `user_detail`). Class-based views
    /// arrive as `MyView.as_view()`, so the call layer and the `.as_view`
    /// suffix are stripped to resolve the class itself. Cross-file references
    /// resolve to None - best-effort, same-file only.
    fn view_arg(&self, args: tree_sitter::Node) -> Option<(String, Option<SymbolId>)> {
        let mut seen_string = false;
        for i in 0..args.child_count() {
            let child = args.child(i as u32)?;
            match child.kind() {
                "," | "(" | ")" => continue,
                "string" => {
                    seen_string = true;
                    continue;
                }
                "keyword_argument" | "comment" => continue,
                _ => {}
            }
            if !seen_string {
                continue;
            }
            let mut target = child;
            if target.kind() == "call" {
                if let Some(func) = target.child_by_field_name("function") {
                    target = func;
                }
            }
            let text = self.node_text(target);
            let text = text.strip_suffix(".as_view").unwrap_or(text);
            let view_name = text.rsplit('.').next().unwrap_or(text).trim().to_string();
            let id = self
                .ir
                .symbols
                .values()
                .find(|s| s.name == view_name)
                .map(|s| s.id);
            return Some((view_name, id));
        }
        None
    }

    /// DRF `router.register(r"users", UserViewSet)` -> one Any-method route
    /// per registration, the controller resolved to the ViewSet class when it
    /// lives in the same file. Gated on the receiver being named like a router
    /// so a plugin registry's `.register(...)` is never misread as a route.
    fn try_extract_viewset_register(&mut self, call: tree_sitter::Node, callee_name: &str) {
        let Some((object, method)) = callee_name.rsplit_once('.') else {
            return;
        };
        if method != "register" {
            return;
        }
        let object_tail = object.rsplit('.').next().unwrap_or(object);
        if !object_tail.to_ascii_lowercase().contains("router") {
            return;
        }
        let Some(args) = call.child_by_field_name("arguments") else {
            return;
        };
        let Some(raw) = self.first_string_arg(args) else {
            return;
        };
        let path = normalize_url_path(&raw);
        if path.is_empty() {
            return;
        }
        let controller = self.view_arg(args).and_then(|(_, id)| id);
        self.ir.routes.push(Route {
            method: HttpMethod::Any,
            path,
            controller,
            middleware: self.guards_for(controller),
            file: self.path.clone(),
            line: call.start_position().row as u32 + 1,
        });
    }

    /// aiohttp routes: `app.router.add_get("/x", handler)` and route-table
    /// entries `web.get("/x", handler)`. Both name the handler as a positional
    /// argument after the path, which is what separates a route declaration
    /// from an HTTP client call of the same `object.verb(url)` shape - a call
    /// without a handler argument is left alone.
    fn try_extract_aiohttp_route(&mut self, call: tree_sitter::Node, callee_name: &str) {
        let Some((object, method)) = callee_name.rsplit_once('.') else {
            return;
        };
        let object_tail = object.rsplit('.').next().unwrap_or(object);

        let http_method = if let Some(verb) = method.strip_prefix("add_") {
            // `<router>.add_get(...)`: require a router-named receiver so an
            // unrelated `cache.add_get(...)` helper never becomes a route.
            if !object_tail.to_ascii_lowercase().ends_with("router") {
                return;
            }
            match http_method_from_verb(verb) {
                Some(m) => m,
                None => return,
            }
        } else if object_tail == "web" {
            // `web.get("/x", handler)` inside an `add_routes([...])` table.
            match http_method_from_verb(method) {
                Some(m) => m,
                None => return,
            }
        } else {
            return;
        };

        let Some(args) = call.child_by_field_name("arguments") else {
            return;
        };
        let Some(raw) = self.first_string_arg(args) else {
            return;
        };
        // aiohttp route paths always start with a slash; a bare word or full
        // URL here is a client call or something else entirely.
        if !raw.starts_with('/') {
            return;
        }
        let path = normalize_url_path(&raw);
        if path.is_empty() {
            return;
        }
        // The handler argument is mandatory evidence - no handler, no route.
        let Some((_, controller)) = self.view_arg(args) else {
            return;
        };
        self.ir.routes.push(Route {
            method: http_method,
            path,
            controller,
            middleware: self.guards_for(controller),
            file: self.path.clone(),
            line: call.start_position().row as u32 + 1,
        });
    }

    /// Tornado routes: `Application([(r"/x", MainHandler), ...])`. Each
    /// `(pattern, handler)` tuple in the first list argument becomes an
    /// Any-method route with the handler class as controller. `URLSpec(...)`
    /// entries are not unpacked - tuples dominate real Tornado code, and the
    /// pattern-must-start-with-slash check keeps an unrelated `Application`
    /// constructor from inventing routes.
    fn try_extract_tornado_routes(&mut self, call: tree_sitter::Node, callee_name: &str) {
        let ctor = callee_name.rsplit('.').next().unwrap_or(callee_name);
        if ctor != "Application" {
            return;
        }
        let Some(args) = call.child_by_field_name("arguments") else {
            return;
        };
        for i in 0..args.child_count() {
            let Some(list) = args.child(i as u32) else {
                continue;
            };
            if list.kind() != "list" {
                continue;
            }
            for j in 0..list.child_count() {
                let Some(item) = list.child(j as u32) else {
                    continue;
                };
                if item.kind() != "tuple" {
                    continue;
                }
                let Some(raw) = self.first_string_arg(item) else {
                    continue;
                };
                if !raw.starts_with('/') {
                    continue;
                }
                let path = normalize_url_path(&raw);
                if path.is_empty() {
                    continue;
                }
                let Some((_, controller)) = self.view_arg(item) else {
                    continue;
                };
                self.ir.routes.push(Route {
                    method: HttpMethod::Any,
                    path,
                    controller,
                    middleware: self.guards_for(controller),
                    file: self.path.clone(),
                    line: item.start_position().row as u32 + 1,
                });
            }
            // Only the first list argument holds the handler table.
            break;
        }
    }

    /// Record a client HTTP call so the linker can connect it to its route.
    fn try_extract_http_call(
        &mut self,
        call: tree_sitter::Node,
        callee_name: &str,
        caller_id: SymbolId,
    ) {
        // Need `object.verb` form: split the callee dotted-path.
        let mut parts: Vec<&str> = callee_name.split('.').collect();
        let Some(verb) = parts.pop() else { return };
        let Some(object) = parts.pop() else { return };
        let Some(method) = http_method_from_verb(verb) else {
            return;
        };
        if !is_python_http_client(object) {
            return;
        }
        let Some(args) = call.child_by_field_name("arguments") else {
            return;
        };
        let Some(raw) = self.first_string_arg(args) else {
            return;
        };
        if !(raw.starts_with('/') || raw.starts_with("http")) {
            return;
        }
        let path = normalize_url_path(&raw);
        if path.is_empty() {
            return;
        }
        self.ir.http_calls.push(HttpCall {
            method,
            path,
            caller: caller_id,
            file: self.path.clone(),
            line: call.start_position().row as u32 + 1,
        });
    }
}

/// Map an HTTP verb (decorator suffix or client method) to an `HttpMethod`.
fn http_method_from_verb(verb: &str) -> Option<HttpMethod> {
    match verb.trim().to_ascii_lowercase().as_str() {
        "get" => Some(HttpMethod::Get),
        "post" => Some(HttpMethod::Post),
        "put" => Some(HttpMethod::Put),
        "patch" => Some(HttpMethod::Patch),
        "delete" => Some(HttpMethod::Delete),
        _ => None,
    }
}

/// Whether an object name looks like an HTTP client, so `.get`/`.post` is a
/// request rather than `dict.get`. Matches the well-known modules plus common
/// session/client variable names.
fn is_python_http_client(obj: &str) -> bool {
    let o = obj.to_ascii_lowercase();
    const NAMES: &[&str] = &[
        "requests", "httpx", "aiohttp", "session", "client", "http", "urllib3",
    ];
    NAMES.contains(&o.as_str())
        || o.ends_with("session")
        || o.ends_with("client")
        || o.ends_with("_http")
}

fn strip_quotes(s: &str) -> String {
    s.trim()
        .trim_start_matches(['f', 'b', 'r', 'F', 'B', 'R', 'u', 'U'])
        .trim_start_matches(['"', '\'', '`'])
        .trim_end_matches(['"', '\'', '`'])
        .to_string()
}

/// Reduce a URL to a comparable path: drop protocol+host and query/fragment,
/// ensure a leading slash, drop the trailing slash. Param normalisation
/// (`<int:id>`/`{id}` -> `*`) happens at link time.
fn normalize_url_path(url: &str) -> String {
    let mut u = url.trim();
    if let Some(pos) = u.find("://") {
        match u[pos + 3..].find('/') {
            Some(slash) => u = &u[pos + 3 + slash..],
            None => return String::new(),
        }
    }
    let u = u.split(['?', '#']).next().unwrap_or(u);
    if u.is_empty() {
        return String::new();
    }
    let path = if u.starts_with('/') {
        u.to_string()
    } else {
        format!("/{u}")
    };
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Count parameters in a Python function definition, excluding `self` and `cls`.
fn count_python_params(node: tree_sitter::Node, source: &str) -> u8 {
    if let Some(params) = node.child_by_field_name("parameters") {
        let mut count: u8 = 0;
        for i in 0..params.child_count() {
            if let Some(child) = params.child(i as u32) {
                let is_param = matches!(
                    child.kind(),
                    "identifier"
                        | "typed_parameter"
                        | "default_parameter"
                        | "typed_default_parameter"
                        | "list_splat_pattern"
                        | "dictionary_splat_pattern"
                );
                if is_param {
                    let param_text = child.utf8_text(source.as_bytes()).unwrap_or("");
                    let param_name = param_text.split(':').next().unwrap_or("").trim();
                    let param_name = param_name.split('=').next().unwrap_or("").trim();
                    let param_name = param_name.trim_start_matches('*');
                    if param_name != "self" && param_name != "cls" {
                        count = count.saturating_add(1);
                    }
                }
            }
        }
        count
    } else {
        0
    }
}

fn hash_path(path: &Path) -> u64 {
    crate::stable_hash(path.to_string_lossy().as_ref())
}

fn hash_string(s: &str) -> u64 {
    crate::stable_hash(s)
}

/// Remove triple-quoted strings (docstrings) before normalization - two
/// functions that differ only in their docstrings must hash identically,
/// just like functions that differ only in comments.
fn strip_docstrings(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &source[i..];
        if rest.starts_with("\"\"\"") || rest.starts_with("'''") {
            let quote = &rest[..3];
            match rest[3..].find(quote) {
                Some(end) => {
                    i += 3 + end + 3;
                    continue;
                }
                None => {
                    // Unterminated - drop the rest, matching Python's view
                    // that everything to EOF belongs to the string.
                    break;
                }
            }
        }
        let ch = rest.chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Normalized hash: docstrings, comments and whitespace stripped, identifiers
/// replaced with placeholders, so renamed duplicates hash identically.
fn hash_normalized(s: &str) -> u64 {
    let stripped = crate::strip_comments(&strip_docstrings(s), false, true, true);
    let mut normalized = String::with_capacity(stripped.len());
    let chars: Vec<char> = stripped.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        if chars[i].is_alphabetic() || chars[i] == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            let lower = ident.to_lowercase();
            match lower.as_str() {
                // Python keywords
                "def" | "class" | "return" | "if" | "else" | "elif" | "while" | "for"
                | "in" | "import" | "from" | "as" | "with" | "try" | "except" | "finally"
                | "raise" | "pass" | "break" | "continue" | "and" | "or" | "not" | "is"
                | "none" | "true" | "false" | "lambda" | "yield" | "global" | "nonlocal"
                | "assert" | "del" | "async" | "await"
                // Common built-ins
                | "self" | "cls" | "print" | "len" | "range" | "int" | "str" | "float"
                | "list" | "dict" | "set" | "tuple" | "bool" | "type" | "isinstance"
                | "hasattr" | "getattr" | "setattr" | "super" | "property"
                | "staticmethod" | "classmethod" => {
                    normalized.push_str(&lower);
                }
                _ => {
                    normalized.push_str("_ID_");
                }
            }
            continue;
        }
        normalized.push(chars[i]);
        i += 1;
    }
    hash_string(&normalized)
}
