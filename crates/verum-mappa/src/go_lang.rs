use std::path::Path;

use anyhow::{Context, Result};

use std::collections::HashMap;

use verum_nucleus::{
    Call, CallTarget, FileId, FileInfo, HttpCall, HttpMethod, Ir, Language, Route, Symbol,
    SymbolId, SymbolKind, Visibility,
};

/// Parse a Go file into a partial IR.
pub fn parse_file(path: &Path) -> Result<Ir> {
    let source =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_go::language())
        .map_err(|e| anyhow::anyhow!("Failed to set Go language: {}", e))?;

    let tree = parser
        .parse(&source, None)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse {}", path.display()))?;

    let mut extractor = GoExtractor {
        source: source.clone(),
        path: path.to_path_buf(),
        next_id: hash_path(path),
        current_package: String::new(),
        current_type: None,
        current_function: None,
        group_prefixes: HashMap::new(),
        pending_handlers: Vec::new(),
        ir: Ir::new(),
    };

    extractor.walk_node(tree.root_node());
    extractor.resolve_route_handlers();

    let line_count = source.lines().count() as u32;
    let size_bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    let file_id = FileId(hash_path(path));
    let symbol_ids: Vec<SymbolId> = extractor.ir.symbols.keys().copied().collect();

    extractor.ir.files.insert(
        path.to_path_buf(),
        FileInfo {
            id: file_id,
            path: path.to_path_buf(),
            language: Language::Go,
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

struct GoExtractor {
    source: String,
    path: std::path::PathBuf,
    next_id: u64,
    current_package: String,
    current_type: Option<SymbolId>,
    current_function: Option<SymbolId>,
    /// Maps a router-group variable to its accumulated URL prefix, e.g.
    /// `api := r.Group("/api")` records `api -> /api`, so a later
    /// `api.GET("/users", ...)` becomes the route `/api/users`.
    group_prefixes: HashMap<String, String>,
    /// `(index into ir.routes, handler name)` recorded while walking, resolved to
    /// a controller symbol after the walk - a handler is often defined *after*
    /// the route that references it.
    pending_handlers: Vec<(usize, String)>,
    ir: Ir,
}

impl GoExtractor {
    fn alloc_id(&mut self) -> SymbolId {
        self.next_id += 1;
        SymbolId(self.next_id)
    }

    fn fully_qualified(&self, name: &str) -> String {
        if self.current_package.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", self.current_package, name)
        }
    }

    fn node_text<'a>(&'a self, node: tree_sitter::Node<'a>) -> &'a str {
        node.utf8_text(self.source.as_bytes()).unwrap_or("")
    }

    fn hash_node(&self, node: tree_sitter::Node) -> (u64, u64) {
        let text = &self.source[node.start_byte()..node.end_byte()];
        (hash_string(text), hash_normalized(text))
    }

    /// Determine Go visibility: uppercase first letter = Public, else Private.
    fn go_visibility(name: &str) -> Visibility {
        if name.starts_with(|c: char| c.is_uppercase()) {
            Visibility::Public
        } else {
            Visibility::Private
        }
    }

    fn walk_node(&mut self, node: tree_sitter::Node) {
        match node.kind() {
            "package_clause" => self.handle_package(node),
            "type_declaration" => self.handle_type_declaration(node),
            "function_declaration" => self.handle_function(node),
            "method_declaration" => self.handle_method(node),
            "call_expression" => self.handle_call(node),
            "short_var_declaration" | "assignment_statement" => {
                self.detect_group_assignment(node);
                let child_count = node.child_count();
                for i in 0..child_count {
                    if let Some(child) = node.child(i) {
                        self.walk_node(child);
                    }
                }
            }
            _ => {
                let child_count = node.child_count();
                for i in 0..child_count {
                    if let Some(child) = node.child(i) {
                        self.walk_node(child);
                    }
                }
            }
        }
    }

    fn handle_package(&mut self, node: tree_sitter::Node) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "package_identifier" {
                    self.current_package = self.node_text(child).to_string();
                }
            }
        }
    }

    fn handle_type_declaration(&mut self, node: tree_sitter::Node) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "type_spec" {
                    self.handle_type_spec(child);
                }
            }
        }
    }

    fn handle_type_spec(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let type_node = node.child_by_field_name("type");

        let kind = match type_node.map(|n| n.kind()) {
            Some("struct_type") => SymbolKind::Class,
            Some("interface_type") => SymbolKind::Interface,
            _ => SymbolKind::Class, // type aliases, etc. treat as Class
        };

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();
        let fq = self.fully_qualified(&name);
        let visibility = Self::go_visibility(&name);

        let symbol = Symbol {
            id,
            name: name.clone(),
            fully_qualified: fq,
            kind,
            visibility,
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: Language::Go,
            parent: None,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count: 0,
            is_entry_point: name == "main",
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);

        // Go doesn't nest types, but walking the body with current_type set
        // records the owner for methods.
        let prev_type = self.current_type.take();
        self.current_type = Some(id);

        if let Some(type_body) = type_node {
            let child_count = type_body.child_count();
            for j in 0..child_count {
                if let Some(child) = type_body.child(j) {
                    self.walk_node(child);
                }
            }
        }

        self.current_type = prev_type;
    }

    fn handle_function(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();
        let fq = self.fully_qualified(&name);
        let visibility = Self::go_visibility(&name);
        let param_count = count_params(node);

        let symbol = Symbol {
            id,
            name: name.clone(),
            fully_qualified: fq,
            kind: SymbolKind::Function,
            visibility,
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: Language::Go,
            parent: None,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count,
            is_entry_point: name == "main",
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);

        let prev_func = self.current_function.take();
        self.current_function = Some(id);

        if let Some(body) = node.child_by_field_name("body") {
            let child_count = body.child_count();
            for i in 0..child_count {
                if let Some(child) = body.child(i) {
                    self.walk_node(child);
                }
            }
        }

        self.current_function = prev_func;
    }

    fn handle_method(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();
        let visibility = Self::go_visibility(&name);
        let param_count = count_params(node);

        let receiver_type = self.extract_receiver_type(node);
        let fq = if let Some(ref recv) = receiver_type {
            if self.current_package.is_empty() {
                format!("{}.{}", recv, name)
            } else {
                format!("{}.{}.{}", self.current_package, recv, name)
            }
        } else {
            self.fully_qualified(&name)
        };

        let parent = receiver_type.as_ref().and_then(|recv_name| {
            self.ir
                .symbols
                .iter()
                .find(|(_, s)| s.name == *recv_name && s.kind == SymbolKind::Class)
                .map(|(id, _)| *id)
        });

        let symbol = Symbol {
            id,
            name,
            fully_qualified: fq,
            kind: SymbolKind::Method,
            visibility,
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: Language::Go,
            parent,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count,
            is_entry_point: false,
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);

        let prev_func = self.current_function.take();
        self.current_function = Some(id);

        if let Some(body) = node.child_by_field_name("body") {
            let child_count = body.child_count();
            for i in 0..child_count {
                if let Some(child) = body.child(i) {
                    self.walk_node(child);
                }
            }
        }

        self.current_function = prev_func;
    }

    /// Extract the receiver type name from a method_declaration.
    /// e.g. `func (s *UserService) GetUserByID(...)` -> "UserService"
    fn extract_receiver_type(&self, node: tree_sitter::Node) -> Option<String> {
        let receiver = node.child_by_field_name("receiver")?;
        for i in 0..receiver.child_count() {
            if let Some(child) = receiver.child(i) {
                if child.kind() == "parameter_declaration" {
                    if let Some(type_node) = child.child_by_field_name("type") {
                        return Some(self.extract_type_name(type_node));
                    }
                }
            }
        }
        None
    }

    /// Extract a type name, stripping pointer (*) if present.
    fn extract_type_name(&self, node: tree_sitter::Node) -> String {
        match node.kind() {
            "pointer_type" => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "type_identifier" {
                            return self.node_text(child).to_string();
                        }
                    }
                }
                self.node_text(node).trim_start_matches('*').to_string()
            }
            "type_identifier" => self.node_text(node).to_string(),
            _ => self.node_text(node).to_string(),
        }
    }

    fn handle_call(&mut self, node: tree_sitter::Node) {
        let function_node = match node.child_by_field_name("function") {
            Some(n) => n,
            None => return,
        };

        let callee_name = match function_node.kind() {
            "selector_expression" => {
                // e.g. fmt.Println, svc.GetUserByID
                let operand = function_node
                    .child_by_field_name("operand")
                    .map(|n| self.node_text(n).to_string())
                    .unwrap_or_default();
                let field = function_node
                    .child_by_field_name("field")
                    .map(|n| self.node_text(n).to_string())
                    .unwrap_or_default();
                format!("{}.{}", operand, field)
            }
            "identifier" => self.node_text(function_node).to_string(),
            "parenthesized_expression" => {
                // Dynamic call via function variable
                let text = self.node_text(function_node).to_string();
                if let Some(caller_id) = self.current_function {
                    self.ir.calls.push(Call {
                        caller: caller_id,
                        callee: CallTarget::Dynamic(text),
                        file: self.path.clone(),
                        line: node.start_position().row as u32 + 1,
                        col: node.start_position().column as u32,
                    });
                }
                self.walk_call_arguments(node);
                return;
            }
            _ => self.node_text(function_node).to_string(),
        };

        if let Some(caller_id) = self.current_function {
            self.ir.calls.push(Call {
                caller: caller_id,
                callee: CallTarget::Unresolved(callee_name),
                file: self.path.clone(),
                line: node.start_position().row as u32 + 1,
                col: node.start_position().column as u32,
            });
        }

        // A call is either a route registration (server side) or an HTTP client
        // call (caller side) or neither - never both. Try the route first.
        if function_node.kind() == "selector_expression"
            && self.try_extract_route(node, function_node)
        {
            // registered a route
        } else {
            self.try_extract_http_call(node, function_node);
        }

        self.walk_call_arguments(node);
    }

    /// Named (non-punctuation) argument nodes of a call expression.
    fn arg_nodes<'a>(&self, node: tree_sitter::Node<'a>) -> Vec<tree_sitter::Node<'a>> {
        let mut out = Vec::new();
        if let Some(args) = node.child_by_field_name("arguments") {
            for i in 0..args.child_count() {
                if let Some(c) = args.child(i) {
                    if c.is_named() {
                        out.push(c);
                    }
                }
            }
        }
        out
    }

    /// Text of a string-literal node with its quotes/backticks stripped, or None.
    fn string_literal_text(&self, node: tree_sitter::Node) -> Option<String> {
        match node.kind() {
            "interpreted_string_literal" | "raw_string_literal" => {
                Some(strip_go_quotes(self.node_text(node)))
            }
            _ => None,
        }
    }

    /// The `operand`/`field` pair of a `selector_expression` (`operand.field`).
    fn selector_parts(&self, sel: tree_sitter::Node) -> (String, String) {
        let operand = sel
            .child_by_field_name("operand")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();
        let field = sel
            .child_by_field_name("field")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();
        (operand, field)
    }

    /// Record `api := r.Group("/api")` (and chi's `r.Route("/api", ...)`) so that
    /// routes later registered on `api` inherit the `/api` prefix.
    fn detect_group_assignment(&mut self, node: tree_sitter::Node) {
        let left = node
            .child_by_field_name("left")
            .or_else(|| child_of_kind(node, "expression_list"));
        let right = node.child_by_field_name("right").or_else(|| {
            // Second expression_list in an assignment.
            let mut lists = Vec::new();
            for i in 0..node.child_count() {
                if let Some(c) = node.child(i) {
                    if c.kind() == "expression_list" {
                        lists.push(c);
                    }
                }
            }
            lists.into_iter().nth(1)
        });
        let (Some(left), Some(right)) = (left, right) else {
            return;
        };

        // First identifier on the left-hand side.
        let mut lhs_name = None;
        for i in 0..left.child_count() {
            if let Some(c) = left.child(i) {
                if c.kind() == "identifier" {
                    lhs_name = Some(self.node_text(c).to_string());
                    break;
                }
            }
        }
        let Some(lhs_name) = lhs_name else { return };

        // First call_expression on the right-hand side.
        let mut call = None;
        for i in 0..right.child_count() {
            if let Some(c) = right.child(i) {
                if c.kind() == "call_expression" {
                    call = Some(c);
                    break;
                }
            }
        }
        let Some(call) = call else { return };
        let Some(func) = call.child_by_field_name("function") else {
            return;
        };
        if func.kind() != "selector_expression" {
            return;
        }
        let (operand, field) = self.selector_parts(func);
        if field != "Group" && field != "Route" {
            return;
        }
        let Some(prefix_arg) = self
            .arg_nodes(call)
            .into_iter()
            .find_map(|a| self.string_literal_text(a))
        else {
            return;
        };
        if !prefix_arg.starts_with('/') {
            return;
        }
        let parent = self
            .group_prefixes
            .get(&operand)
            .cloned()
            .unwrap_or_default();
        let full = join_route_path(&parent, &prefix_arg);
        self.group_prefixes.insert(lhs_name, full);
    }

    /// Detect and record a web-framework route registration. Returns true if a
    /// route was recorded. Handles net/http (`HandleFunc`/`Handle` -> Any), gin &
    /// echo (`GET`/`POST`/..., `Any`), and chi (`Get`/`Post`/...).
    fn try_extract_route(
        &mut self,
        node: tree_sitter::Node,
        function_node: tree_sitter::Node,
    ) -> bool {
        let (operand, field) = self.selector_parts(function_node);
        let Some(method) = route_method_from_field(&field) else {
            return false;
        };

        // Mixed-case verbs (chi `Get`/`Post`/...) collide with client calls like
        // `http.Get`. Only treat them as routes when the receiver looks like a
        // router and not like an HTTP client.
        let ambiguous = matches!(field.as_str(), "Get" | "Post" | "Put" | "Patch" | "Delete");
        if ambiguous && (!is_router_receiver(&operand) || looks_like_http_client(&operand)) {
            return false;
        }

        let args = self.arg_nodes(node);
        // First argument must be a string-literal path starting with "/".
        let Some(first) = args.first() else {
            return false;
        };
        let Some(raw_path) = self.string_literal_text(*first) else {
            return false;
        };
        if !raw_path.starts_with('/') {
            return false;
        }

        let prefix = self
            .group_prefixes
            .get(&operand)
            .cloned()
            .unwrap_or_default();
        let path = join_route_path(&prefix, &raw_path);

        // The handler is the last named non-path argument (gin allows leading
        // middleware). Resolve it to a symbol after the whole file is walked,
        // since the handler is frequently defined below the registration.
        let handler = args
            .iter()
            .skip(1)
            .rev()
            .find_map(|a| self.handler_name(*a));

        let route_idx = self.ir.routes.len();
        self.ir.routes.push(Route {
            method,
            path,
            controller: None,
            middleware: Vec::new(),
            file: self.path.clone(),
            line: node.start_position().row as u32 + 1,
        });
        if let Some(name) = handler {
            self.pending_handlers.push((route_idx, name));
        }
        true
    }

    /// Resolve each pending route handler name to a controller symbol, now that
    /// every symbol in the file has been recorded.
    fn resolve_route_handlers(&mut self) {
        for (route_idx, name) in std::mem::take(&mut self.pending_handlers) {
            let id = self
                .ir
                .symbols
                .iter()
                .find(|(_, s)| s.name == name)
                .map(|(id, _)| *id);
            if let (Some(id), Some(route)) = (id, self.ir.routes.get_mut(route_idx)) {
                route.controller = Some(id);
            }
        }
    }

    /// The referable name of a handler argument: an `identifier` yields its text,
    /// a `selector_expression` (`h.Serve`) yields its field.
    fn handler_name(&self, node: tree_sitter::Node) -> Option<String> {
        match node.kind() {
            "identifier" => Some(self.node_text(node).to_string()),
            "selector_expression" => node
                .child_by_field_name("field")
                .map(|n| self.node_text(n).to_string()),
            _ => None,
        }
    }

    /// Record a client-side HTTP call: `http.Get(url)`, `client.Post(url, ...)`,
    /// resty's `client.R().Get(url)`. The URL argument must be a string literal
    /// starting with "/" or "http".
    fn try_extract_http_call(&mut self, node: tree_sitter::Node, function_node: tree_sitter::Node) {
        if function_node.kind() != "selector_expression" {
            return;
        }
        let Some(caller_id) = self.current_function else {
            return;
        };

        let field = function_node
            .child_by_field_name("field")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();
        let Some(method) = client_method_from_verb(&field) else {
            return;
        };

        // The receiver must look like an HTTP client. The operand can itself be a
        // call (`client.R()`), so check its full text for a client-ish name.
        let operand = function_node
            .child_by_field_name("operand")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();
        if !looks_like_http_client(&operand) {
            return;
        }

        let Some(raw) = self
            .arg_nodes(node)
            .into_iter()
            .find_map(|a| self.string_literal_text(a))
        else {
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
            line: node.start_position().row as u32 + 1,
        });
    }

    fn walk_call_arguments(&mut self, node: tree_sitter::Node) {
        if let Some(args) = node.child_by_field_name("arguments") {
            let child_count = args.child_count();
            for i in 0..child_count {
                if let Some(child) = args.child(i) {
                    self.walk_node(child);
                }
            }
        }
    }
}

fn count_params(node: tree_sitter::Node) -> u8 {
    if let Some(params) = node.child_by_field_name("parameters") {
        let mut count: u8 = 0;
        for i in 0..params.child_count() {
            if let Some(child) = params.child(i) {
                if child.kind() == "parameter_declaration" {
                    count = count.saturating_add(1);
                }
            }
        }
        count
    } else {
        0
    }
}

/// First direct child of `node` with the given kind.
fn child_of_kind<'a>(node: tree_sitter::Node<'a>, kind: &str) -> Option<tree_sitter::Node<'a>> {
    for i in 0..node.child_count() {
        if let Some(c) = node.child(i) {
            if c.kind() == kind {
                return Some(c);
            }
        }
    }
    None
}

/// Strip the surrounding quotes/backticks from a Go string literal.
fn strip_go_quotes(s: &str) -> String {
    s.trim()
        .trim_start_matches(['"', '`'])
        .trim_end_matches(['"', '`'])
        .to_string()
}

/// Map a call field to a route HTTP method. `HandleFunc`/`Handle` (net/http) and
/// gin's `Any` register any verb; gin/echo use uppercase verbs, chi mixed-case.
fn route_method_from_field(field: &str) -> Option<HttpMethod> {
    match field {
        "HandleFunc" | "Handle" | "Any" | "ANY" => Some(HttpMethod::Any),
        "GET" | "Get" => Some(HttpMethod::Get),
        "POST" | "Post" => Some(HttpMethod::Post),
        "PUT" | "Put" => Some(HttpMethod::Put),
        "PATCH" | "Patch" => Some(HttpMethod::Patch),
        "DELETE" | "Delete" => Some(HttpMethod::Delete),
        _ => None,
    }
}

/// Map a client call verb (`Get`/`Post`/...) to an HTTP method.
fn client_method_from_verb(field: &str) -> Option<HttpMethod> {
    match field {
        "Get" => Some(HttpMethod::Get),
        "Post" | "PostForm" => Some(HttpMethod::Post),
        "Put" => Some(HttpMethod::Put),
        "Patch" => Some(HttpMethod::Patch),
        "Delete" => Some(HttpMethod::Delete),
        _ => None,
    }
}

/// Whether a receiver name looks like a router/mux/engine/group rather than an
/// unrelated object (so `r.Get("/x", h)` is a route but `cache.Get("k")` isn't).
fn is_router_receiver(recv: &str) -> bool {
    let r = recv.to_ascii_lowercase();
    const NAMES: &[&str] = &[
        "r", "router", "mux", "e", "engine", "app", "api", "group", "g", "rg", "v1", "v2", "srv",
        "server", "route", "routes", "root",
    ];
    NAMES.contains(&r.as_str())
        || r.ends_with("router")
        || r.ends_with("mux")
        || r.ends_with("group")
        || r.ends_with("engine")
}

/// Whether a receiver looks like an HTTP client (so `.Get`/`.Post` is a request).
/// Handles resty's chained `client.R()` by inspecting the leftmost segment.
fn looks_like_http_client(recv: &str) -> bool {
    let recv = recv.trim();
    // Leftmost identifier of a chain like `client.R()` or `c.R()`.
    let head = recv
        .split(['.', '('])
        .next()
        .unwrap_or(recv)
        .to_ascii_lowercase();
    const NAMES: &[&str] = &["http", "client", "c", "httpclient", "resty", "hc"];
    NAMES.contains(&head.as_str())
        || head.ends_with("client")
        || head.ends_with("http")
        || recv.to_ascii_lowercase().contains(".r()")
}

/// Join a group prefix and a route path into a single normalized URL path.
fn join_route_path(prefix: &str, path: &str) -> String {
    let combined = if prefix.is_empty() {
        path.to_string()
    } else {
        format!("/{}/{}", prefix.trim_matches('/'), path.trim_matches('/'))
    };
    let combined = combined.trim();
    let s = if combined.starts_with('/') {
        combined.to_string()
    } else {
        format!("/{combined}")
    };
    let trimmed = s.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Reduce a URL to a comparable path: drop protocol+host and query/fragment,
/// ensure a leading slash, drop the trailing slash.
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

fn hash_path(path: &Path) -> u64 {
    crate::stable_hash(path.to_string_lossy().as_ref())
}

fn hash_string(s: &str) -> u64 {
    crate::stable_hash(s)
}

/// Normalized hash: comments and whitespace stripped, identifiers replaced with
/// placeholders, so renamed duplicates hash identically.
fn hash_normalized(s: &str) -> u64 {
    let stripped = crate::strip_comments(s, true, false, true);
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
                // Go keywords
                "func" | "type" | "struct" | "interface" | "return" | "if" | "else" | "for"
                | "range" | "switch" | "case" | "default" | "var" | "const" | "package"
                | "import" | "go" | "defer" | "chan" | "select" | "map" | "break" | "continue"
                | "fallthrough" | "goto" | "nil" | "true" | "false" | "int" | "string"
                | "float64" | "float32" | "bool" | "byte" | "rune" | "error" | "make" | "len"
                | "cap" | "append" | "copy" | "delete" | "new" | "close" | "panic" | "recover"
                | "print" | "println" => {
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
