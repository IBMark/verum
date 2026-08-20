use std::path::Path;

use anyhow::{Context, Result};

use verum_nucleus::{
    Call, CallTarget, FileId, FileInfo, HttpCall, HttpMethod, Ir, Language, Symbol, SymbolId,
    SymbolKind, Visibility,
};

/// Parse a JavaScript or TypeScript file into a partial IR.
pub fn parse_file(path: &Path, is_typescript: bool) -> Result<Ir> {
    let source =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_source(&source, path, is_typescript, None)
}

/// Parse JS/TS from an in-memory source string, attributing symbols to `path`.
/// Used both by [`parse_file`] and by inline-`<script>` extraction from HTML.
///
/// `id_seed` overrides the base value the symbol-ID counter starts from
/// (default: `hash(path)`). Callers parsing multiple fragments attributed to
/// the same `path` (e.g. several inline `<script>` blocks in one HTML file)
/// must pass a distinct seed per fragment, or fragment N+1 would allocate the
/// same SymbolIds as fragment N and silently overwrite its symbols on merge.
pub fn parse_source(
    source: &str,
    path: &Path,
    is_typescript: bool,
    id_seed: Option<u64>,
) -> Result<Ir> {
    let source = source.to_string();

    // TSX needs its own grammar; plain TS and JS each get their own too.
    let (key, language): (&'static str, fn() -> tree_sitter::Language) = if is_typescript {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "tsx" {
            ("tsx", || tree_sitter_typescript::LANGUAGE_TSX.into())
        } else {
            ("typescript", || {
                tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
            })
        }
    } else {
        ("javascript", || tree_sitter_javascript::LANGUAGE.into())
    };

    let tree = crate::parser_pool::parse(key, language, &source)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse {}", path.display()))?;

    let lang = if is_typescript {
        Language::TypeScript
    } else {
        Language::JavaScript
    };

    let mut extractor = JsExtractor {
        depth: 0,
        source: source.clone(),
        path: path.to_path_buf(),
        next_id: id_seed.unwrap_or_else(|| hash_path(path)),
        current_class: None,
        current_function: None,
        ir: Ir::new(),
        language: lang.clone(),
        in_export: false,
        current_controller_base: None,
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
            language: lang,
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

struct JsExtractor {
    /// Current `walk_node` recursion depth, checked against
    /// [`crate::MAX_RECURSION_DEPTH`] so a pathologically deep AST cannot
    /// overflow the stack (an abort no panic guard can catch).
    depth: usize,
    source: String,
    path: std::path::PathBuf,
    next_id: u64,
    current_class: Option<SymbolId>,
    current_function: Option<SymbolId>,
    ir: Ir,
    language: Language,
    /// Whether we are inside an export_statement, so children get Public visibility.
    in_export: bool,
    /// Base path from an enclosing NestJS `@Controller('/base')` decorator, so
    /// method decorators (`@Get('/x')`) can be resolved to a full route path.
    current_controller_base: Option<String>,
}

impl JsExtractor {
    fn alloc_id(&mut self) -> SymbolId {
        self.next_id += 1;
        SymbolId(self.next_id)
    }

    fn node_text<'a>(&'a self, node: tree_sitter::Node<'a>) -> &'a str {
        node.utf8_text(self.source.as_bytes()).unwrap_or("")
    }

    fn hash_node(&self, node: tree_sitter::Node) -> (u64, u64) {
        let text = &self.source[node.start_byte()..node.end_byte()];
        (hash_string(text), hash_normalized(text))
    }

    fn default_visibility(&self) -> Visibility {
        if self.in_export {
            Visibility::Public
        } else {
            Visibility::Private
        }
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
            "class_declaration" | "class" => self.handle_class(node),
            "method_definition" => self.handle_method(node),
            "function_declaration" | "function" => self.handle_function(node),
            "variable_declaration" | "lexical_declaration" => {
                self.handle_variable_declaration(node)
            }
            "export_statement" => self.handle_export(node),
            "call_expression" => self.handle_call(node),
            "new_expression" => self.handle_new(node),
            "import_statement" => self.handle_import(node),
            // JSX elements - treat <Component /> as a call to Component
            "jsx_element" | "jsx_self_closing_element" => self.handle_jsx_element(node),
            "interface_declaration" => self.handle_interface(node),
            "enum_declaration" => self.handle_enum(node),
            "type_alias_declaration" => {
                // Skip type aliases, just recurse children
                self.walk_children(node);
            }
            _ => {
                self.walk_children(node);
            }
        }
    }

    fn walk_children(&mut self, node: tree_sitter::Node) {
        let child_count = node.child_count();
        for i in 0..child_count {
            if let Some(child) = node.child(i as u32) {
                self.walk_node(child);
            }
        }
    }

    fn handle_export(&mut self, node: tree_sitter::Node) {
        let prev_export = self.in_export;
        self.in_export = true;

        // Re-exports (`export { X } from './m'`, `export * from './m'`) carry
        // a source string.
        let has_source = self.has_child_kind(node, "string");

        if has_source {
            self.extract_export_specifiers(node);
        }

        self.walk_children(node);

        self.in_export = prev_export;
    }

    /// Handle import statements: `import { X, Y } from './module'`
    /// `import X from './module'`, `import * as X from './module'`
    ///
    /// Registers each imported symbol name as an Unresolved call so that
    /// the exported symbol in the source module is not flagged as dead code.
    fn handle_import(&mut self, node: tree_sitter::Node) {
        let mut imported_names: Vec<String> = Vec::new();

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i as u32) {
                match child.kind() {
                    // `import X from ...` - default import
                    "identifier" => {
                        let name = self.node_text(child).to_string();
                        if !name.is_empty() && name != "from" && name != "import" {
                            imported_names.push(name);
                        }
                    }
                    // `import { X, Y, Z } from ...` - named imports
                    "import_clause" => {
                        self.extract_import_clause_names(child, &mut imported_names, 0);
                    }
                    // `import * as Ns from ...`
                    "namespace_import" => {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            let name = self.node_text(name_node).to_string();
                            if !name.is_empty() {
                                imported_names.push(name);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let caller_id = self.current_function.or(self.current_class);
        for name in imported_names {
            if let Some(caller) = caller_id {
                self.ir.calls.push(Call {
                    caller,
                    callee: CallTarget::Unresolved(name),
                    file: self.path.clone(),
                    line: node.start_position().row as u32 + 1,
                    col: node.start_position().column as u32,
                });
            } else {
                // No enclosing scope - attribute to the synthetic file scope.
                let file_caller = self.get_or_create_file_scope();
                self.ir.calls.push(Call {
                    caller: file_caller,
                    callee: CallTarget::Unresolved(name),
                    file: self.path.clone(),
                    line: node.start_position().row as u32 + 1,
                    col: node.start_position().column as u32,
                });
            }
        }
    }

    /// Depth-capped: the catch-all arm recurses into unrecognized children,
    /// so a hostile or error-recovery import clause could otherwise nest to
    /// the input's depth. Anything past the cap is skipped deterministically.
    fn extract_import_clause_names(
        &self,
        node: tree_sitter::Node,
        names: &mut Vec<String>,
        depth: usize,
    ) {
        if depth >= crate::MAX_RECURSION_DEPTH {
            return;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i as u32) {
                match child.kind() {
                    "identifier" => {
                        let name = self.node_text(child).to_string();
                        if !name.is_empty() && name != "from" {
                            names.push(name);
                        }
                    }
                    "named_imports" => {
                        // `{ X, Y as Z }` - import_specifier children
                        for j in 0..child.child_count() {
                            if let Some(spec) = child.child(j as u32) {
                                if spec.kind() == "import_specifier" {
                                    // The "name" field is what's exported, "alias" is local name
                                    if let Some(name_node) = spec.child_by_field_name("name") {
                                        let name = self.node_text(name_node).to_string();
                                        if !name.is_empty() {
                                            names.push(name);
                                        }
                                    }
                                    if let Some(alias_node) = spec.child_by_field_name("alias") {
                                        let alias = self.node_text(alias_node).to_string();
                                        if !alias.is_empty() {
                                            names.push(alias);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "namespace_import" => {
                        // `* as Ns`
                        for j in 0..child.child_count() {
                            if let Some(grandchild) = child.child(j as u32) {
                                if grandchild.kind() == "identifier" {
                                    let name = self.node_text(grandchild).to_string();
                                    if !name.is_empty() && name != "as" {
                                        names.push(name);
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        self.extract_import_clause_names(child, names, depth + 1);
                    }
                }
            }
        }
    }

    fn extract_export_specifiers(&mut self, node: tree_sitter::Node) {
        let caller_id = self
            .current_function
            .or(self.current_class)
            .unwrap_or_else(|| self.get_or_create_file_scope());

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i as u32) {
                match child.kind() {
                    "export_clause" => {
                        // `export { X, Y } from ...`
                        for j in 0..child.child_count() {
                            if let Some(spec) = child.child(j as u32) {
                                if spec.kind() == "export_specifier" {
                                    if let Some(name_node) = spec.child_by_field_name("name") {
                                        let name = self.node_text(name_node).to_string();
                                        if !name.is_empty() {
                                            self.ir.calls.push(Call {
                                                caller: caller_id,
                                                callee: CallTarget::Unresolved(name),
                                                file: self.path.clone(),
                                                line: node.start_position().row as u32 + 1,
                                                col: node.start_position().column as u32,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // `export * from ...` - can't enumerate the names behind a
                    // wildcard, so there is nothing to record.
                    "*" => {}
                    _ => {}
                }
            }
        }
    }

    fn has_child_kind(&self, node: tree_sitter::Node, kind: &str) -> bool {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i as u32) {
                if child.kind() == kind {
                    return true;
                }
            }
        }
        false
    }

    /// Get or create a file-scope pseudo symbol for top-level calls.
    fn get_or_create_file_scope(&mut self) -> SymbolId {
        let file_scope_name = format!("__file_scope_{}", self.path.display());
        for (id, sym) in &self.ir.symbols {
            if sym.name == file_scope_name {
                return *id;
            }
        }

        let id = self.alloc_id();
        let symbol = Symbol {
            id,
            name: file_scope_name.clone(),
            fully_qualified: file_scope_name,
            kind: SymbolKind::Function,
            visibility: Visibility::Private,
            file: self.path.clone(),
            line_start: 1,
            line_end: 1,
            col_start: 0,
            col_end: 0,
            language: self.language.clone(),
            parent: None,
            hash: 0,
            normalized_hash: 0,
            flow_hash: 0,
            param_count: 0,
            is_entry_point: true, // File scope is always "alive"
            doc_comment: None,
        };
        self.ir.symbols.insert(id, symbol);
        id
    }

    fn handle_class(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        if name.is_empty() {
            // Anonymous class, just walk children
            self.walk_children(node);
            return;
        }

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();

        let symbol = Symbol {
            id,
            name: name.clone(),
            fully_qualified: name,
            kind: SymbolKind::Class,
            visibility: self.default_visibility(),
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: self.language.clone(),
            parent: None,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count: 0,
            is_entry_point: false,
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);

        let prev_class = self.current_class.take();
        self.current_class = Some(id);
        // NestJS `@Controller('/base')` prefix applies to every route method
        // declared inside this class body.
        let prev_base = self.current_controller_base.take();
        self.current_controller_base = self.controller_base(node);

        if let Some(body) = node.child_by_field_name("body") {
            self.walk_children(body);
        }

        self.current_controller_base = prev_base;
        self.current_class = prev_class;
    }

    fn handle_method(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();

        let fq = if let Some(class_id) = self.current_class {
            if let Some(class_sym) = self.ir.symbols.get(&class_id) {
                format!("{}.{}", class_sym.fully_qualified, name)
            } else {
                name.clone()
            }
        } else {
            name.clone()
        };

        let is_static = check_static(node, &self.source);
        let param_count = count_params(node);

        let kind = if is_static {
            SymbolKind::StaticMethod
        } else {
            SymbolKind::Method
        };

        let visibility = extract_method_visibility(node, &self.source);

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
            language: self.language.clone(),
            parent: self.current_class,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count,
            is_entry_point: false,
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);
        self.note_if_http_wrapper(&name, node);

        // NestJS route decorators (`@Get('/x')`) sit as siblings just before
        // this method; the decorated method is the handler.
        self.extract_nest_route(node, id);

        let prev_func = self.current_function.take();
        self.current_function = Some(id);

        if let Some(body) = node.child_by_field_name("body") {
            self.walk_children(body);
        }

        self.current_function = prev_func;
    }

    fn handle_function(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        if name.is_empty() {
            // Anonymous function expression -- walk children but don't register as symbol
            self.walk_children(node);
            return;
        }

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();
        let param_count = count_params(node);

        let symbol = Symbol {
            id,
            name: name.clone(),
            fully_qualified: name.clone(),
            kind: SymbolKind::Function,
            visibility: self.default_visibility(),
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: self.language.clone(),
            parent: None,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count,
            is_entry_point: false,
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);
        self.note_if_http_wrapper(&name, node);

        let prev_func = self.current_function.take();
        self.current_function = Some(id);

        if let Some(body) = node.child_by_field_name("body") {
            self.walk_children(body);
        }

        self.current_function = prev_func;
    }

    /// Handle variable/lexical declarations.
    /// Looks for patterns like `const foo = () => { ... }` or `const foo = function() { ... }`
    fn handle_variable_declaration(&mut self, node: tree_sitter::Node) {
        let child_count = node.child_count();
        for i in 0..child_count {
            if let Some(child) = node.child(i as u32) {
                if child.kind() == "variable_declarator" {
                    self.handle_variable_declarator(child);
                }
            }
        }
    }

    fn handle_variable_declarator(&mut self, node: tree_sitter::Node) {
        let name_node = node.child_by_field_name("name");
        let value_node = node.child_by_field_name("value");

        if let (Some(name_n), Some(value_n)) = (name_node, value_node) {
            let value_kind = value_n.kind();
            if value_kind == "arrow_function"
                || value_kind == "function"
                || value_kind == "function_expression"
            {
                let name = self.node_text(name_n).to_string();
                if name.is_empty() {
                    self.walk_node(value_n);
                    return;
                }

                let (hash, normalized_hash) = self.hash_node(value_n);
                let id = self.alloc_id();
                let param_count = count_params(value_n);

                let symbol = Symbol {
                    id,
                    name: name.clone(),
                    fully_qualified: name,
                    kind: SymbolKind::Function,
                    visibility: self.default_visibility(),
                    file: self.path.clone(),
                    line_start: node.start_position().row as u32 + 1,
                    line_end: node.end_position().row as u32 + 1,
                    col_start: node.start_position().column as u32,
                    col_end: node.end_position().column as u32,
                    language: self.language.clone(),
                    parent: self.current_class,
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

                if let Some(body) = value_n.child_by_field_name("body") {
                    self.walk_children(body);
                }

                self.current_function = prev_func;
            } else {
                self.walk_node(value_n);
            }
        } else {
            self.walk_children(node);
        }
    }

    fn handle_interface(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        if name.is_empty() {
            return;
        }

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();

        let symbol = Symbol {
            id,
            name: name.clone(),
            fully_qualified: name,
            kind: SymbolKind::Interface,
            visibility: self.default_visibility(),
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: self.language.clone(),
            parent: None,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count: 0,
            is_entry_point: false,
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);
    }

    fn handle_enum(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        if name.is_empty() {
            return;
        }

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();

        let symbol = Symbol {
            id,
            name: name.clone(),
            fully_qualified: name,
            kind: SymbolKind::Enum,
            visibility: self.default_visibility(),
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: self.language.clone(),
            parent: None,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count: 0,
            is_entry_point: false,
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);
    }

    fn handle_call(&mut self, node: tree_sitter::Node) {
        let func_node = match node.child_by_field_name("function") {
            Some(n) => n,
            None => return,
        };

        // Top-level calls (module bootstrap like `loadApp().catch(...)`) have
        // no enclosing function/class; attribute them to a synthetic file
        // scope so the callee still counts as used and does not read as dead.
        let caller_id = self
            .current_function
            .or(self.current_class)
            .unwrap_or_else(|| self.get_or_create_file_scope());

        let target = match func_node.kind() {
            "member_expression" => {
                // obj.method() or obj.prop.method()
                let prop = func_node
                    .child_by_field_name("property")
                    .map(|n| self.node_text(n).to_string())
                    .unwrap_or_default();
                let obj = func_node
                    .child_by_field_name("object")
                    .map(|n| self.node_text(n).to_string())
                    .unwrap_or_default();
                if obj.is_empty() {
                    CallTarget::Unresolved(prop)
                } else {
                    CallTarget::Unresolved(format!("{}.{}", obj, prop))
                }
            }
            "identifier" => {
                let name = self.node_text(func_node).to_string();
                CallTarget::Unresolved(name)
            }
            _ => {
                let text = self.node_text(func_node).to_string();
                CallTarget::Dynamic(text)
            }
        };

        self.ir.calls.push(Call {
            caller: caller_id,
            callee: target,
            file: self.path.clone(),
            line: node.start_position().row as u32 + 1,
            col: node.start_position().column as u32,
        });

        // A backend route registration (`app.get('/x', h)`) and a client HTTP
        // call (`api.get('/x')`) are the same shape; try the route (server) side
        // first, and only fall through to the client side if it is not a route.
        if !self.try_extract_route(node, func_node) {
            self.try_extract_http_call(node, func_node, caller_id);
        }

        if let Some(args) = node.child_by_field_name("arguments") {
            self.walk_children(args);
        }
        // Walk the callee expression too: in a chain like `foo().bar()` the
        // inner `foo()` call lives inside this call's `function` (member)
        // node, not its arguments, and would otherwise be missed.
        if func_node.kind() == "member_expression" {
            if let Some(obj) = func_node.child_by_field_name("object") {
                self.walk_node(obj);
            }
        }
    }

    /// Record a client HTTP call (`fetch('/api/x')`, `axios.get('/api/x')`,
    /// `api.post('/x', ...)`) so the linking pass can connect it to the route
    /// that serves it, across the language boundary.
    fn try_extract_http_call(
        &mut self,
        node: tree_sitter::Node,
        func_node: tree_sitter::Node,
        caller_id: SymbolId,
    ) {
        let (is_http, verb_method) = match func_node.kind() {
            "identifier" => {
                let name = self.node_text(func_node);
                // `fetch(...)`, `axios(...)`, and data-fetching hooks that take a
                // URL as their first argument (`useSWR('/x')`, `useQuery(...)`).
                (
                    name == "fetch" || name == "axios" || is_data_hook(name),
                    None,
                )
            }
            "member_expression" => {
                let prop = func_node
                    .child_by_field_name("property")
                    .map(|n| self.node_text(n).to_string())
                    .unwrap_or_default();
                let obj_full = func_node
                    .child_by_field_name("object")
                    .map(|n| self.node_text(n).to_string())
                    .unwrap_or_default();
                let obj = obj_full.rsplit('.').next().unwrap_or(&obj_full);
                let m = http_method_from_verb(&prop);
                (m.is_some() && is_http_client_name(obj), m)
            }
            _ => (false, None),
        };
        let Some(args) = node.child_by_field_name("arguments") else {
            return;
        };
        // Path may be a plain string/template first arg, or the `url` field of a
        // config object (`axios({ url: '/y', method: 'post' })`).
        let Some(raw) = self
            .first_string_arg(args)
            .or_else(|| self.url_from_config_object(args))
        else {
            return;
        };
        // Must look like a URL/path, not an arbitrary key (`cache.get("k")`).
        if !(raw.starts_with('/') || raw.starts_with("http")) {
            return;
        }
        let path = normalize_url_path(&raw);
        if path.is_empty() {
            return;
        }
        let method = verb_method
            .or_else(|| self.method_from_options(args))
            .unwrap_or(HttpMethod::Get);
        let call = HttpCall {
            method,
            path,
            caller: caller_id,
            file: self.path.clone(),
            line: node.start_position().row as u32 + 1,
        };

        if is_http {
            self.ir.http_calls.push(call);
            return;
        }
        // Not a direct fetch/axios call, but a literal URL path was passed to a
        // function - it may be the project's own HTTP wrapper (`request('/x')`,
        // `apiFetch('/x')`). Record a candidate; the wrapper-promotion pass keeps
        // it only if that callee is confirmed to wrap fetch/axios.
        if let Some(via) = self.candidate_wrapper_name(func_node) {
            self.ir.http_call_candidates.push((via, call));
        }
    }

    /// The callee name for a possible wrapper call: the bare identifier
    /// (`request('/x')`) or the method name (`this.request('/x')`).
    fn candidate_wrapper_name(&self, func_node: tree_sitter::Node) -> Option<String> {
        match func_node.kind() {
            "identifier" => Some(self.node_text(func_node).to_string()),
            "member_expression" => func_node
                .child_by_field_name("property")
                .map(|n| self.node_text(n).to_string()),
            _ => None,
        }
    }

    /// Record a function whose body calls `fetch`/`axios` as an HTTP wrapper, so
    /// literal-path calls to it elsewhere are recognized as HTTP calls.
    fn note_if_http_wrapper(&mut self, name: &str, body: tree_sitter::Node) {
        if name.is_empty() {
            return;
        }
        let text = self.node_text(body);
        if text.contains("fetch(") || text.contains("axios") {
            self.ir.http_wrappers.push(name.to_string());
        }
    }

    /// Content (quotes stripped) of the first string-literal argument.
    fn first_string_arg(&self, args: tree_sitter::Node) -> Option<String> {
        for i in 0..args.child_count() {
            let c = args.child(i as u32)?;
            if matches!(c.kind(), "string" | "template_string") {
                return Some(strip_quotes(self.node_text(c)));
            }
        }
        None
    }

    /// Method from a `{ method: 'POST' }` options object (2nd fetch/axios arg).
    fn method_from_options(&self, args: tree_sitter::Node) -> Option<HttpMethod> {
        let text = self.node_text(args).to_lowercase();
        if !text.contains("method") {
            return None;
        }
        for (kw, m) in [
            ("post", HttpMethod::Post),
            ("put", HttpMethod::Put),
            ("patch", HttpMethod::Patch),
            ("delete", HttpMethod::Delete),
        ] {
            if text.contains(&format!("\"{kw}\"")) || text.contains(&format!("'{kw}'")) {
                return Some(m);
            }
        }
        None
    }

    /// URL from a config object argument (`{ url: '/y', method: 'post' }`).
    fn url_from_config_object(&self, args: tree_sitter::Node) -> Option<String> {
        for i in 0..args.child_count() {
            let c = args.child(i as u32)?;
            if c.kind() != "object" {
                continue;
            }
            for j in 0..c.child_count() {
                let Some(pair) = c.child(j as u32) else {
                    continue;
                };
                if pair.kind() != "pair" {
                    continue;
                }
                let key = pair
                    .child_by_field_name("key")
                    .map(|k| self.node_text(k).to_string())
                    .unwrap_or_default();
                if key.trim_matches(['"', '\'']) != "url" {
                    continue;
                }
                if let Some(val) = pair.child_by_field_name("value") {
                    if matches!(val.kind(), "string" | "template_string") {
                        return Some(strip_quotes(self.node_text(val)));
                    }
                }
            }
        }
        None
    }

    /// Backend route registration on the server side:
    /// `app.get('/p', handler)`, `router.post('/p', h)`,
    /// `router.route('/p').get(fn)`, `app.use('/prefix', mw)`.
    /// Returns true if a route was recorded (so the caller skips client-call
    /// extraction for the same node). NestJS decorator routes are handled in
    /// [`Self::handle_method`], not here.
    fn try_extract_route(&mut self, node: tree_sitter::Node, func_node: tree_sitter::Node) -> bool {
        if func_node.kind() != "member_expression" {
            return false;
        }
        let prop = func_node
            .child_by_field_name("property")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();
        let Some(method) = route_method_from_verb(&prop) else {
            return false;
        };
        let Some(obj_node) = func_node.child_by_field_name("object") else {
            return false;
        };
        let Some(args) = node.child_by_field_name("arguments") else {
            return false;
        };
        let line = node.start_position().row as u32 + 1;

        // Chained form: `router.route('/p').get(fn)` - the object is itself the
        // `router.route('/p')` call, carrying the path; this verb selects it.
        if obj_node.kind() == "call_expression" {
            if let Some(inner_func) = obj_node.child_by_field_name("function") {
                if inner_func.kind() == "member_expression" {
                    let inner_prop = inner_func
                        .child_by_field_name("property")
                        .map(|n| self.node_text(n).to_string())
                        .unwrap_or_default();
                    let inner_obj = inner_func
                        .child_by_field_name("object")
                        .map(|n| self.node_text(n).to_string())
                        .unwrap_or_default();
                    if inner_prop == "route" && is_router_name(last_segment(&inner_obj)) {
                        if let Some(inner_args) = obj_node.child_by_field_name("arguments") {
                            if let Some(raw) = self.first_string_arg(inner_args) {
                                if raw.starts_with('/') {
                                    let controller = self.resolve_handler_from_args(args);
                                    self.push_route(method, &raw, controller, line);
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            return false;
        }

        // Direct form: `app.get('/p', handler)`. The object must look like a
        // server/router (`app`, `router`, `server`, `fastify`, ...) - never a
        // generic client name (`api`, `http`), so client calls are not
        // misclassified as routes.
        let obj_text = self.node_text(obj_node).to_string();
        if !is_router_name(last_segment(&obj_text)) {
            return false;
        }
        let Some(raw) = self.first_string_arg(args) else {
            return false;
        };
        if !raw.starts_with('/') {
            return false;
        }
        let controller = self.resolve_handler_from_args(args);
        self.push_route(method, &raw, controller, line);
        true
    }

    /// Record a route into the IR, normalizing the path.
    fn push_route(
        &mut self,
        method: HttpMethod,
        raw_path: &str,
        controller: Option<SymbolId>,
        line: u32,
    ) {
        let path = normalize_url_path(raw_path);
        let path = if path.is_empty() {
            "/".to_string()
        } else {
            path
        };
        self.ir.routes.push(verum_nucleus::Route {
            method,
            path,
            controller,
            middleware: Vec::new(),
            file: self.path.clone(),
            line,
        });
    }

    /// Resolve the route handler: the last identifier argument (`..., handler)`)
    /// mapped to a same-file symbol of that name, if one exists.
    fn resolve_handler_from_args(&self, args: tree_sitter::Node) -> Option<SymbolId> {
        let mut last_ident: Option<String> = None;
        for i in 0..args.child_count() {
            let Some(c) = args.child(i as u32) else {
                continue;
            };
            if c.kind() == "identifier" {
                last_ident = Some(self.node_text(c).to_string());
            }
        }
        let name = last_ident?;
        self.resolve_symbol_by_name(&name)
    }

    /// First same-file function/method symbol with the given name.
    fn resolve_symbol_by_name(&self, name: &str) -> Option<SymbolId> {
        self.ir
            .symbols
            .values()
            .find(|s| {
                s.name == name
                    && matches!(
                        s.kind,
                        SymbolKind::Function | SymbolKind::Method | SymbolKind::StaticMethod
                    )
            })
            .map(|s| s.id)
    }

    /// NestJS: from a method's preceding `@Get('/x')` / `@Post()` decorators,
    /// record a route whose handler is the decorated method itself, combining
    /// the method path with the class-level `@Controller('/base')` prefix.
    fn extract_nest_route(&mut self, method_node: tree_sitter::Node, method_id: SymbolId) {
        let mut sib = method_node.prev_sibling();
        while let Some(d) = sib {
            match d.kind() {
                "decorator" => {
                    if let Some((callee, args)) = self.decorator_call(d) {
                        if let Some(method) = nest_method_from_decorator(&callee) {
                            let sub = args
                                .and_then(|a| self.first_string_arg(a))
                                .unwrap_or_default();
                            let base = self.current_controller_base.clone().unwrap_or_default();
                            let path = join_route(&base, &sub);
                            let line = method_node.start_position().row as u32 + 1;
                            self.ir.routes.push(verum_nucleus::Route {
                                method,
                                path,
                                controller: Some(method_id),
                                middleware: Vec::new(),
                                file: self.path.clone(),
                                line,
                            });
                        }
                    }
                    sib = d.prev_sibling();
                }
                // Comments or accessibility modifiers can sit between a
                // decorator and its method; keep scanning past them.
                "comment" => sib = d.prev_sibling(),
                _ => break,
            }
        }
    }

    /// The callee name and optional arguments node of a decorator
    /// (`@Get('/x')` -> ("Get", Some(args)); `@Injectable` -> ("Injectable", None)).
    fn decorator_call<'a>(
        &self,
        decorator: tree_sitter::Node<'a>,
    ) -> Option<(String, Option<tree_sitter::Node<'a>>)> {
        for i in 0..decorator.child_count() {
            let Some(c) = decorator.child(i as u32) else {
                continue;
            };
            match c.kind() {
                "call_expression" => {
                    let callee = c
                        .child_by_field_name("function")
                        .map(|n| self.node_text(n).to_string())
                        .unwrap_or_default();
                    return Some((
                        last_segment(&callee).to_string(),
                        c.child_by_field_name("arguments"),
                    ));
                }
                "identifier" => {
                    return Some((self.node_text(c).to_string(), None));
                }
                _ => {}
            }
        }
        None
    }

    /// Base path from a class's `@Controller('/base')` decorator, if any.
    fn controller_base(&self, class_node: tree_sitter::Node) -> Option<String> {
        for i in 0..class_node.child_count() {
            let Some(c) = class_node.child(i as u32) else {
                continue;
            };
            if c.kind() != "decorator" {
                continue;
            }
            if let Some((callee, args)) = self.decorator_call(c) {
                if callee == "Controller" {
                    let base = args
                        .and_then(|a| self.first_string_arg(a))
                        .unwrap_or_default();
                    return Some(base);
                }
            }
        }
        None
    }

    fn handle_new(&mut self, node: tree_sitter::Node) {
        let constructor_node = match node.child_by_field_name("constructor") {
            Some(n) => n,
            None => return,
        };

        // Top-level `new Foo()` has no enclosing function/class; attribute it
        // to the synthetic file scope so Foo still counts as used.
        let caller_id = self
            .current_function
            .or(self.current_class)
            .unwrap_or_else(|| self.get_or_create_file_scope());

        let name = self.node_text(constructor_node).to_string();
        let target = CallTarget::Unresolved(format!("new {}", name));

        self.ir.calls.push(Call {
            caller: caller_id,
            callee: target,
            file: self.path.clone(),
            line: node.start_position().row as u32 + 1,
            col: node.start_position().column as u32,
        });

        if let Some(args) = node.child_by_field_name("arguments") {
            self.walk_children(args);
        }
    }

    /// Handle JSX elements: `<Component />` and `<Component>...</Component>`
    ///
    /// Registers the component name as an Unresolved call target so that
    /// React components referenced in JSX are not flagged as dead code.
    fn handle_jsx_element(&mut self, node: tree_sitter::Node) {
        let tag_name = self.extract_jsx_tag_name(node);

        if let Some(name) = tag_name {
            // Only register as a call if it's a component (PascalCase) - not an
            // HTML element (lowercase like div, span, etc.)
            if name.chars().next().is_some_and(|c| c.is_uppercase()) {
                // Top-level JSX (e.g. `createRoot(...).render(<App />)`)
                // falls back to the synthetic file scope.
                let caller = self
                    .current_function
                    .or(self.current_class)
                    .unwrap_or_else(|| self.get_or_create_file_scope());
                self.ir.calls.push(Call {
                    caller,
                    callee: CallTarget::Unresolved(name.clone()),
                    file: self.path.clone(),
                    line: node.start_position().row as u32 + 1,
                    col: node.start_position().column as u32,
                });

                // Also register the short name if it contains a dot (e.g. Foo.Bar)
                if let Some(short) = name.rsplit('.').next() {
                    if short != name {
                        self.ir.calls.push(Call {
                            caller,
                            callee: CallTarget::Unresolved(short.to_string()),
                            file: self.path.clone(),
                            line: node.start_position().row as u32 + 1,
                            col: node.start_position().column as u32,
                        });
                    }
                }
            }
        }

        self.walk_children(node);
    }

    /// Extract the tag name from a JSX element or self-closing element.
    fn extract_jsx_tag_name(&self, node: tree_sitter::Node) -> Option<String> {
        // For jsx_self_closing_element, the name is a direct child field
        if node.kind() == "jsx_self_closing_element" {
            if let Some(name_node) = node.child_by_field_name("name") {
                return Some(self.node_text(name_node).to_string());
            }
            // Fallback: look for first identifier/member_expression child
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i as u32) {
                    match child.kind() {
                        "identifier" | "member_expression" | "jsx_namespace_name" => {
                            return Some(self.node_text(child).to_string());
                        }
                        _ => {}
                    }
                }
            }
            return None;
        }

        // For jsx_element, find the jsx_opening_element child
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i as u32) {
                if child.kind() == "jsx_opening_element" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        return Some(self.node_text(name_node).to_string());
                    }
                    // Fallback: first identifier child
                    for j in 0..child.child_count() {
                        if let Some(grandchild) = child.child(j as u32) {
                            match grandchild.kind() {
                                "identifier" | "member_expression" | "jsx_namespace_name" => {
                                    return Some(self.node_text(grandchild).to_string());
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

fn check_static(node: tree_sitter::Node, source: &str) -> bool {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
            if let Ok(text) = child.utf8_text(source.as_bytes()) {
                if text == "static" {
                    return true;
                }
            }
        }
    }
    false
}

/// TS accessibility modifiers; JS methods are always public.
fn extract_method_visibility(node: tree_sitter::Node, source: &str) -> Visibility {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
            if child.kind() == "accessibility_modifier" {
                let text = child
                    .utf8_text(source.as_bytes())
                    .unwrap_or("")
                    .to_lowercase();
                return match text.as_str() {
                    "private" => Visibility::Private,
                    "protected" => Visibility::Protected,
                    "public" => Visibility::Public,
                    _ => Visibility::Public,
                };
            }
        }
    }
    Visibility::Public
}

fn count_params(node: tree_sitter::Node) -> u8 {
    if let Some(params) = node.child_by_field_name("parameters") {
        let mut count: u8 = 0;
        for i in 0..params.child_count() {
            if let Some(child) = params.child(i as u32) {
                match child.kind() {
                    "identifier"
                    | "required_parameter"
                    | "optional_parameter"
                    | "rest_parameter"
                    | "assignment_pattern"
                    | "destructuring_pattern"
                    | "object_pattern"
                    | "array_pattern" => {
                        count = count.saturating_add(1);
                    }
                    _ => {}
                }
            }
        }
        count
    } else {
        // Arrow functions can take a single param without parens: `x => x`.
        if let Some(param) = node.child_by_field_name("parameter") {
            if param.kind() == "identifier" {
                return 1;
            }
        }
        0
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
        // Replace identifiers with placeholder, keep JS/TS keywords
        if chars[i].is_alphabetic() || chars[i] == '_' || chars[i] == '$' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '$')
            {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            let lower = ident.to_lowercase();
            match lower.as_str() {
                "function" | "class" | "const" | "let" | "var" | "return" | "if" | "else"
                | "while" | "for" | "do" | "switch" | "case" | "break" | "continue" | "new"
                | "this" | "super" | "true" | "false" | "null" | "undefined" | "void"
                | "typeof" | "instanceof" | "in" | "of" | "delete" | "throw" | "try" | "catch"
                | "finally" | "yield" | "await" | "async" | "export" | "import" | "default"
                | "from" | "extends" | "static" | "get" | "set" | "number" | "string"
                | "boolean" | "any" | "never" | "interface" | "type" | "enum" | "implements"
                | "public" | "private" | "protected" | "readonly" | "abstract" | "declare"
                | "module" | "namespace" | "require" | "console" | "promise" | "array"
                | "object" | "map" | "date" | "json" | "math" | "error" | "regexp" => {
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

fn http_method_from_verb(verb: &str) -> Option<HttpMethod> {
    match verb.to_ascii_lowercase().as_str() {
        "get" => Some(HttpMethod::Get),
        "post" => Some(HttpMethod::Post),
        "put" => Some(HttpMethod::Put),
        "patch" => Some(HttpMethod::Patch),
        "delete" | "del" => Some(HttpMethod::Delete),
        _ => None,
    }
}

/// Whether an object name looks like an HTTP client (so `.get`/`.post` is a
/// request, not `map.get`). Matches known clients and `*Api`/`*Client`/`*Http`.
fn is_http_client_name(obj: &str) -> bool {
    let o = obj.to_ascii_lowercase();
    const NAMES: &[&str] = &[
        "axios",
        "http",
        "$http",
        "api",
        "client",
        "request",
        "superagent",
        "ky",
        "got",
        "instance",
        "fetch",
    ];
    NAMES.contains(&o.as_str())
        || o.ends_with("api")
        || o.ends_with("client")
        || o.ends_with("http")
        || o.ends_with("service")
}

/// Data-fetching hooks whose first argument is a URL/key path.
fn is_data_hook(name: &str) -> bool {
    matches!(
        name,
        "useSWR"
            | "useSWRMutation"
            | "useQuery"
            | "useMutation"
            | "useFetch"
            | "useRequest"
            | "useAsyncData"
    )
}

/// HTTP verb of a backend route registration. Express/koa/fastify use `.get`,
/// `.post`, ...; `all`/`any`/`use`/`options`/`head` mount for any/every method.
fn route_method_from_verb(verb: &str) -> Option<HttpMethod> {
    match verb.to_ascii_lowercase().as_str() {
        "get" => Some(HttpMethod::Get),
        "post" => Some(HttpMethod::Post),
        "put" => Some(HttpMethod::Put),
        "patch" => Some(HttpMethod::Patch),
        "delete" | "del" => Some(HttpMethod::Delete),
        "all" | "any" | "use" | "options" | "head" => Some(HttpMethod::Any),
        _ => None,
    }
}

/// HTTP verb of a NestJS method decorator (`@Get`, `@Post`, ...).
fn nest_method_from_decorator(name: &str) -> Option<HttpMethod> {
    match name {
        "Get" => Some(HttpMethod::Get),
        "Post" => Some(HttpMethod::Post),
        "Put" => Some(HttpMethod::Put),
        "Patch" => Some(HttpMethod::Patch),
        "Delete" => Some(HttpMethod::Delete),
        "All" | "Options" | "Head" => Some(HttpMethod::Any),
        _ => None,
    }
}

/// Whether an object name looks like an express/koa/fastify app or router (so
/// `.get`/`.post` is a route registration, not a client request or `map.get`).
/// Deliberately excludes generic client names (`api`, `http`, `client`) so
/// client HTTP calls are not misclassified as server routes.
fn is_router_name(obj: &str) -> bool {
    let o = obj.to_ascii_lowercase();
    const NAMES: &[&str] = &["app", "router", "server", "fastify", "express", "koa"];
    NAMES.contains(&o.as_str())
        || o.ends_with("router")
        || o.ends_with("app")
        || o.ends_with("server")
}

/// Last dotted/bracketed segment of an object expression: `this.router` ->
/// `router`, so member chains still match router names.
fn last_segment(obj: &str) -> &str {
    obj.rsplit(['.', ']', ' ']).next().unwrap_or(obj)
}

/// Join a NestJS controller base path with a method sub-path into one route
/// path with a single leading slash (`/api` + `x` -> `/api/x`; both empty -> `/`).
fn join_route(base: &str, sub: &str) -> String {
    let b = base.trim_matches('/');
    let s = sub.trim_matches('/');
    let joined = match (b.is_empty(), s.is_empty()) {
        (true, true) => String::new(),
        (true, false) => s.to_string(),
        (false, true) => b.to_string(),
        (false, false) => format!("{b}/{s}"),
    };
    if joined.is_empty() {
        "/".to_string()
    } else {
        format!("/{joined}")
    }
}

fn strip_quotes(s: &str) -> String {
    s.trim()
        .trim_start_matches(['"', '\'', '`'])
        .trim_end_matches(['"', '\'', '`'])
        .to_string()
}

/// Reduce a URL to a comparable path: drop protocol+host and query/fragment,
/// ensure a leading slash, drop the trailing slash. Param normalization
/// (`:id`/`${id}`/`{id}` -> `*`) happens at match time.
fn normalize_url_path(url: &str) -> String {
    let mut u = url.trim();
    if let Some(pos) = u.find("://") {
        match u[pos + 3..].find('/') {
            Some(slash) => u = &u[pos + 3 + slash..],
            None => return String::new(),
        }
    }
    let u = u.split(['?', '#']).next().unwrap_or(u);
    // A `${...}` glued to the end of a segment (not right after `/`) is a
    // query-string / suffix builder - `/applications${query}` - not a path
    // param, so truncate it. `/users/${id}` (after `/`) is a real param, kept.
    let u = match u.find("${") {
        Some(i) if i > 0 && u.as_bytes()[i - 1] != b'/' => &u[..i],
        _ => u,
    };
    if u.is_empty() {
        return String::new();
    }
    let path = if u.starts_with('/') {
        u.to_string()
    } else {
        format!("/{u}")
    };
    path.trim_end_matches('/').to_string()
}
