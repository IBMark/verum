//! Java frontend. Tree-sitter-java frontend at Rust/PHP-frontend parity:
//! file registration + class / interface / enum / record / method / field / call
//! extraction, package-qualified names, real visibility from modifiers, method
//! parameter counts, `extends`/`implements` heritage edges, `import` uses with a
//! short-name -> FQN alias map, instance/static call receivers, `new` object
//! creation uses, and annotation text captured into each symbol's `doc_comment`
//! (the interface the java_web Spring/JAX-RS route extractor reads).

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

use verum_nucleus::{
    Call, CallTarget, FileId, FileInfo, Ir, Language, Symbol, SymbolId, SymbolKind, Visibility,
};

pub fn parse_file(path: &Path) -> Result<Ir> {
    let source =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let tree = crate::parser_pool::parse("java", || tree_sitter_java::LANGUAGE.into(), &source)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse {}", path.display()))?;

    let mut extractor = JavaExtractor {
        source: source.clone(),
        path: path.to_path_buf(),
        next_id: hash_path(path),
        package: String::new(),
        current_class: None,
        current_method: None,
        imports: HashMap::new(),
        file_scope: None,
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
            language: Language::Java,
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

struct JavaExtractor {
    source: String,
    path: std::path::PathBuf,
    next_id: u64,
    package: String,
    current_class: Option<SymbolId>,
    current_method: Option<SymbolId>,
    /// Maps short type name -> fully qualified name from `import` statements.
    imports: HashMap<String, String>,
    /// File-level pseudo symbol for top-level `import`/`new` references.
    file_scope: Option<SymbolId>,
    ir: Ir,
}

impl JavaExtractor {
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

    fn fq(&self, name: &str) -> String {
        match (self.package.is_empty(), self.current_class) {
            (_, Some(cid)) => match self.ir.symbols.get(&cid) {
                Some(c) => format!("{}::{}", c.fully_qualified, name),
                None => name.to_string(),
            },
            (false, None) => format!("{}.{}", self.package, name),
            (true, None) => name.to_string(),
        }
    }

    /// Synthetic file-scope symbol so top-level references (imports, `new`)
    /// always have a valid caller and don't dangle.
    fn get_or_create_file_scope(&mut self) -> SymbolId {
        if let Some(id) = self.file_scope {
            return id;
        }
        let id = self.alloc_id();
        let name = format!("__file_scope_{}", self.path.display());
        self.ir.symbols.insert(
            id,
            Symbol {
                id,
                name: name.clone(),
                fully_qualified: name,
                kind: SymbolKind::Function,
                visibility: Visibility::Private,
                file: self.path.clone(),
                line_start: 1,
                line_end: 1,
                col_start: 0,
                col_end: 0,
                language: Language::Java,
                parent: None,
                hash: 0,
                normalized_hash: 0,
                flow_hash: 0,
                param_count: 0,
                is_entry_point: true,
                doc_comment: None,
            },
        );
        self.file_scope = Some(id);
        id
    }

    /// Record an Unresolved use of `name` from `caller`, plus the aliased FQN
    /// form when `name` was brought in via an `import`.
    fn record_use(&mut self, caller: SymbolId, name: &str, line: u32, col: u32) {
        if name.is_empty() {
            return;
        }
        self.ir.calls.push(Call {
            caller,
            callee: CallTarget::Unresolved(name.to_string()),
            file: self.path.clone(),
            line,
            col,
        });
        if let Some(fq) = self.imports.get(name).cloned() {
            if fq != name {
                self.ir.calls.push(Call {
                    caller,
                    callee: CallTarget::Unresolved(fq),
                    file: self.path.clone(),
                    line,
                    col,
                });
            }
        }
    }

    fn walk_node(&mut self, node: tree_sitter::Node) {
        match node.kind() {
            "package_declaration" => {
                // `package a.b.c;`
                let text = self.node_text(node);
                self.package = text
                    .trim_start_matches("package")
                    .trim()
                    .trim_end_matches(';')
                    .trim()
                    .to_string();
                self.walk_children(node);
            }
            "import_declaration" => self.handle_import(node),
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration" => self.handle_type(node),
            "field_declaration" => self.handle_field(node),
            "method_declaration" | "constructor_declaration" => self.handle_method(node),
            "method_invocation" => self.handle_call(node),
            "object_creation_expression" => self.handle_object_creation(node),
            _ => self.walk_children(node),
        }
    }

    fn walk_children(&mut self, node: tree_sitter::Node) {
        for i in 0..node.child_count() {
            if let Some(c) = node.child(i as u32) {
                self.walk_node(c);
            }
        }
    }

    /// `import a.b.C;` / `import static a.b.C.m;` / `import a.b.*;`
    fn handle_import(&mut self, node: tree_sitter::Node) {
        let text = self.node_text(node);
        let body = text
            .trim_start_matches("import")
            .trim()
            .trim_start_matches("static")
            .trim()
            .trim_end_matches(';')
            .trim();
        if body.is_empty() || body.ends_with('*') {
            return;
        }
        let fqn = body.to_string();
        let short = fqn.rsplit('.').next().unwrap_or(&fqn).to_string();
        if !short.is_empty() {
            self.imports.insert(short, fqn.clone());
        }
        // Record the imported type as a use so it isn't reported dead.
        let caller = self
            .current_method
            .or(self.current_class)
            .unwrap_or_else(|| self.get_or_create_file_scope());
        self.ir.calls.push(Call {
            caller,
            callee: CallTarget::Unresolved(fqn),
            file: self.path.clone(),
            line: node.start_position().row as u32 + 1,
            col: node.start_position().column as u32,
        });
    }

    fn handle_type(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();
        let (hash, normalized) = self.hash_node(node);
        let modifiers = self.modifiers_of(node);
        let visibility = self.visibility_from(modifiers);
        let doc_comment = self.annotations_text(modifiers);
        let id = self.alloc_id();
        let fq = self.fq(&name);
        let kind = match node.kind() {
            "interface_declaration" => SymbolKind::Interface,
            "enum_declaration" => SymbolKind::Enum,
            _ => SymbolKind::Class,
        };
        self.ir.symbols.insert(
            id,
            Symbol {
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
                language: Language::Java,
                parent: self.current_class,
                hash,
                normalized_hash: normalized,
                flow_hash: normalized,
                param_count: 0,
                is_entry_point: false,
                doc_comment,
            },
        );

        // extends / implements heritage edges so parents aren't dead.
        self.handle_heritage(node, id);

        let prev = self.current_class.replace(id);
        if let Some(body) = node.child_by_field_name("body") {
            self.walk_children(body);
        }
        self.current_class = prev;
    }

    /// Record `extends Base` and `implements I, J` as Unresolved call edges.
    fn handle_heritage(&mut self, node: tree_sitter::Node, class_id: SymbolId) {
        let line = node.start_position().row as u32 + 1;
        let col = node.start_position().column as u32;
        if let Some(sc) = node.child_by_field_name("superclass") {
            for name in self.collect_type_names(sc) {
                self.record_use(class_id, &name, line, col);
            }
        }
        if let Some(ifaces) = node.child_by_field_name("interfaces") {
            for name in self.collect_type_names(ifaces) {
                self.record_use(class_id, &name, line, col);
            }
        }
    }

    /// Collect head type names under a `superclass` / `super_interfaces` node,
    /// stripping generic arguments (`List<Foo>` -> `List`).
    fn collect_type_names(&self, node: tree_sitter::Node) -> Vec<String> {
        let mut out = Vec::new();
        for i in 0..node.named_child_count() {
            if let Some(child) = node.named_child(i as u32) {
                match child.kind() {
                    "type_identifier" | "scoped_type_identifier" => {
                        out.push(self.node_text(child).to_string());
                    }
                    "generic_type" => {
                        if let Some(head) = child.named_child(0) {
                            out.push(self.node_text(head).to_string());
                        }
                    }
                    // `type_list` inside super_interfaces
                    "type_list" => out.extend(self.collect_type_names(child)),
                    _ => {}
                }
            }
        }
        out
    }

    fn handle_field(&mut self, node: tree_sitter::Node) {
        let modifiers = self.modifiers_of(node);
        let visibility = self.visibility_from(modifiers);
        let doc_comment = self.annotations_text(modifiers);
        // A single `field_declaration` may declare several names: `int a, b;`.
        for i in 0..node.named_child_count() {
            let child = match node.named_child(i as u32) {
                Some(c) => c,
                None => continue,
            };
            if child.kind() != "variable_declarator" {
                continue;
            }
            let name = child
                .child_by_field_name("name")
                .map(|n| self.node_text(n).to_string())
                .unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let (hash, normalized) = self.hash_node(child);
            let id = self.alloc_id();
            let fq = self.fq(&name);
            self.ir.symbols.insert(
                id,
                Symbol {
                    id,
                    name,
                    fully_qualified: fq,
                    kind: SymbolKind::Property,
                    visibility: visibility.clone(),
                    file: self.path.clone(),
                    line_start: node.start_position().row as u32 + 1,
                    line_end: node.end_position().row as u32 + 1,
                    col_start: node.start_position().column as u32,
                    col_end: node.end_position().column as u32,
                    language: Language::Java,
                    parent: self.current_class,
                    hash,
                    normalized_hash: normalized,
                    flow_hash: normalized,
                    param_count: 0,
                    is_entry_point: false,
                    doc_comment: doc_comment.clone(),
                },
            );
        }
        // Walk any initializer expressions (e.g. `= new Foo()`).
        self.walk_children(node);
    }

    fn handle_method(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_else(|| "<init>".to_string());
        let (hash, normalized) = self.hash_node(node);
        let modifiers = self.modifiers_of(node);
        let visibility = self.visibility_from(modifiers);
        let doc_comment = self.annotations_text(modifiers);
        let param_count = self.param_count(node);
        let id = self.alloc_id();
        let fq = self.fq(&name);
        self.ir.symbols.insert(
            id,
            Symbol {
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
                language: Language::Java,
                parent: self.current_class,
                hash,
                normalized_hash: normalized,
                flow_hash: normalized,
                param_count,
                is_entry_point: false,
                doc_comment,
            },
        );
        let prev = self.current_method.replace(id);
        if let Some(body) = node.child_by_field_name("body") {
            self.walk_children(body);
        }
        self.current_method = prev;
    }

    fn handle_call(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();
        if name.is_empty() {
            self.walk_children(node);
            return;
        }
        // Capture the receiver: `obj.method()` / `Type.staticMethod()`.
        let receiver = node
            .child_by_field_name("object")
            .map(|n| self.node_text(n).to_string())
            .filter(|s| !s.is_empty());
        let target = match &receiver {
            Some(r) => format!("{}.{}", r, name),
            None => name.clone(),
        };
        if let Some(caller) = self.current_method.or(self.current_class) {
            self.ir.calls.push(Call {
                caller,
                callee: CallTarget::Unresolved(target),
                file: self.path.clone(),
                line: node.start_position().row as u32 + 1,
                col: node.start_position().column as u32,
            });
            // If the receiver is an imported type, also emit the FQN-qualified form.
            if let Some(r) = &receiver {
                if let Some(fq) = self.imports.get(r).cloned() {
                    self.ir.calls.push(Call {
                        caller,
                        callee: CallTarget::Unresolved(format!("{}.{}", fq, name)),
                        file: self.path.clone(),
                        line: node.start_position().row as u32 + 1,
                        col: node.start_position().column as u32,
                    });
                }
            }
        }
        // Walk arguments (and receiver expression) for nested/chained calls.
        self.walk_children(node);
    }

    /// `new Foo()` - record a use of the constructed type.
    fn handle_object_creation(&mut self, node: tree_sitter::Node) {
        if let Some(ty) = node.child_by_field_name("type") {
            let name = match ty.kind() {
                "generic_type" => ty
                    .named_child(0)
                    .map(|n| self.node_text(n).to_string())
                    .unwrap_or_default(),
                _ => self.node_text(ty).to_string(),
            };
            let caller = self
                .current_method
                .or(self.current_class)
                .unwrap_or_else(|| self.get_or_create_file_scope());
            let line = node.start_position().row as u32 + 1;
            let col = node.start_position().column as u32;
            self.record_use(caller, &name, line, col);
        }
        // Walk constructor arguments for nested calls.
        if let Some(args) = node.child_by_field_name("arguments") {
            self.walk_children(args);
        }
    }

    fn modifiers_of<'a>(&self, node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
        for i in 0..node.child_count() {
            if let Some(c) = node.child(i as u32) {
                if c.kind() == "modifiers" {
                    return Some(c);
                }
            }
        }
        None
    }

    /// Map access modifiers to visibility; package-private (none) -> Global.
    fn visibility_from(&self, modifiers: Option<tree_sitter::Node>) -> Visibility {
        if let Some(mods) = modifiers {
            for i in 0..mods.child_count() {
                if let Some(c) = mods.child(i as u32) {
                    match self.node_text(c) {
                        "public" => return Visibility::Public,
                        "protected" => return Visibility::Protected,
                        "private" => return Visibility::Private,
                        _ => {}
                    }
                }
            }
        }
        Visibility::Global
    }

    /// Join every annotation's source text (e.g. `@GetMapping("/x") @ResponseBody`).
    fn annotations_text(&self, modifiers: Option<tree_sitter::Node>) -> Option<String> {
        let mods = modifiers?;
        let mut parts = Vec::new();
        for i in 0..mods.child_count() {
            if let Some(c) = mods.child(i as u32) {
                if c.kind() == "annotation" || c.kind() == "marker_annotation" {
                    parts.push(self.node_text(c).to_string());
                }
            }
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }

    fn param_count(&self, node: tree_sitter::Node) -> u8 {
        let params = match node.child_by_field_name("parameters") {
            Some(p) => p,
            None => return 0,
        };
        let mut count: u32 = 0;
        for i in 0..params.named_child_count() {
            if let Some(c) = params.named_child(i as u32) {
                if c.kind() == "formal_parameter" || c.kind() == "spread_parameter" {
                    count += 1;
                }
            }
        }
        count.min(u8::MAX as u32) as u8
    }
}

fn hash_path(path: &Path) -> u64 {
    crate::stable_hash(path.to_string_lossy().as_ref())
}

fn hash_string(s: &str) -> u64 {
    crate::stable_hash(s)
}

fn hash_normalized(s: &str) -> u64 {
    crate::stable_hash(&crate::strip_comments(s, true, false, true))
}
