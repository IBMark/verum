use std::path::Path;

use anyhow::{Context, Result};

use verum_nucleus::{
    Call, CallTarget, FileId, FileInfo, HttpCall, HttpMethod, Ir, Language, Symbol, SymbolId,
    SymbolKind, Visibility,
};

/// Parse a PHP file into a partial IR.
pub fn parse_file(path: &Path) -> Result<Ir> {
    let source =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let tree = crate::parser_pool::parse("php", || tree_sitter_php::LANGUAGE_PHP.into(), &source)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse {}", path.display()))?;

    let mut extractor = PhpExtractor {
        depth: 0,
        source: source.clone(),
        path: path.to_path_buf(),
        next_id: hash_path(path),
        current_namespace: String::new(),
        current_class: None,
        current_function: None,
        ir: Ir::new(),
        use_aliases: std::collections::HashMap::new(),
        file_scope: None,
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
            language: Language::Php,
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

struct PhpExtractor {
    /// Current `walk_node` recursion depth, checked against
    /// [`crate::MAX_RECURSION_DEPTH`] so a pathologically deep AST cannot
    /// overflow the stack (an abort no panic guard can catch).
    depth: usize,
    source: String,
    path: std::path::PathBuf,
    next_id: u64,
    current_namespace: String,
    current_class: Option<SymbolId>,
    current_function: Option<SymbolId>,
    ir: Ir,
    /// Maps short alias -> fully qualified name from `use` statements.
    use_aliases: std::collections::HashMap<String, String>,
    /// File-level pseudo symbol for top-level use/extends references.
    file_scope: Option<SymbolId>,
}

impl PhpExtractor {
    fn alloc_id(&mut self) -> SymbolId {
        self.next_id += 1;
        SymbolId(self.next_id)
    }

    fn fully_qualified(&self, name: &str) -> String {
        if self.current_namespace.is_empty() {
            name.to_string()
        } else {
            format!("{}\\{}", self.current_namespace, name)
        }
    }

    fn node_text<'a>(&'a self, node: tree_sitter::Node<'a>) -> &'a str {
        node.utf8_text(self.source.as_bytes()).unwrap_or("")
    }

    fn hash_node(&self, node: tree_sitter::Node) -> (u64, u64) {
        let text = &self.source[node.start_byte()..node.end_byte()];
        (hash_string(text), hash_normalized(text))
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
            "namespace_definition" => self.handle_namespace(node),
            // Use statements: `use App\Models\User;` or `use App\Models\User as UserModel;`
            "namespace_use_declaration" => self.handle_use_declaration(node),
            "class_declaration" => self.handle_class(node),
            "interface_declaration" => self.handle_interface(node),
            "trait_declaration" => self.handle_trait(node),
            "function_definition" => self.handle_function(node),
            "method_declaration" => self.handle_method(node),
            "function_call_expression" => self.handle_function_call(node),
            "member_call_expression" => self.handle_member_call(node),
            "scoped_call_expression" => self.handle_scoped_call(node),
            // Class constant access: `User::class`, `Model::query()`
            "class_constant_access_expression" => self.handle_class_constant_access(node),
            // Object creation: `new User()`
            "object_creation_expression" => self.handle_object_creation(node),
            // Trait use inside class body: `use Notifiable, HasFactory;`
            "use_declaration" => self.handle_trait_use(node),
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
            language: Language::Php,
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

    /// Handle `use App\Models\User;` or `use App\Models\User as UserModel;`
    fn handle_use_declaration(&mut self, node: tree_sitter::Node) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i as u32) {
                if child.kind() == "namespace_use_clause" {
                    let fq_name = child
                        .child_by_field_name("name")
                        .or_else(|| {
                            // Some grammars put the name as first child
                            for j in 0..child.child_count() {
                                if let Some(grandchild) = child.child(j as u32) {
                                    if grandchild.kind() == "qualified_name"
                                        || grandchild.kind() == "namespace_name"
                                        || grandchild.kind() == "name"
                                    {
                                        return Some(grandchild);
                                    }
                                }
                            }
                            None
                        })
                        .map(|n| self.node_text(n).to_string())
                        .unwrap_or_default();

                    if fq_name.is_empty() {
                        continue;
                    }

                    let alias = child
                        .child_by_field_name("alias")
                        .map(|n| self.node_text(n).to_string());

                    let short_name = alias.unwrap_or_else(|| {
                        fq_name.rsplit('\\').next().unwrap_or(&fq_name).to_string()
                    });

                    self.use_aliases.insert(short_name.clone(), fq_name.clone());

                    // A `use` counts as a reference; record both FQ and short name.
                    let caller = self
                        .current_function
                        .or(self.current_class)
                        .unwrap_or_else(|| self.get_or_create_file_scope());

                    self.ir.calls.push(Call {
                        caller,
                        callee: CallTarget::Unresolved(fq_name.clone()),
                        file: self.path.clone(),
                        line: node.start_position().row as u32 + 1,
                        col: node.start_position().column as u32,
                    });
                    self.ir.calls.push(Call {
                        caller,
                        callee: CallTarget::Unresolved(short_name),
                        file: self.path.clone(),
                        line: node.start_position().row as u32 + 1,
                        col: node.start_position().column as u32,
                    });
                } else if child.kind() == "namespace_use_group" {
                    // Group use: `use App\Models\{User, Server};`
                    self.handle_group_use(child, node);
                } else if child.kind() == "qualified_name" || child.kind() == "namespace_name" {
                    // Simple use: `use App\Models\User;` - the name is a direct child
                    let fq_name = self.node_text(child).to_string();
                    if !fq_name.is_empty() {
                        let short_name =
                            fq_name.rsplit('\\').next().unwrap_or(&fq_name).to_string();
                        self.use_aliases.insert(short_name.clone(), fq_name.clone());

                        let caller = self
                            .current_function
                            .or(self.current_class)
                            .unwrap_or_else(|| self.get_or_create_file_scope());
                        self.ir.calls.push(Call {
                            caller,
                            callee: CallTarget::Unresolved(fq_name),
                            file: self.path.clone(),
                            line: node.start_position().row as u32 + 1,
                            col: node.start_position().column as u32,
                        });
                        self.ir.calls.push(Call {
                            caller,
                            callee: CallTarget::Unresolved(short_name),
                            file: self.path.clone(),
                            line: node.start_position().row as u32 + 1,
                            col: node.start_position().column as u32,
                        });
                    }
                }
            }
        }
    }

    /// Handle group use declarations: `use App\Models\{User, Server, Node};`
    fn handle_group_use(&mut self, group_node: tree_sitter::Node, parent_node: tree_sitter::Node) {
        let mut prefix = String::new();
        for i in 0..group_node.child_count() {
            if let Some(child) = group_node.child(i as u32) {
                if child.kind() == "namespace_name" || child.kind() == "qualified_name" {
                    prefix = self.node_text(child).to_string();
                    break;
                }
            }
        }

        for i in 0..group_node.child_count() {
            if let Some(child) = group_node.child(i as u32) {
                if child.kind() == "namespace_use_clause" {
                    let name = child
                        .child_by_field_name("name")
                        .map(|n| self.node_text(n).to_string())
                        .unwrap_or_else(|| {
                            // Fallback: first identifier child
                            for j in 0..child.child_count() {
                                if let Some(gc) = child.child(j as u32) {
                                    if gc.kind() == "name" || gc.kind() == "qualified_name" {
                                        return self.node_text(gc).to_string();
                                    }
                                }
                            }
                            String::new()
                        });

                    if name.is_empty() {
                        continue;
                    }

                    let fq_name = if prefix.is_empty() {
                        name.clone()
                    } else {
                        format!("{}\\{}", prefix, name)
                    };

                    let short_name = fq_name.rsplit('\\').next().unwrap_or(&fq_name).to_string();

                    self.use_aliases.insert(short_name.clone(), fq_name.clone());

                    let caller = self
                        .current_function
                        .or(self.current_class)
                        .unwrap_or_else(|| self.get_or_create_file_scope());
                    self.ir.calls.push(Call {
                        caller,
                        callee: CallTarget::Unresolved(fq_name),
                        file: self.path.clone(),
                        line: parent_node.start_position().row as u32 + 1,
                        col: parent_node.start_position().column as u32,
                    });
                    self.ir.calls.push(Call {
                        caller,
                        callee: CallTarget::Unresolved(short_name),
                        file: self.path.clone(),
                        line: parent_node.start_position().row as u32 + 1,
                        col: parent_node.start_position().column as u32,
                    });
                }
            }
        }
    }

    /// Handle `Foo::class`, `Foo::CONSTANT`, `Foo::staticMethod()`
    fn handle_class_constant_access(&mut self, node: tree_sitter::Node) {
        let class_name = node
            .child_by_field_name("class")
            .or_else(|| node.child(0))
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        if !class_name.is_empty()
            && class_name != "self"
            && class_name != "static"
            && class_name != "parent"
        {
            let caller = self
                .current_function
                .or(self.current_class)
                .unwrap_or_else(|| self.get_or_create_file_scope());

            self.ir.calls.push(Call {
                caller,
                callee: CallTarget::Unresolved(class_name.clone()),
                file: self.path.clone(),
                line: node.start_position().row as u32 + 1,
                col: node.start_position().column as u32,
            });

            if let Some(fq) = self.use_aliases.get(&class_name) {
                self.ir.calls.push(Call {
                    caller,
                    callee: CallTarget::Unresolved(fq.clone()),
                    file: self.path.clone(),
                    line: node.start_position().row as u32 + 1,
                    col: node.start_position().column as u32,
                });
            }
        }

        let child_count = node.child_count();
        for i in 0..child_count {
            if let Some(child) = node.child(i as u32) {
                self.walk_node(child);
            }
        }
    }

    /// Handle `new User()`, `new ServerCreationService()`
    fn handle_object_creation(&mut self, node: tree_sitter::Node) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i as u32) {
                if child.kind() == "name"
                    || child.kind() == "qualified_name"
                    || child.kind() == "namespace_name"
                {
                    let class_name = self.node_text(child).to_string();
                    if !class_name.is_empty() && class_name != "self" && class_name != "static" {
                        let caller = self
                            .current_function
                            .or(self.current_class)
                            .unwrap_or_else(|| self.get_or_create_file_scope());

                        self.ir.calls.push(Call {
                            caller,
                            callee: CallTarget::Unresolved(class_name.clone()),
                            file: self.path.clone(),
                            line: node.start_position().row as u32 + 1,
                            col: node.start_position().column as u32,
                        });

                        if let Some(fq) = self.use_aliases.get(&class_name) {
                            self.ir.calls.push(Call {
                                caller,
                                callee: CallTarget::Unresolved(fq.clone()),
                                file: self.path.clone(),
                                line: node.start_position().row as u32 + 1,
                                col: node.start_position().column as u32,
                            });
                        }
                    }
                }
            }
        }

        if let Some(args) = node.child_by_field_name("arguments") {
            let child_count = args.child_count();
            for i in 0..child_count {
                if let Some(child) = args.child(i as u32) {
                    self.walk_node(child);
                }
            }
        }
    }

    /// Handle `use TraitName, AnotherTrait;` inside class bodies.
    fn handle_trait_use(&mut self, node: tree_sitter::Node) {
        let caller = self
            .current_class
            .or(self.current_function)
            .unwrap_or_else(|| self.get_or_create_file_scope());

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i as u32) {
                match child.kind() {
                    "name" | "qualified_name" | "namespace_name" => {
                        let trait_name = self.node_text(child).to_string();
                        if !trait_name.is_empty() && trait_name != "use" {
                            self.ir.calls.push(Call {
                                caller,
                                callee: CallTarget::Unresolved(trait_name.clone()),
                                file: self.path.clone(),
                                line: node.start_position().row as u32 + 1,
                                col: node.start_position().column as u32,
                            });
                            let short = trait_name.rsplit('\\').next().unwrap_or(&trait_name);
                            if let Some(fq) = self.use_aliases.get(short) {
                                self.ir.calls.push(Call {
                                    caller,
                                    callee: CallTarget::Unresolved(fq.clone()),
                                    file: self.path.clone(),
                                    line: node.start_position().row as u32 + 1,
                                    col: node.start_position().column as u32,
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn handle_namespace(&mut self, node: tree_sitter::Node) {
        if let Some(name_node) = node.child_by_field_name("name") {
            self.current_namespace = self.node_text(name_node).to_string();
        }

        if let Some(body) = node.child_by_field_name("body") {
            let child_count = body.child_count();
            for i in 0..child_count {
                if let Some(child) = body.child(i as u32) {
                    self.walk_node(child);
                }
            }
        } else {
            // Namespace without braces - walk remaining siblings
            let child_count = node.child_count();
            for i in 0..child_count {
                if let Some(child) = node.child(i as u32) {
                    if child.kind() != "namespace_name" && child.kind() != "namespace" {
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
            language: Language::Php,
            parent: None,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count: 0,
            is_entry_point: false,
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);

        self.extract_class_heritage(node, id);

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

    /// Extract parent class and implemented interfaces from class declaration.
    fn extract_class_heritage(&mut self, node: tree_sitter::Node, class_id: SymbolId) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i as u32) {
                match child.kind() {
                    // `extends BaseClass`
                    "base_clause" => {
                        for j in 0..child.child_count() {
                            if let Some(name_node) = child.child(j as u32) {
                                if name_node.kind() == "name"
                                    || name_node.kind() == "qualified_name"
                                    || name_node.kind() == "namespace_name"
                                {
                                    let parent_name = self.node_text(name_node).to_string();
                                    if !parent_name.is_empty() {
                                        self.ir.calls.push(Call {
                                            caller: class_id,
                                            callee: CallTarget::Unresolved(parent_name.clone()),
                                            file: self.path.clone(),
                                            line: child.start_position().row as u32 + 1,
                                            col: child.start_position().column as u32,
                                        });
                                        if let Some(fq) = self.use_aliases.get(&parent_name) {
                                            self.ir.calls.push(Call {
                                                caller: class_id,
                                                callee: CallTarget::Unresolved(fq.clone()),
                                                file: self.path.clone(),
                                                line: child.start_position().row as u32 + 1,
                                                col: child.start_position().column as u32,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // `implements InterfaceA, InterfaceB`
                    "class_interface_clause" => {
                        for j in 0..child.child_count() {
                            if let Some(name_node) = child.child(j as u32) {
                                if name_node.kind() == "name"
                                    || name_node.kind() == "qualified_name"
                                    || name_node.kind() == "namespace_name"
                                {
                                    let iface_name = self.node_text(name_node).to_string();
                                    if !iface_name.is_empty() {
                                        self.ir.calls.push(Call {
                                            caller: class_id,
                                            callee: CallTarget::Unresolved(iface_name.clone()),
                                            file: self.path.clone(),
                                            line: child.start_position().row as u32 + 1,
                                            col: child.start_position().column as u32,
                                        });
                                        if let Some(fq) = self.use_aliases.get(&iface_name) {
                                            self.ir.calls.push(Call {
                                                caller: class_id,
                                                callee: CallTarget::Unresolved(fq.clone()),
                                                file: self.path.clone(),
                                                line: child.start_position().row as u32 + 1,
                                                col: child.start_position().column as u32,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn handle_interface(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();
        let fq = self.fully_qualified(&name);

        let symbol = Symbol {
            id,
            name,
            fully_qualified: fq,
            kind: SymbolKind::Interface,
            visibility: Visibility::Public,
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: Language::Php,
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

    fn handle_trait(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();
        let fq = self.fully_qualified(&name);

        let symbol = Symbol {
            id,
            name,
            fully_qualified: fq,
            kind: SymbolKind::Trait,
            visibility: Visibility::Public,
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: Language::Php,
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

    fn handle_function(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();
        let fq = self.fully_qualified(&name);

        let param_count = count_params(node);

        let symbol = Symbol {
            id,
            name,
            fully_qualified: fq,
            kind: SymbolKind::Function,
            visibility: Visibility::Global,
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: Language::Php,
            parent: None,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count,
            is_entry_point: false,
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);

        self.extract_parameter_type_hints(node, id);

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

    fn handle_method(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();

        let fq = if let Some(class_id) = self.current_class {
            if let Some(class_sym) = self.ir.symbols.get(&class_id) {
                format!("{}::{}", class_sym.fully_qualified, name)
            } else {
                self.fully_qualified(&name)
            }
        } else {
            self.fully_qualified(&name)
        };

        let visibility = extract_visibility(node, &self.source);
        let is_static = check_static(node, &self.source);
        let param_count = count_params(node);

        let kind = if is_static {
            SymbolKind::StaticMethod
        } else {
            SymbolKind::Method
        };

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
            language: Language::Php,
            parent: self.current_class,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count,
            is_entry_point: false,
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);

        self.extract_parameter_type_hints(node, id);

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

    /// Extract type hints from function/method parameters and register as calls.
    /// This handles constructor DI, method injection, and form request type hints.
    fn extract_parameter_type_hints(&mut self, node: tree_sitter::Node, caller_id: SymbolId) {
        let params = match node.child_by_field_name("parameters") {
            Some(p) => p,
            None => return,
        };

        for i in 0..params.child_count() {
            if let Some(child) = params.child(i as u32) {
                match child.kind() {
                    "simple_parameter" | "property_promotion_parameter" | "variadic_parameter" => {
                        self.extract_type_from_param(child, caller_id);
                    }
                    _ => {}
                }
            }
        }
    }

    fn extract_type_from_param(&mut self, param_node: tree_sitter::Node, caller_id: SymbolId) {
        if let Some(type_node) = param_node.child_by_field_name("type") {
            self.register_type_as_call(type_node, caller_id, 0);
        } else {
            for i in 0..param_node.child_count() {
                if let Some(child) = param_node.child(i as u32) {
                    match child.kind() {
                        "named_type" | "qualified_name" | "name" | "optional_type"
                        | "union_type" | "intersection_type" | "nullable_type" => {
                            self.register_type_as_call(child, caller_id, 0);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Register a type reference as a call (resolving through use aliases).
    ///
    /// Depth-capped: union/nullable types recurse one level per component, so
    /// a hostile deeply-nested type expression would otherwise overflow the
    /// stack. Components past the cap are skipped deterministically.
    fn register_type_as_call(
        &mut self,
        type_node: tree_sitter::Node,
        caller_id: SymbolId,
        depth: usize,
    ) {
        if depth >= crate::MAX_RECURSION_DEPTH {
            return;
        }
        match type_node.kind() {
            "union_type" | "intersection_type" => {
                for i in 0..type_node.child_count() {
                    if let Some(child) = type_node.child(i as u32) {
                        self.register_type_as_call(child, caller_id, depth + 1);
                    }
                }
            }
            "optional_type" | "nullable_type" => {
                for i in 0..type_node.child_count() {
                    if let Some(child) = type_node.child(i as u32) {
                        if child.kind() != "?" {
                            self.register_type_as_call(child, caller_id, depth + 1);
                        }
                    }
                }
            }
            _ => {
                let type_name = self.node_text(type_node).to_string();
                let lower = type_name.to_lowercase();
                if matches!(
                    lower.as_str(),
                    "int"
                        | "string"
                        | "float"
                        | "bool"
                        | "array"
                        | "void"
                        | "null"
                        | "mixed"
                        | "object"
                        | "callable"
                        | "iterable"
                        | "self"
                        | "static"
                        | "parent"
                        | "true"
                        | "false"
                        | "never"
                        | "\\closure"
                        | "closure"
                ) {
                    return;
                }

                if type_name.is_empty() {
                    return;
                }

                self.ir.calls.push(Call {
                    caller: caller_id,
                    callee: CallTarget::Unresolved(type_name.clone()),
                    file: self.path.clone(),
                    line: type_node.start_position().row as u32 + 1,
                    col: type_node.start_position().column as u32,
                });

                let short = type_name.rsplit('\\').next().unwrap_or(&type_name);
                if let Some(fq) = self.use_aliases.get(short) {
                    self.ir.calls.push(Call {
                        caller: caller_id,
                        callee: CallTarget::Unresolved(fq.clone()),
                        file: self.path.clone(),
                        line: type_node.start_position().row as u32 + 1,
                        col: type_node.start_position().column as u32,
                    });
                }
                if short != type_name {
                    self.ir.calls.push(Call {
                        caller: caller_id,
                        callee: CallTarget::Unresolved(short.to_string()),
                        file: self.path.clone(),
                        line: type_node.start_position().row as u32 + 1,
                        col: type_node.start_position().column as u32,
                    });
                }
            }
        }
    }

    /// Collect the `argument` child nodes of an `arguments` node, in order.
    fn arg_nodes<'a>(&self, args: tree_sitter::Node<'a>) -> Vec<tree_sitter::Node<'a>> {
        let mut out = Vec::new();
        for i in 0..args.child_count() {
            if let Some(child) = args.child(i as u32) {
                if child.kind() == "argument" {
                    out.push(child);
                }
            }
        }
        out
    }

    /// If the argument wraps a plain string literal, return its content (without
    /// the surrounding quotes).
    fn arg_string_literal(&self, arg: tree_sitter::Node) -> Option<String> {
        let child = arg.named_child(0)?;
        if !matches!(child.kind(), "string" | "encapsed_string") {
            return None;
        }
        for j in 0..child.child_count() {
            if let Some(sc) = child.child(j as u32) {
                if sc.kind() == "string_content" {
                    return Some(self.node_text(sc).to_string());
                }
            }
        }
        // Empty string literal ('') has no string_content child.
        Some(String::new())
    }

    /// Reduce a URL (absolute `http://host/path?q` or root-relative `/path?q`) to
    /// its path with a leading slash and no query/fragment. Returns `None` when
    /// the string is not a literal URL/path we should record.
    fn url_to_path(url: &str) -> Option<String> {
        let stripped = if let Some(rest) = url.strip_prefix("http://") {
            Some(rest)
        } else {
            url.strip_prefix("https://")
        };

        let raw_path = if let Some(after_scheme) = stripped {
            // Everything from the first '/' after the host onwards.
            match after_scheme.find('/') {
                Some(idx) => after_scheme[idx..].to_string(),
                None => "/".to_string(),
            }
        } else if url.starts_with('/') {
            url.to_string()
        } else {
            return None;
        };

        // Strip query string and fragment.
        let path = raw_path.split(['?', '#']).next().unwrap_or("/").to_string();
        let path = if path.is_empty() {
            "/".to_string()
        } else {
            path
        };
        Some(path)
    }

    fn http_verb(name: &str) -> Option<HttpMethod> {
        match name.to_ascii_lowercase().as_str() {
            "get" => Some(HttpMethod::Get),
            "post" => Some(HttpMethod::Post),
            "put" => Some(HttpMethod::Put),
            "patch" => Some(HttpMethod::Patch),
            "delete" => Some(HttpMethod::Delete),
            _ => None,
        }
    }

    /// Map an explicit HTTP method string (Guzzle `request('POST', ...)`).
    fn http_method_from_str(s: &str) -> HttpMethod {
        match s.to_ascii_uppercase().as_str() {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "PATCH" => HttpMethod::Patch,
            "DELETE" => HttpMethod::Delete,
            _ => HttpMethod::Any,
        }
    }

    /// Record an outgoing HTTP call if `url` is a literal path/URL.
    fn record_http_call(
        &mut self,
        method: HttpMethod,
        url: &str,
        caller: SymbolId,
        node: tree_sitter::Node,
    ) {
        if let Some(path) = Self::url_to_path(url) {
            self.ir.http_calls.push(HttpCall {
                method,
                path,
                caller,
                file: self.path.clone(),
                line: node.start_position().row as u32 + 1,
            });
        }
    }

    fn handle_function_call(&mut self, node: tree_sitter::Node) {
        let callee_name = node
            .child_by_field_name("function")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        // Top-level calls (plain-script bootstrap code) have no enclosing
        // function/class; attribute them to the synthetic file scope so the
        // callee still counts as used and does not read as dead.
        let caller_id = self
            .current_function
            .or(self.current_class)
            .unwrap_or_else(|| self.get_or_create_file_scope());
        let is_curl_setopt =
            callee_name.rsplit('\\').next().unwrap_or(&callee_name) == "curl_setopt";
        let target = if callee_name.contains("$$") || callee_name == "call_user_func" {
            CallTarget::Dynamic(callee_name)
        } else {
            CallTarget::Unresolved(callee_name)
        };

        self.ir.calls.push(Call {
            caller: caller_id,
            callee: target,
            file: self.path.clone(),
            line: node.start_position().row as u32 + 1,
            col: node.start_position().column as u32,
        });

        // curl: `curl_setopt($ch, CURLOPT_URL, 'http://host/path')`.
        // Method is best-effort GET (CURLOPT_POST / CURLOPT_CUSTOMREQUEST would
        // set it elsewhere; we default to GET).
        if is_curl_setopt {
            if let Some(args) = node.child_by_field_name("arguments") {
                let arg_nodes = self.arg_nodes(args);
                if arg_nodes.len() >= 3 {
                    let is_url_opt = arg_nodes[1]
                        .named_child(0)
                        .map(|n| {
                            self.node_text(n).rsplit('\\').next().unwrap_or("") == "CURLOPT_URL"
                        })
                        .unwrap_or(false);
                    if is_url_opt {
                        if let Some(url) = self.arg_string_literal(arg_nodes[2]) {
                            self.record_http_call(HttpMethod::Get, &url, caller_id, node);
                        }
                    }
                }
            }
        }

        if let Some(args) = node.child_by_field_name("arguments") {
            let child_count = args.child_count();
            for i in 0..child_count {
                if let Some(child) = args.child(i as u32) {
                    self.walk_node(child);
                }
            }
        }
    }

    fn handle_member_call(&mut self, node: tree_sitter::Node) {
        let method_name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let object_name = node
            .child_by_field_name("object")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let method_lc = method_name.to_ascii_lowercase();
        let full_call = if object_name.is_empty() {
            method_name
        } else {
            format!("{}->{}", object_name, method_name)
        };

        // Fall back to the synthetic file scope for top-level `$obj->method()`.
        let caller_id = self
            .current_function
            .or(self.current_class)
            .unwrap_or_else(|| self.get_or_create_file_scope());
        self.ir.calls.push(Call {
            caller: caller_id,
            callee: CallTarget::Unresolved(full_call),
            file: self.path.clone(),
            line: node.start_position().row as u32 + 1,
            col: node.start_position().column as u32,
        });

        // Outgoing HTTP client call via a member call:
        //   * Laravel HTTP facade chain: `Http::withToken(..)->get('http://...')`
        //   * Guzzle verb call:          `$client->post('http://...')`
        //   * Guzzle request call:       `$client->request('POST', 'http://...')`
        // The "URL literal starts with / or http" guard (in url_to_path) keeps
        // unrelated `->get()`/`->post()` calls from being mis-recorded.
        if let Some(args) = node.child_by_field_name("arguments") {
            let arg_nodes = self.arg_nodes(args);
            if method_lc == "request" {
                // First arg = HTTP method string, second arg = URL string.
                if arg_nodes.len() >= 2 {
                    if let (Some(verb), Some(url)) = (
                        self.arg_string_literal(arg_nodes[0]),
                        self.arg_string_literal(arg_nodes[1]),
                    ) {
                        let method = Self::http_method_from_str(&verb);
                        self.record_http_call(method, &url, caller_id, node);
                    }
                }
            } else if let Some(method) = Self::http_verb(&method_lc) {
                if let Some(first) = arg_nodes.first() {
                    if let Some(url) = self.arg_string_literal(*first) {
                        self.record_http_call(method, &url, caller_id, node);
                    }
                }
            }
        }

        if let Some(args) = node.child_by_field_name("arguments") {
            let child_count = args.child_count();
            for i in 0..child_count {
                if let Some(child) = args.child(i as u32) {
                    self.walk_node(child);
                }
            }
        }
    }

    fn handle_scoped_call(&mut self, node: tree_sitter::Node) {
        let method_name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let scope_name = node
            .child_by_field_name("scope")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        // Laravel HTTP facade direct call: `Http::get('http://.../path')`.
        // Match the facade by its last name segment so fully-qualified
        // `\Illuminate\Support\Facades\Http::get(...)` also resolves.
        let is_http_facade = scope_name.rsplit('\\').next().unwrap_or(&scope_name) == "Http";
        let http_method = Self::http_verb(&method_name.to_ascii_lowercase());

        let full_call = if scope_name.is_empty() {
            method_name
        } else {
            format!("{}::{}", scope_name, method_name)
        };

        // Fall back to the synthetic file scope for top-level `Foo::bar()`.
        let caller_id = self
            .current_function
            .or(self.current_class)
            .unwrap_or_else(|| self.get_or_create_file_scope());
        self.ir.calls.push(Call {
            caller: caller_id,
            callee: CallTarget::Unresolved(full_call),
            file: self.path.clone(),
            line: node.start_position().row as u32 + 1,
            col: node.start_position().column as u32,
        });

        if is_http_facade {
            if let Some(method) = http_method {
                if let Some(args) = node.child_by_field_name("arguments") {
                    if let Some(first) = self.arg_nodes(args).first() {
                        if let Some(url) = self.arg_string_literal(*first) {
                            self.record_http_call(method, &url, caller_id, node);
                        }
                    }
                }
            }
        }

        if let Some(args) = node.child_by_field_name("arguments") {
            let child_count = args.child_count();
            for i in 0..child_count {
                if let Some(child) = args.child(i as u32) {
                    self.walk_node(child);
                }
            }
        }
    }
}

fn extract_visibility(node: tree_sitter::Node, source: &str) -> Visibility {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
            if child.kind() == "visibility_modifier" {
                let text = child
                    .utf8_text(source.as_bytes())
                    .unwrap_or("")
                    .to_lowercase();
                return match text.as_str() {
                    "public" => Visibility::Public,
                    "protected" => Visibility::Protected,
                    "private" => Visibility::Private,
                    _ => Visibility::Public,
                };
            }
        }
    }
    Visibility::Public
}

fn check_static(node: tree_sitter::Node, source: &str) -> bool {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
            if child.kind() == "static_modifier" {
                return true;
            }
            // Some grammars use a generic modifier node
            if child.kind() == "static" {
                return true;
            }
            if let Ok(text) = child.utf8_text(source.as_bytes()) {
                if text == "static" {
                    return true;
                }
            }
        }
    }
    false
}

fn count_params(node: tree_sitter::Node) -> u8 {
    if let Some(params) = node.child_by_field_name("parameters") {
        let mut count: u8 = 0;
        for i in 0..params.child_count() {
            if let Some(child) = params.child(i as u32) {
                if child.kind() == "simple_parameter"
                    || child.kind() == "variadic_parameter"
                    || child.kind() == "property_promotion_parameter"
                {
                    count = count.saturating_add(1);
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

/// Normalized hash: comments and whitespace stripped, identifiers replaced with
/// placeholders, so renamed duplicates hash identically.
fn hash_normalized(s: &str) -> u64 {
    let stripped = crate::strip_comments(s, true, true, true);
    let mut normalized = String::with_capacity(stripped.len());
    let chars: Vec<char> = stripped.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        if chars[i] == '$' {
            normalized.push_str("$_");
            i += 1;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            continue;
        }
        if chars[i].is_alphabetic() || chars[i] == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            // Keep PHP keywords and built-in functions, replace user identifiers
            let lower = ident.to_lowercase();
            match lower.as_str() {
                "function" | "class" | "public" | "private" | "protected" | "static" | "return"
                | "if" | "else" | "while" | "for" | "foreach" | "as" | "new" | "echo" | "null"
                | "true" | "false" | "array" | "int" | "string" | "float" | "bool" | "void"
                | "self" | "parent" | "intval" | "strval" | "floatval" | "isset" | "empty"
                | "unset" | "date" | "strtotime" | "implode" | "explode" | "count" | "md5"
                | "sha1" | "eval" | "require" | "include" => {
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
