use std::path::Path;

use anyhow::{Context, Result};

use verum_nucleus::{
    Call, CallTarget, FileId, FileInfo, HttpCall, HttpMethod, Ir, Language, Route, Symbol,
    SymbolId, SymbolKind, Visibility,
};

/// Parse a Rust file into a partial IR.
pub fn parse_file(path: &Path) -> Result<Ir> {
    let source =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::language())
        .map_err(|e| anyhow::anyhow!("Failed to set Rust language: {}", e))?;

    let tree = parser
        .parse(&source, None)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse {}", path.display()))?;

    let mut extractor = RustExtractor {
        source: source.clone(),
        path: path.to_path_buf(),
        next_id: hash_path(path),
        current_module: module_path_for(path),
        current_impl: None,
        current_impl_name: String::new(),
        local_types: std::collections::HashMap::new(),
        field_types: std::collections::HashMap::new(),
        current_function: None,
        in_test_context: false,
        pending_impl_methods: Vec::new(),
        use_aliases: std::collections::HashMap::new(),
        fn_returns: std::collections::HashMap::new(),
        file_scope: None,
        ir: Ir::new(),
    };

    extractor.collect_fn_returns(tree.root_node());
    extractor.walk_node(tree.root_node());
    extractor.record_attribute_refs();

    // Bind methods from impl blocks whose target type is declared later in
    // the file - the walk couldn't see it yet.
    let pending = std::mem::take(&mut extractor.pending_impl_methods);
    if !pending.is_empty() {
        for (method_id, type_name) in pending {
            // `find_symbol_by_name` breaks same-name-in-different-modules
            // ties deterministically (earliest declaration) instead of
            // depending on HashMap iteration order - see its doc comment.
            if let Some(parent_id) = extractor.find_symbol_by_name(&type_name) {
                if let Some(sym) = extractor.ir.symbols.get_mut(&method_id) {
                    if sym.parent.is_none() {
                        sym.parent = Some(parent_id);
                    }
                }
            }
        }
    }

    let line_count = source.lines().count() as u32;
    let size_bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    let file_id = FileId(hash_path(path));
    let symbol_ids: Vec<SymbolId> = extractor.ir.symbols.keys().copied().collect();

    extractor.ir.files.insert(
        path.to_path_buf(),
        FileInfo {
            id: file_id,
            path: path.to_path_buf(),
            language: Language::Rust,
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

struct RustExtractor {
    source: String,
    path: std::path::PathBuf,
    next_id: u64,
    current_module: String,
    current_impl: Option<SymbolId>,
    current_impl_name: String,
    current_function: Option<SymbolId>,
    /// True while walking inside a `#[cfg(test)]` module - every function in
    /// such a module (test cases and their helpers) is test-only and must not
    /// be reported as dead code.
    in_test_context: bool,
    /// Local variable -> type short-name for the function currently being
    /// walked, inferred from `let x: T = ...` annotations and constructor-style
    /// initializers (`let x = T::new(...)`, `vec![...]`, `T { ... }`). Lets method
    /// calls on locals be emitted as `T::method` instead of `x.method`, which
    /// both resolves against in-IR impls and gives downstream passes (chains,
    /// taint) the receiver type.
    local_types: std::collections::HashMap<String, String>,
    /// Struct name -> (field name -> type short-name), from struct definitions
    /// in this file. Types `self.field.method()` calls inside impls.
    field_types: std::collections::HashMap<String, std::collections::HashMap<String, String>>,
    /// Methods whose impl target wasn't declared yet when the impl block was
    /// walked (single forward pass); (method id, base type name), re-bound
    /// after the whole file is mapped.
    pending_impl_methods: Vec<(SymbolId, String)>,
    /// `use` imports in this file: short name -> full path (crate:: stripped).
    /// Lets `frame::parse(x)` after `use crate::net::frame;` emit the exact
    /// module-qualified callee instead of a suffix guess.
    use_aliases: std::collections::HashMap<String, String>,
    /// Function short-name -> return type short-name, pre-collected so a
    /// `let x = connect();` can type `x` from `connect`'s return regardless of
    /// definition order. Feeds receiver-typed method resolution.
    fn_returns: std::collections::HashMap<String, String>,
    /// File-level pseudo symbol owning calls/references made outside any fn -
    /// `static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_waker, ...)` and
    /// other `const`/`static` initializers. Without it those references are
    /// dropped and their targets read as dead.
    file_scope: Option<SymbolId>,
    ir: Ir,
}

impl RustExtractor {
    fn alloc_id(&mut self) -> SymbolId {
        self.next_id += 1;
        SymbolId(self.next_id)
    }

    fn fully_qualified(&self, name: &str) -> String {
        if self.current_module.is_empty() {
            name.to_string()
        } else {
            format!("{}::{}", self.current_module, name)
        }
    }

    fn node_text<'a>(&'a self, node: tree_sitter::Node<'a>) -> &'a str {
        node.utf8_text(self.source.as_bytes()).unwrap_or("")
    }

    /// Find a symbol by bare name, deterministically. `ir.symbols` is a
    /// HashMap, so picking the first match from its iteration order would
    /// let a same-name collision (two types/functions sharing a bare name in
    /// different modules) resolve to whichever symbol the process's random
    /// hash seed happened to iterate first - stable within one run, but
    /// different on the next. Break ties by earliest declaration (line, then
    /// id, both content-derived) so the same source always resolves the same
    /// symbol.
    fn find_symbol_by_name(&self, name: &str) -> Option<SymbolId> {
        self.ir
            .symbols
            .iter()
            .filter(|(_, s)| s.name == name)
            .min_by(|a, b| {
                a.1.line_start
                    .cmp(&b.1.line_start)
                    .then(a.0 .0.cmp(&b.0 .0))
            })
            .map(|(id, _)| *id)
    }

    fn hash_node(&self, node: tree_sitter::Node) -> (u64, u64) {
        let text = &self.source[node.start_byte()..node.end_byte()];
        (hash_string(text), hash_normalized(text))
    }

    /// Concatenate the text of `attribute_item` nodes immediately preceding
    /// `node`. In tree-sitter-rust, outer attributes (`#[...]`) are emitted as
    /// sibling nodes before the item they annotate, so we walk backwards over
    /// any attributes (skipping interspersed comments) until we hit real code.
    fn preceding_attributes(&self, node: tree_sitter::Node) -> String {
        let mut collected = String::new();
        let mut cursor = node.prev_sibling();
        while let Some(sib) = cursor {
            match sib.kind() {
                "attribute_item" => {
                    collected.push_str(self.node_text(sib));
                    collected.push('\n');
                }
                "line_comment" | "block_comment" => {}
                _ => break,
            }
            cursor = sib.prev_sibling();
        }
        collected
    }

    /// True if `node` carries a test-runner attribute (`#[test]`,
    /// `#[tokio::test]`, `#[bench]`, `#[rstest]`, `#[test_case(..)]`, etc.).
    /// Word-boundary matching, so `#[cfg(feature = "latest")]` and
    /// `#[cfg(not(test))]` don't count.
    fn has_test_attribute(&self, node: tree_sitter::Node) -> bool {
        let attrs = normalize_attrs(&self.preceding_attributes(node));
        has_affirmative_word(&attrs, "test")
            || has_affirmative_word(&attrs, "bench")
            || attrs.contains("test_case")
            || attrs.contains("rstest")
            || attrs.contains("proptest")
            || attrs.contains("quickcheck")
    }

    /// True if `node` is exported across a boundary Verum cannot see: FFI,
    /// wasm, Python bindings, proc-macros, or a runtime-provided `main`.
    ///
    /// These are invoked by a linker, host runtime or the compiler rather than
    /// by name from Rust, so they have no in-crate caller and would otherwise
    /// read as dead.
    fn has_export_attribute(&self, node: tree_sitter::Node) -> bool {
        let attrs = self.preceding_attributes(node);
        EXPORT_ATTRIBUTES.iter().any(|a| attrs.contains(a))
    }

    /// True if `node` (a `mod_item`) is gated behind `#[cfg(test)]`.
    /// `#[cfg(not(test))]` gates production-only code and must not match -
    /// treating it as a test module would silently disable dead-code
    /// analysis for everything inside it.
    fn is_cfg_test_module(&self, node: tree_sitter::Node) -> bool {
        let attrs = normalize_attrs(&self.preceding_attributes(node));
        attrs.contains("cfg(") && has_affirmative_word(&attrs, "test")
    }

    /// `#[allow(dead_code)]` / `#[expect(dead_code)]` is the author saying
    /// "intentionally uncalled" - reporting the item anyway is noise they
    /// already opted out of.
    fn has_allow_dead_code(&self, node: tree_sitter::Node) -> bool {
        let attrs = normalize_attrs(&self.preceding_attributes(node));
        attrs.contains("allow(dead_code)") || attrs.contains("expect(dead_code)")
    }

    /// Item gated to a platform/target we may not be analysing (`#[cfg(windows)]`,
    /// `#[cfg(target_os = "...")]`). Its callers live in the other-platform build
    /// Verum isn't looking at, so "uncalled here" doesn't mean dead - e.g. the
    /// Windows `ctrl_*` console handlers on a Linux checkout.
    fn has_platform_cfg(&self, node: tree_sitter::Node) -> bool {
        let attrs = normalize_attrs(&self.preceding_attributes(node));
        attrs.contains("cfg(") && PLATFORM_CFG_TOKENS.iter().any(|t| attrs.contains(t))
    }

    fn walk_node(&mut self, node: tree_sitter::Node) {
        match node.kind() {
            "mod_item" => self.handle_mod(node),
            "use_declaration" => self.handle_use(node),
            "struct_item" => self.handle_struct(node),
            "enum_item" => self.handle_enum(node),
            "trait_item" => self.handle_trait(node),
            "impl_item" => self.handle_impl(node),
            "function_item" => self.handle_function(node),
            "function_signature_item" => self.handle_function_signature(node),
            "let_declaration" => self.handle_let(node),
            "call_expression" => self.handle_call(node),
            "struct_expression" => self.handle_struct_expression(node),
            "macro_invocation" => self.handle_macro_invocation(node),
            "macro_definition" => self.handle_macro_definition(node),
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

    fn handle_mod(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let prev_module = self.current_module.clone();
        if self.current_module.is_empty() {
            self.current_module = name;
        } else {
            self.current_module = format!("{}::{}", self.current_module, name);
        }

        // A `#[cfg(test)]` module (or one conventionally named `tests`) marks
        // everything inside as test-only. Inherit an outer test context so
        // nested modules stay test-only too.
        let prev_test_context = self.in_test_context;
        if self.is_cfg_test_module(node) || self.current_module.rsplit("::").next() == Some("tests")
        {
            self.in_test_context = true;
        }

        // Walk the body if present (inline modules)
        if let Some(body) = node.child_by_field_name("body") {
            let child_count = body.child_count();
            for i in 0..child_count {
                if let Some(child) = body.child(i) {
                    self.walk_node(child);
                }
            }
        }

        self.current_module = prev_module;
        self.in_test_context = prev_test_context;
    }

    /// Record `use` imports so later calls through the imported name can be
    /// emitted fully qualified. Text-parsed: grouped imports (`use a::{b, c as
    /// d}`) expand recursively; globs and underscore imports are skipped.
    fn handle_use(&mut self, node: tree_sitter::Node) {
        let text = self.node_text(node).to_string();
        let Some(pos) = text.find("use ") else { return };
        let spec = text[pos + 4..]
            .trim()
            .trim_end_matches(';')
            .trim()
            .to_string();
        let mut pairs = Vec::new();
        expand_use(&spec, "", &mut pairs);
        for (alias, full) in pairs {
            let full = full.strip_prefix("crate::").unwrap_or(&full).to_string();
            self.use_aliases.insert(alias, full);
        }
    }

    /// Expand a call path to match the module-qualified names symbols carry:
    /// strip `crate::`, resolve `self::`/`super::` against the current module,
    /// and route the first segment through the file's `use` imports.
    fn qualify_call_path(&self, raw: &str) -> String {
        if let Some(rest) = raw.strip_prefix("crate::") {
            return rest.to_string();
        }
        if let Some(rest) = raw.strip_prefix("self::") {
            return if self.current_module.is_empty() {
                rest.to_string()
            } else {
                format!("{}::{}", self.current_module, rest)
            };
        }
        if let Some(rest) = raw.strip_prefix("super::") {
            let parent = self
                .current_module
                .rsplit_once("::")
                .map(|(p, _)| p)
                .unwrap_or("");
            return if parent.is_empty() {
                rest.to_string()
            } else {
                format!("{parent}::{rest}")
            };
        }
        let first = raw.split("::").next().unwrap_or("");
        if let Some(full) = self.use_aliases.get(first) {
            return format!("{}{}", full, &raw[first.len()..]);
        }
        raw.to_string()
    }

    fn handle_struct(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();
        let fq = self.fully_qualified(&name);
        let visibility = extract_visibility(node, &self.source);

        // Record field name -> type for receiver-type inference on
        // `self.field.method()` calls inside this struct's impls.
        if let Some(body) = node.child_by_field_name("body") {
            let mut fields = std::collections::HashMap::new();
            let mut cursor = body.walk();
            for field in body.children(&mut cursor) {
                if field.kind() != "field_declaration" {
                    continue;
                }
                let (Some(fname), Some(ftype)) = (
                    field.child_by_field_name("name"),
                    field.child_by_field_name("type"),
                ) else {
                    continue;
                };
                if let Some(short) = Self::type_short(self.node_text(ftype)) {
                    fields.insert(self.node_text(fname).to_string(), short);
                }
            }
            if !fields.is_empty() {
                self.field_types.insert(name.clone(), fields);
            }
        }

        let symbol = Symbol {
            id,
            name,
            fully_qualified: fq,
            kind: SymbolKind::Class, // Reuse Class kind for structs
            visibility,
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: Language::Rust,
            parent: None,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count: 0,
            is_entry_point: self.has_allow_dead_code(node),
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);
    }

    fn handle_enum(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();
        let fq = self.fully_qualified(&name);
        let visibility = extract_visibility(node, &self.source);

        let symbol = Symbol {
            id,
            name,
            fully_qualified: fq,
            kind: SymbolKind::Enum,
            visibility,
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: Language::Rust,
            parent: None,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count: 0,
            is_entry_point: self.has_allow_dead_code(node),
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
        let visibility = extract_visibility(node, &self.source);

        let symbol = Symbol {
            id,
            name,
            fully_qualified: fq,
            kind: SymbolKind::Trait,
            visibility,
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: Language::Rust,
            parent: None,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count: 0,
            is_entry_point: false,
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);

        if let Some(body) = node.child_by_field_name("body") {
            let prev_impl = self.current_impl.take();
            let prev_impl_name = self.current_impl_name.clone();
            self.current_impl = Some(id);
            self.current_impl_name = self.ir.symbols.get(&id).unwrap().fully_qualified.clone();

            let child_count = body.child_count();
            for i in 0..child_count {
                if let Some(child) = body.child(i) {
                    self.walk_node(child);
                }
            }

            self.current_impl = prev_impl;
            self.current_impl_name = prev_impl_name;
        }
    }

    fn handle_impl(&mut self, node: tree_sitter::Node) {
        // `impl Foo<T>` / `impl<'a> Foo<'a>`: match on the base name - the
        // generic arguments never appear in the struct's symbol name.
        let type_name = node
            .child_by_field_name("type")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();
        let type_name = type_name
            .split('<')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();

        let trait_name = node
            .child_by_field_name("trait")
            .map(|n| self.node_text(n).to_string());

        let impl_target_id = self.find_symbol_by_name(&type_name);

        let prev_impl = self.current_impl.take();
        let prev_impl_name = self.current_impl_name.clone();
        self.current_impl = impl_target_id;

        if let Some(ref trait_n) = trait_name {
            self.current_impl_name = format!("<{} as {}>", type_name, trait_n);
        } else {
            self.current_impl_name = type_name;
        }

        if let Some(body) = node.child_by_field_name("body") {
            let child_count = body.child_count();
            for i in 0..child_count {
                if let Some(child) = body.child(i) {
                    self.walk_node(child);
                }
            }
        }

        self.current_impl = prev_impl;
        self.current_impl_name = prev_impl_name;
    }

    fn handle_function(&mut self, node: tree_sitter::Node) {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();
        let visibility = extract_visibility(node, &self.source);
        let param_count = count_params(node);

        // Structural shape of the body; 0 (= "no flow hash") for bodies too
        // small to be meaningful duplicates, and for test code - tests that
        // exercise one helper with different inputs are structurally identical
        // by convention, not by copying.
        let in_test = self.in_test_context || self.has_test_attribute(node);
        let flow_hash = if in_test {
            0
        } else {
            node.child_by_field_name("body")
                .map(structural_hash)
                .filter(|(_, nodes)| *nodes >= MIN_FLOW_NODES)
                .map(|(h, _)| h)
                .unwrap_or(0)
        };

        // Entry-point detection (kept alive for dead-code analysis):
        //  - test cases / benches and anything inside a `#[cfg(test)]` module
        //  - `main` (binary / example entry point)
        //  - trait-impl methods (e.g. `Debug::fmt`) which are dispatched via the
        //    trait rather than called by name, so they look "uncalled".
        //  - trait *provided* methods (a body inside a `trait` block, e.g.
        //    `AsyncReadExt::read_to_end`) - API/dispatch surface implemented or
        //    called by downstream code, never by name in-crate.
        let is_trait_impl_method =
            self.current_impl_name.starts_with('<') && self.current_impl_name.contains(" as ");
        let is_trait_provided_method = self
            .current_impl
            .and_then(|id| self.ir.symbols.get(&id))
            .is_some_and(|s| matches!(s.kind, SymbolKind::Trait));
        let is_entry_point = self.in_test_context
            || name == "main"
            || self.has_test_attribute(node)
            || self.has_export_attribute(node)
            || self.has_allow_dead_code(node)
            || self.has_platform_cfg(node)
            || is_trait_impl_method
            || is_trait_provided_method;

        let (kind, fq, parent) =
            if self.current_impl.is_some() || !self.current_impl_name.is_empty() {
                let has_self = has_self_param(node, &self.source);
                let kind = if has_self {
                    SymbolKind::Method
                } else {
                    SymbolKind::StaticMethod
                };
                let fq = if self.current_impl_name.is_empty() {
                    self.fully_qualified(&name)
                } else if self.current_module.is_empty() {
                    format!("{}::{}", self.current_impl_name, name)
                } else {
                    format!(
                        "{}::{}::{}",
                        self.current_module, self.current_impl_name, name
                    )
                };
                (kind, fq, self.current_impl)
            } else {
                let fq = self.fully_qualified(&name);
                (SymbolKind::Function, fq, None)
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
            language: Language::Rust,
            parent,
            hash,
            normalized_hash,
            flow_hash,
            param_count,
            is_entry_point,
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);

        // Web-framework attribute routes on this function:
        // `#[get("/path")]`, `#[post("/path")]`, `#[route("/p", method="GET")]`
        // (actix-web / axum / rocket). The function IS the handler, so the
        // route's controller is this symbol.
        for attr_line in self.preceding_attributes(node).lines() {
            if let Some((method, path)) = parse_route_attribute(attr_line) {
                self.ir.routes.push(Route {
                    method,
                    path,
                    controller: Some(id),
                    middleware: Vec::new(),
                    file: self.path.clone(),
                    line: node.start_position().row as u32 + 1,
                });
            }
        }

        if parent.is_none() && !self.current_impl_name.is_empty() {
            let base = self
                .current_impl_name
                .strip_prefix('<')
                .and_then(|s| s.split(" as ").next())
                .unwrap_or(&self.current_impl_name)
                .to_string();
            self.pending_impl_methods.push((id, base));
        }

        let prev_func = self.current_function.take();
        self.current_function = Some(id);
        let prev_locals = std::mem::take(&mut self.local_types);

        if let Some(body) = node.child_by_field_name("body") {
            let child_count = body.child_count();
            for i in 0..child_count {
                if let Some(child) = body.child(i) {
                    self.walk_node(child);
                }
            }
        }

        self.local_types = prev_locals;
        self.current_function = prev_func;
    }

    fn handle_function_signature(&mut self, node: tree_sitter::Node) {
        // Trait method signatures (no body)
        let name = node
            .child_by_field_name("name")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let (hash, normalized_hash) = self.hash_node(node);
        let id = self.alloc_id();
        let visibility = extract_visibility(node, &self.source);
        let param_count = count_params(node);

        let has_self = has_self_param(node, &self.source);
        let kind = if has_self {
            SymbolKind::Method
        } else {
            SymbolKind::StaticMethod
        };

        let fq = if self.current_impl_name.is_empty() {
            self.fully_qualified(&name)
        } else if self.current_module.is_empty() {
            format!("{}::{}", self.current_impl_name, name)
        } else {
            format!(
                "{}::{}::{}",
                self.current_module, self.current_impl_name, name
            )
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
            language: Language::Rust,
            parent: self.current_impl,
            hash,
            normalized_hash,
            flow_hash: normalized_hash,
            param_count,
            is_entry_point: false,
            doc_comment: None,
        };

        self.ir.symbols.insert(id, symbol);
    }

    /// Reduce a type expression to its short name: `&mut Vec<Option<u8>>` ->
    /// `Vec`, `std::collections::BTreeMap<K, V>` -> `BTreeMap`. Returns None
    /// for non-nominal types (slices, tuples, fn pointers, generics).
    fn type_short(text: &str) -> Option<String> {
        let t = text
            .trim_start_matches('&')
            .trim_start_matches("mut ")
            .trim_start();
        let t = t.split('<').next().unwrap_or(t).trim();
        let t = t.rsplit("::").next().unwrap_or(t).trim();
        (!t.is_empty()
            && t.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .then(|| t.to_string())
    }

    /// Infer the type short-name an initializer expression produces.
    /// Handles constructor-style associated calls (`T::new(...)` - assumed to
    /// return `Self`, the overwhelmingly common convention), `vec![...]`, and
    /// struct literals, unwrapping `?`, `.await`, `&` and parentheses.
    /// Pre-pass: map each function's short name to its declared return type, so
    /// `let x = f()` can type `x` even when `f` is defined later in the file.
    /// First definition wins on name collision (deterministic, position-sorted
    /// enough for this heuristic).
    fn collect_fn_returns(&mut self, node: tree_sitter::Node) {
        if node.kind() == "function_item" {
            if let (Some(name), Some(ret)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("return_type"),
            ) {
                if let Some(ty) = Self::type_short(self.node_text(ret)) {
                    self.fn_returns
                        .entry(self.node_text(name).to_string())
                        .or_insert(ty);
                }
            }
        }
        let n = node.child_count();
        for i in 0..n {
            if let Some(c) = node.child(i) {
                self.collect_fn_returns(c);
            }
        }
    }

    fn infer_expr_type(&self, node: tree_sitter::Node) -> Option<String> {
        let mut expr = node;
        while matches!(
            expr.kind(),
            "try_expression"
                | "await_expression"
                | "reference_expression"
                | "parenthesized_expression"
                | "unary_expression"
        ) {
            expr = expr.named_child(0)?;
        }
        match expr.kind() {
            "call_expression" => {
                let func = expr.child_by_field_name("function")?;
                // Bare `f()` -> f's declared return type (from the pre-pass).
                if func.kind() == "identifier" {
                    return self.fn_returns.get(self.node_text(func)).cloned();
                }
                let text = match func.kind() {
                    "scoped_identifier" => self.node_text(func),
                    "generic_function" => self.node_text(func.child_by_field_name("function")?),
                    _ => return None,
                };
                // A bare-name path (`make::<T>()` had function=identifier, handled
                // above); `path::Type::assoc()` -> the segment before the final
                // `::`, the constructor-returns-Self heuristic.
                let (receiver, _assoc) = text.rsplit_once("::")?;
                Self::type_short(receiver)
            }
            "macro_invocation" => {
                let name = expr.child_by_field_name("macro")?;
                (self.node_text(name) == "vec").then(|| "Vec".to_string())
            }
            "struct_expression" => {
                let name = expr.child_by_field_name("name")?;
                Self::type_short(self.node_text(name))
            }
            _ => None,
        }
    }

    /// Record a local binding's type, then walk the initializer for calls.
    fn handle_let(&mut self, node: tree_sitter::Node) {
        let var = node
            .child_by_field_name("pattern")
            .map(|p| match p.kind() {
                "mut_pattern" => p.named_child(0).unwrap_or(p),
                _ => p,
            })
            .filter(|p| p.kind() == "identifier")
            .map(|p| self.node_text(p).to_string());

        if let Some(var) = var {
            let annotated = node
                .child_by_field_name("type")
                .and_then(|t| Self::type_short(self.node_text(t)));
            let inferred = annotated.or_else(|| {
                node.child_by_field_name("value")
                    .and_then(|v| self.infer_expr_type(v))
            });
            if let Some(ty) = inferred {
                self.local_types.insert(var, ty);
            }
        }

        // Still walk children so calls in the initializer are recorded.
        let child_count = node.child_count();
        for i in 0..child_count {
            if let Some(child) = node.child(i) {
                self.walk_node(child);
            }
        }
    }

    /// Resolve a method-call receiver expression to a type short-name when a
    /// local binding or struct field tells us one.
    fn receiver_type(&self, object: &str) -> Option<String> {
        if let Some(t) = self.local_types.get(object) {
            return Some(t.clone());
        }
        // `self.field` -> field type on the impl'd struct. current_impl_name is
        // `Type` or `<Type as Trait>`.
        let field = object.strip_prefix("self.")?;
        if field.contains(['.', '(', '[']) {
            return None;
        }
        let impl_type = self
            .current_impl_name
            .strip_prefix('<')
            .and_then(|s| s.split(" as ").next())
            .unwrap_or(&self.current_impl_name);
        self.field_types.get(impl_type)?.get(field).cloned()
    }

    /// Functions referenced only from an attribute string - serde's
    /// `#[serde(serialize_with = "path")]`, `deserialize_with`, `default`,
    /// `skip_serializing_if`, and getter/setter hooks. They're never a call in
    /// source, so without an edge the referenced fn reads as dead. Scanned from
    /// raw text: attribute internals aren't reliably structured in tree-sitter.
    fn record_attribute_refs(&mut self) {
        const FN_ATTR_KEYS: &[&str] = &[
            "serialize_with",
            "deserialize_with",
            "default",
            "getter",
            "setter",
            "skip_serializing_if",
        ];
        let mut refs: Vec<String> = Vec::new();
        for key in FN_ATTR_KEYS {
            let mut from = 0;
            while let Some(pos) = self.source[from..].find(key) {
                let after = from + pos + key.len();
                from = after;
                // `key = "path"` (allowing whitespace around `=`).
                let rest = self.source[after..].trim_start();
                let Some(rest) = rest.strip_prefix('=') else {
                    continue;
                };
                let rest = rest.trim_start();
                let Some(rest) = rest.strip_prefix('"') else {
                    continue;
                };
                if let Some(end) = rest.find('"') {
                    let path = &rest[..end];
                    if path
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_alphabetic() || c == '_')
                    {
                        refs.push(path.to_string());
                    }
                }
            }
        }
        if refs.is_empty() {
            return;
        }
        let caller = self.get_or_create_file_scope();
        for path in refs {
            let name = self.qualify_call_path(&path);
            self.ir.calls.push(Call {
                caller,
                callee: CallTarget::Unresolved(name),
                file: self.path.clone(),
                line: 1,
                col: 0,
            });
        }
    }

    /// Pseudo-symbol standing in for module-level (`const`/`static`) scope, so
    /// references made outside any function still get a caller and their
    /// targets stay reachable. Created lazily, once per file.
    fn get_or_create_file_scope(&mut self) -> SymbolId {
        if let Some(id) = self.file_scope {
            return id;
        }
        let id = self.alloc_id();
        let name = "<file>".to_string();
        self.ir.symbols.insert(
            id,
            Symbol {
                id,
                name: name.clone(),
                fully_qualified: format!("{}::<file>", self.current_module),
                kind: SymbolKind::Function,
                visibility: Visibility::Private,
                file: self.path.clone(),
                line_start: 1,
                line_end: 1,
                col_start: 0,
                col_end: 0,
                language: Language::Rust,
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

    /// Detect axum/actix builder routes and reqwest/hyper HTTP-client calls on
    /// a call expression, pushing `Route`/`HttpCall` records. Runs alongside
    /// normal call-edge recording; never suppresses it.
    fn handle_web_call(
        &mut self,
        node: tree_sitter::Node,
        func_node: tree_sitter::Node,
        caller_id: SymbolId,
    ) {
        let Some(args) = node.child_by_field_name("arguments") else {
            return;
        };
        let line = node.start_position().row as u32 + 1;

        match func_node.kind() {
            "field_expression" => {
                let method_name = func_node
                    .child_by_field_name("field")
                    .map(|n| self.node_text(n).to_string())
                    .unwrap_or_default();
                let object = func_node
                    .child_by_field_name("value")
                    .map(|n| self.node_text(n).to_string())
                    .unwrap_or_default();

                // `.route("/path", get(handler))` builder route.
                if method_name == "route" {
                    self.try_builder_route(args, line);
                    return;
                }

                // `client.get("/url")` / `Client::new().post("/url")`.
                if let Some(hm) = http_method_from_verb(&method_name) {
                    if looks_like_http_client(&object) {
                        self.record_http_call(args, hm, caller_id, line);
                    }
                }
            }
            "scoped_identifier" => {
                // `reqwest::get("/url")`.
                let text = self.node_text(func_node);
                if let Some((recv, method)) = text.rsplit_once("::") {
                    if let Some(hm) = http_method_from_verb(method) {
                        if looks_like_http_client(recv) {
                            self.record_http_call(args, hm, caller_id, line);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Push an `HttpCall` if the first argument is a string-literal URL that
    /// looks like a request target (starts with `/` or `http`). The literal
    /// guard keeps `map.get("key")` from being mistaken for a request.
    fn record_http_call(
        &mut self,
        args: tree_sitter::Node,
        method: HttpMethod,
        caller_id: SymbolId,
        line: u32,
    ) {
        let Some(url) = self.first_arg_string(args) else {
            return;
        };
        if !(url.starts_with('/') || url.starts_with("http")) {
            return;
        }
        self.ir.http_calls.push(HttpCall {
            method,
            path: url_to_path(&url),
            caller: caller_id,
            file: self.path.clone(),
            line,
        });
    }

    /// Parse `.route("/path", get(handler))`: path from the first string-literal
    /// arg, method from the `get(...)`/`post(...)` wrapper, controller resolved
    /// from the handler ident when it names an in-file symbol.
    fn try_builder_route(&mut self, args: tree_sitter::Node, line: u32) {
        let mut cursor = args.walk();
        let named: Vec<tree_sitter::Node> = args.named_children(&mut cursor).collect();

        let Some(path_node) = named.first() else {
            return;
        };
        if !matches!(path_node.kind(), "string_literal" | "raw_string_literal") {
            return;
        }
        let path = self.string_value(*path_node);

        let Some(method_node) = named.get(1) else {
            return;
        };
        if method_node.kind() != "call_expression" {
            return;
        }
        let Some(mfunc) = method_node.child_by_field_name("function") else {
            return;
        };
        let verb = match mfunc.kind() {
            "identifier" => self.node_text(mfunc).to_string(),
            "scoped_identifier" => self
                .node_text(mfunc)
                .rsplit("::")
                .next()
                .unwrap_or_default()
                .to_string(),
            _ => return,
        };
        let Some(method) = http_method_from_verb(&verb) else {
            return;
        };

        // Try to resolve the handler ident (first arg of the wrapper) to a
        // symbol already mapped in this file; otherwise leave it None.
        let controller = method_node
            .child_by_field_name("arguments")
            .and_then(|a| {
                let mut c = a.walk();
                let first = a.named_children(&mut c).next();
                first
            })
            .filter(|n| matches!(n.kind(), "identifier" | "scoped_identifier"))
            .map(|n| self.node_text(n).to_string())
            .and_then(|name| self.resolve_symbol_by_name(&name));

        self.ir.routes.push(Route {
            method,
            path,
            controller,
            middleware: Vec::new(),
            file: self.path.clone(),
            line,
        });
    }

    /// First argument of a call, when it is a string literal - its unquoted
    /// value. Returns None if the first argument is anything else.
    fn first_arg_string(&self, args: tree_sitter::Node) -> Option<String> {
        let mut cursor = args.walk();
        let first = args.named_children(&mut cursor).next()?;
        matches!(first.kind(), "string_literal" | "raw_string_literal")
            .then(|| self.string_value(first))
    }

    /// Content of a string-literal node with its surrounding quotes stripped.
    fn string_value(&self, node: tree_sitter::Node) -> String {
        let text = self.node_text(node);
        match (text.find('"'), text.rfind('"')) {
            (Some(a), Some(b)) if b > a => text[a + 1..b].to_string(),
            _ => text.to_string(),
        }
    }

    /// Find an in-file symbol by (possibly qualified) name, matching on the
    /// final path segment.
    fn resolve_symbol_by_name(&self, name: &str) -> Option<SymbolId> {
        let short = name.rsplit("::").next().unwrap_or(name);
        self.find_symbol_by_name(short)
    }

    fn handle_call(&mut self, node: tree_sitter::Node) {
        let func_node = match node.child_by_field_name("function") {
            Some(n) => n,
            None => return,
        };

        let caller_id = self
            .current_function
            .or(self.current_impl)
            .unwrap_or_else(|| self.get_or_create_file_scope());

        // Builder-style routes (`.route("/p", get(handler))`) and HTTP-client
        // calls (`reqwest::get("/url")`, `client.post("/url")`) are recorded
        // for cross-language linking, in addition to the normal call edge below.
        self.handle_web_call(node, func_node, caller_id);

        let target = if func_node.kind() == "field_expression" {
            // Method call: x.foo()
            let method_name = func_node
                .child_by_field_name("field")
                .map(|n| self.node_text(n).to_string())
                .unwrap_or_default();
            let object = func_node
                .child_by_field_name("value")
                .map(|n| self.node_text(n).to_string())
                .unwrap_or_default();
            if object.is_empty() {
                CallTarget::Unresolved(method_name)
            } else if let Some(ty) = self.receiver_type(&object) {
                // Receiver type is known: emit `Type::method` so the resolver
                // can bind it to an in-IR impl and downstream passes can
                // classify the receiver (e.g. Vec::truncate is not a
                // destructive database/file operation).
                CallTarget::Unresolved(format!("{}::{}", ty, method_name))
            } else {
                CallTarget::Unresolved(format!("{}.{}", object, method_name))
            }
        } else if func_node.kind() == "scoped_identifier" {
            // Path call: Foo::bar() or module::func()
            let text = self.node_text(func_node).to_string();
            CallTarget::Unresolved(self.qualify_call_path(&text))
        } else if func_node.kind() == "identifier" {
            // Simple function call: foo()
            let text = self.node_text(func_node).to_string();
            CallTarget::Unresolved(self.qualify_call_path(&text))
        } else if func_node.kind() == "generic_function" {
            // Generic call: foo::<T>()
            let name_node = func_node.child_by_field_name("function");
            let text = name_node
                .map(|n| self.node_text(n).to_string())
                .unwrap_or_else(|| self.node_text(func_node).to_string());
            CallTarget::Unresolved(self.qualify_call_path(&text))
        } else {
            // Dynamic or complex expression call
            let text = self.node_text(func_node).to_string();
            CallTarget::Dynamic(text)
        };

        self.ir.calls.push(Call {
            caller: caller_id,
            callee: target,
            file: self.path.clone(),
            line: node.start_position().row as u32 + 1,
            col: node.start_position().column as u32,
        });

        // Bare function references passed as arguments (`.map(parse_line)`,
        // `sort_by_key(hash_of)`) never appear as call_expression nodes, so
        // without an edge here the referenced function reads as dead. A plain
        // variable that shares a function's name keeps that function alive too
        // - the conservative direction for liveness.
        if let Some(args) = node.child_by_field_name("arguments") {
            let n = args.child_count();
            for i in 0..n {
                let Some(arg) = args.child(i) else { continue };
                if matches!(arg.kind(), "identifier" | "scoped_identifier") {
                    self.ir.calls.push(Call {
                        caller: caller_id,
                        callee: CallTarget::Unresolved(self.node_text(arg).to_string()),
                        file: self.path.clone(),
                        line: arg.start_position().row as u32 + 1,
                        col: arg.start_position().column as u32,
                    });
                }
            }
        }

        let child_count = node.child_count();
        for i in 0..child_count {
            if let Some(child) = node.child(i) {
                self.walk_node(child);
            }
        }
    }

    /// Record function references used as struct-literal field values - the
    /// manual vtable / jump-table idiom (`&Vtable { poll, schedule: sched_fn }`).
    /// These aren't call expressions, so without an edge the referenced fns read
    /// as dead. A field value that's just a local variable keeps a same-named fn
    /// alive too - the conservative direction for liveness.
    fn handle_struct_expression(&mut self, node: tree_sitter::Node) {
        let caller_id = self
            .current_function
            .or(self.current_impl)
            .unwrap_or_else(|| self.get_or_create_file_scope());
        if let Some(body) = node.child_by_field_name("body") {
            let n = body.child_count();
            for i in 0..n {
                let Some(field) = body.child(i) else { continue };
                // `{ poll }` shorthand, or `{ poll: poll::<T, S> }` explicit.
                let value = match field.kind() {
                    "shorthand_field_initializer" => field.child(0),
                    "field_initializer" => field.child_by_field_name("value"),
                    _ => None,
                };
                let Some(value) = value else { continue };
                // Path head of the value, up to any turbofish/call/generics -
                // `poll::<T, S>` -> `poll`, `sched_fn` -> `sched_fn`. Handles the
                // grammar variants (identifier / scoped / generic_function)
                // uniformly, and literals/`&expr` fall out (empty head).
                let text = self.node_text(value);
                let head: String = text
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
                    .collect();
                let head = head.trim_end_matches(':');
                if head
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphabetic() || c == '_')
                {
                    let name = self.qualify_call_path(head);
                    self.ir.calls.push(Call {
                        caller: caller_id,
                        callee: CallTarget::Unresolved(name),
                        file: self.path.clone(),
                        line: value.start_position().row as u32 + 1,
                        col: value.start_position().column as u32,
                    });
                }
            }
        }

        // Recurse for nested calls inside field values (`{ x: foo() }`).
        let child_count = node.child_count();
        for i in 0..child_count {
            if let Some(child) = node.child(i) {
                self.walk_node(child);
            }
        }
    }

    fn handle_macro_invocation(&mut self, node: tree_sitter::Node) {
        let macro_name = node
            .child_by_field_name("macro")
            .map(|n| self.node_text(n).to_string())
            .unwrap_or_default();

        let caller_id = self
            .current_function
            .or(self.current_impl)
            .unwrap_or_else(|| self.get_or_create_file_scope());
        self.ir.calls.push(Call {
            caller: caller_id,
            callee: CallTarget::Unresolved(format!("{}!", macro_name)),
            file: self.path.clone(),
            line: node.start_position().row as u32 + 1,
            col: node.start_position().column as u32,
        });

        let child_count = node.child_count();
        for i in 0..child_count {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    // Arguments are an unparsed token stream, not expressions.
                    "token_tree" => self.scan_token_tree(child),
                    // The macro's own name, already recorded above.
                    "identifier" | "scoped_identifier" => {}
                    _ => self.walk_node(child),
                }
            }
        }
    }

    /// Extract calls from the raw token stream of a macro invocation.
    ///
    /// tree-sitter does not parse macro arguments into expressions - they stay a
    /// flat `token_tree`, so a call written inside `println!`, `assert_eq!` or
    /// `vec!` never produces a `call_expression` node. Without this the callee
    /// looks unreferenced and dead-code analysis reports a false positive, which
    /// hits test helpers hardest since `assert*!` is where tests call things.
    ///
    /// Recognises `foo(..)`, `a::b::foo(..)`, `x.foo(..)` and nested `bar!(..)`
    /// by matching an identifier immediately followed by a `(`-delimited group.
    fn scan_token_tree(&mut self, node: tree_sitter::Node) {
        let caller_id = self
            .current_function
            .or(self.current_impl)
            .unwrap_or_else(|| self.get_or_create_file_scope());

        let children: Vec<tree_sitter::Node> = (0..node.child_count())
            .filter_map(|i| node.child(i))
            .collect();

        for (i, child) in children.iter().enumerate() {
            // Nested delimiter groups: `outer(inner(x))`, `vec![f()]`.
            if child.kind() == "token_tree" {
                self.scan_token_tree(*child);
                continue;
            }

            if child.kind() != "identifier" {
                continue;
            }

            let name = self.node_text(*child).to_string();
            // Keywords tokenise as bare words here; `if (x)` is not a call.
            if NON_CALLABLE_KEYWORDS.contains(&name.as_str()) {
                continue;
            }

            let next = match children.get(i + 1) {
                Some(n) => n,
                None => continue,
            };

            // Nested macro: `format!(..)` inside `println!(..)`.
            if next.kind() == "!" {
                if let Some(args) = children.get(i + 2) {
                    if is_paren_group(args) || args.kind() == "token_tree" {
                        self.ir.calls.push(Call {
                            caller: caller_id,
                            callee: CallTarget::Unresolved(format!("{}!", name)),
                            file: self.path.clone(),
                            line: child.start_position().row as u32 + 1,
                            col: child.start_position().column as u32,
                        });
                    }
                }
                continue;
            }

            if !is_paren_group(next) {
                continue;
            }

            // Rebuild the qualified target so it matches how `handle_call`
            // records equivalent non-macro calls.
            let target = self.qualify_token_call(&children, i, &name);

            self.ir.calls.push(Call {
                caller: caller_id,
                callee: CallTarget::Unresolved(target),
                file: self.path.clone(),
                line: child.start_position().row as u32 + 1,
                col: child.start_position().column as u32,
            });
        }
    }

    /// Walk backwards over `::` / `.` separators to rebuild a call's path.
    fn qualify_token_call(&self, children: &[tree_sitter::Node], idx: usize, name: &str) -> String {
        // Method receiver: `x.foo()` is recorded as `x.foo`.
        if idx >= 2 && children[idx - 1].kind() == "." {
            let receiver = children[idx - 2];
            if receiver.kind() == "identifier" {
                return format!("{}.{}", self.node_text(receiver), name);
            }
            return name.to_string();
        }

        // Path segments: `a::b::foo()` is recorded as `a::b::foo`.
        let mut segments = vec![name.to_string()];
        let mut cursor = idx;
        while cursor >= 2 && children[cursor - 1].kind() == "::" {
            let seg = children[cursor - 2];
            if seg.kind() != "identifier" {
                break;
            }
            segments.push(self.node_text(seg).to_string());
            cursor -= 2;
        }
        segments.reverse();
        segments.join("::")
    }

    fn handle_macro_definition(&mut self, node: tree_sitter::Node) {
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
            kind: SymbolKind::Function, // Treat macros as functions
            visibility: Visibility::Public,
            file: self.path.clone(),
            line_start: node.start_position().row as u32 + 1,
            line_end: node.end_position().row as u32 + 1,
            col_start: node.start_position().column as u32,
            col_end: node.end_position().column as u32,
            language: Language::Rust,
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
}

/// Attributes marking a function as reachable from outside the crate graph -
/// a linker symbol, a wasm/Python host, the compiler (proc-macros), or an async
/// runtime that supplies `main`. Matched as substrings of the attribute text,
/// so `#[unsafe(no_mangle)]` and `#[tokio::main]` are both covered.
const EXPORT_ATTRIBUTES: &[&str] = &[
    "no_mangle",
    "export_name",
    "wasm_bindgen",
    "proc_macro",
    "pyfunction",
    "pymethods",
    "pyclass",
    "global_allocator",
    "panic_handler",
    "ctor",
    "dtor",
    "main",
];

/// cfg predicates that gate an item to a specific platform/target. Code behind
/// one is compiled (and called) only in that build, so it can't be proven dead
/// from a checkout of a different target.
const PLATFORM_CFG_TOKENS: &[&str] = &[
    "windows",
    "unix",
    "target_os",
    "target_arch",
    "target_family",
    "target_env",
    "target_vendor",
    "target_pointer_width",
];

/// Keywords that appear as bare identifier-like tokens inside a macro token
/// tree. `if (a) {}` or `match (x) {}` must not be mistaken for calls.
const NON_CALLABLE_KEYWORDS: &[&str] = &[
    "if", "else", "match", "while", "loop", "for", "in", "let", "fn", "return", "as", "move",
    "mut", "ref", "where", "impl", "dyn", "unsafe", "await", "break", "continue", "yield",
];

/// True when `node` is a `(`-delimited group - the argument list of a call.
/// Distinguishes `foo(x)` from `vec![x; 3]` and `Foo { x }`.
fn is_paren_group(node: &tree_sitter::Node) -> bool {
    node.kind() == "token_tree" && node.child(0).map(|c| c.kind() == "(").unwrap_or(false)
}

/// Map an HTTP verb word (`get`, `POST`, ...) to an `HttpMethod`. Case-insensitive.
/// Only the five methods with a distinct `HttpMethod` variant match; anything
/// else (including `route`/`any`, handled by the caller) returns None.
fn http_method_from_verb(verb: &str) -> Option<HttpMethod> {
    Some(match verb.to_ascii_lowercase().as_str() {
        "get" => HttpMethod::Get,
        "post" => HttpMethod::Post,
        "put" => HttpMethod::Put,
        "patch" => HttpMethod::Patch,
        "delete" => HttpMethod::Delete,
        _ => return None,
    })
}

/// Whether a call receiver looks like an HTTP client. Kept loose (the real
/// guard is the string-literal URL at the call site), matching `reqwest`,
/// `hyper`, and any `*client*`/`Client::...` receiver.
fn looks_like_http_client(object: &str) -> bool {
    let o = object.to_ascii_lowercase();
    o.contains("client") || o.contains("reqwest") || o.contains("hyper") || o == "http"
}

/// Reduce a request URL to its path: strip scheme+host and any `?query`/`#frag`.
/// `https://api.example.com/v1/x?y=1` -> `/v1/x`; a bare path is returned as-is.
fn url_to_path(raw: &str) -> String {
    let after_host = match raw.find("://") {
        Some(idx) => {
            let rest = &raw[idx + 3..];
            match rest.find('/') {
                Some(slash) => &rest[slash..],
                None => "/",
            }
        }
        None => raw,
    };
    let no_query = after_host.split('?').next().unwrap_or(after_host);
    no_query.split('#').next().unwrap_or(no_query).to_string()
}

/// Parse one attribute line into a route (verb + path). Handles verb-named
/// attributes (`#[get("/p")]`, `#[actix_web::post("/p")]`) and the generic
/// `#[route("/p", method="GET")]`. Non-route attributes (`#[derive(..)]`,
/// `#[cfg(feature = "x")]`) return None.
fn parse_route_attribute(line: &str) -> Option<(HttpMethod, String)> {
    let inner = line.trim().strip_prefix("#[")?.strip_suffix(']')?.trim();
    let paren = inner.find('(')?;
    let close = inner.rfind(')')?;
    if close <= paren {
        return None;
    }
    let name = inner[..paren].trim();
    let name = name.rsplit("::").next().unwrap_or(name);
    let args = &inner[paren + 1..close];
    let path = first_string_literal(args)?;

    if name.eq_ignore_ascii_case("route") {
        Some((extract_route_method(args).unwrap_or(HttpMethod::Any), path))
    } else {
        http_method_from_verb(name).map(|hm| (hm, path))
    }
}

/// First double-quoted literal's content in `s`, or None.
fn first_string_literal(s: &str) -> Option<String> {
    let start = s.find('"')?;
    let rest = &s[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Method verb from a `#[route(...)]` argument list: the string literal that
/// follows the `method` key, e.g. `method = "GET"` -> `HttpMethod::Get`.
fn extract_route_method(args: &str) -> Option<HttpMethod> {
    let pos = args.find("method")?;
    let val = first_string_literal(&args[pos + "method".len()..])?;
    http_method_from_verb(&val)
}

fn extract_visibility(node: tree_sitter::Node, source: &str) -> Visibility {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "visibility_modifier" {
                let text = child.utf8_text(source.as_bytes()).unwrap_or("").trim();
                return match text {
                    "pub" => Visibility::Public,
                    s if s.starts_with("pub(crate)") => Visibility::Public,
                    s if s.starts_with("pub(super)") => Visibility::Protected,
                    s if s.starts_with("pub(") => Visibility::Protected,
                    _ => Visibility::Public,
                };
            }
        }
    }
    // In Rust, no visibility modifier means private
    Visibility::Private
}

fn has_self_param(node: tree_sitter::Node, _source: &str) -> bool {
    if let Some(params) = node.child_by_field_name("parameters") {
        for i in 0..params.child_count() {
            if let Some(child) = params.child(i) {
                if child.kind() == "self_parameter" {
                    return true;
                }
            }
        }
    }
    false
}

/// Count parameters in a function definition (excluding self).
fn count_params(node: tree_sitter::Node) -> u8 {
    if let Some(params) = node.child_by_field_name("parameters") {
        let mut count: u8 = 0;
        for i in 0..params.child_count() {
            if let Some(child) = params.child(i) {
                if child.kind() == "parameter" || child.kind() == "variadic_parameter" {
                    count = count.saturating_add(1);
                }
            }
        }
        count
    } else {
        0
    }
}

/// Module path implied by the file's location: `src/net/frame.rs` ->
/// `net::frame`, `src/net/mod.rs` -> `net`, `src/lib.rs` / `src/main.rs` ->
/// crate root (empty). Files outside a `src/` tree get no module prefix.
/// Gives symbols their real module-qualified names so exact-path calls
/// resolve exactly instead of by suffix guess.
fn module_path_for(path: &Path) -> String {
    let comps: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let Some(idx) = comps.iter().rposition(|c| c == "src") else {
        return String::new();
    };
    let rel = &comps[idx + 1..];
    if rel.is_empty() {
        return String::new();
    }
    let mut parts: Vec<&str> = rel[..rel.len() - 1].iter().map(|s| s.as_str()).collect();
    let stem = rel[rel.len() - 1].trim_end_matches(".rs");
    if !matches!(stem, "lib" | "main" | "mod") {
        parts.push(stem);
    }
    parts.join("::")
}

/// Expand one `use` spec into (alias, full path) pairs. Handles `a::b::c`,
/// `a::b as x`, nested groups `a::{b, c as d, e::{f, self}}`; skips globs.
fn expand_use(spec: &str, prefix: &str, out: &mut Vec<(String, String)>) {
    let spec = spec.trim();
    if let Some(brace) = spec.find('{') {
        let head = spec[..brace].trim().trim_end_matches("::");
        let close = spec.rfind('}').unwrap_or(spec.len());
        let inner = &spec[brace + 1..close];
        let new_prefix = if head.is_empty() {
            prefix.to_string()
        } else if prefix.is_empty() {
            head.to_string()
        } else {
            format!("{prefix}::{head}")
        };
        let (mut depth, mut start) = (0i32, 0usize);
        for (i, c) in inner.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                ',' if depth == 0 => {
                    expand_use(&inner[start..i], &new_prefix, out);
                    start = i + 1;
                }
                _ => {}
            }
        }
        expand_use(&inner[start..], &new_prefix, out);
        return;
    }
    if spec.is_empty() || spec == "*" || spec.ends_with("::*") {
        return;
    }
    if spec == "self" {
        // `use a::b::{self, c}` - `self` imports the module under its own name.
        if let Some(last) = prefix.rsplit("::").next() {
            if !last.is_empty() {
                out.push((last.to_string(), prefix.to_string()));
            }
        }
        return;
    }
    let (path, alias) = match spec.split_once(" as ") {
        Some((p, a)) => (p.trim(), a.trim()),
        None => (spec, spec.rsplit("::").next().unwrap_or(spec)),
    };
    if alias.is_empty() || alias == "_" {
        return;
    }
    let full = if prefix.is_empty() {
        path.to_string()
    } else {
        format!("{prefix}::{path}")
    };
    out.push((alias.to_string(), full));
}

/// Body node count below which no flow hash is assigned - trivial bodies
/// (accessors, delegations) share shapes by coincidence, not by copying.
const MIN_FLOW_NODES: usize = 30;

/// Hash of a body's tree shape: every node kind in preorder - keywords and
/// operators included, since anonymous token kinds are their text - with the
/// text of identifiers and literals erased. Two bodies collide when they share
/// code shape and call structure but differ in names and constant values: the
/// "same logic, different config" copy that normalized_hash (which keeps
/// literal values) can't see. Comments are skipped entirely.
fn structural_hash(body: tree_sitter::Node) -> (u64, usize) {
    fn mix(s: &str, acc: &mut u64) {
        for b in s.as_bytes() {
            *acc ^= u64::from(*b);
            *acc = acc.wrapping_mul(0x100000001b3);
        }
        *acc ^= 0x1f;
        *acc = acc.wrapping_mul(0x100000001b3);
    }
    fn walk(node: tree_sitter::Node, acc: &mut u64, count: &mut usize) {
        let kind = node.kind();
        match kind {
            "line_comment" | "block_comment" => {}
            // Erase the text, keep the fact that a name/literal sat here.
            "identifier"
            | "field_identifier"
            | "type_identifier"
            | "shorthand_field_identifier"
            | "string_literal"
            | "raw_string_literal"
            | "char_literal"
            | "integer_literal"
            | "float_literal"
            | "boolean_literal" => {
                mix(kind, acc);
                *count += 1;
            }
            _ => {
                mix("(", acc);
                mix(kind, acc);
                *count += 1;
                let n = node.child_count();
                for i in 0..n {
                    if let Some(child) = node.child(i) {
                        walk(child, acc, count);
                    }
                }
                mix(")", acc);
            }
        }
    }
    let mut acc: u64 = 0xcbf29ce484222325;
    let mut count = 0usize;
    walk(body, &mut acc, &mut count);
    (acc, count)
}

/// Attribute text with whitespace removed, so token checks don't depend on
/// formatting (`#[cfg( not( test ) )]` == `#[cfg(not(test))]`).
fn normalize_attrs(attrs: &str) -> String {
    attrs.chars().filter(|c| !c.is_whitespace()).collect()
}

/// True if `needle` occurs in `attrs` as a whole word not wrapped in a
/// `not(...)` guard. Catches `cfg(test)`, `cfg(all(test,unix))`,
/// `tokio::test`; rejects `not(test)` and mid-word hits like `latest`.
fn has_affirmative_word(attrs: &str, needle: &str) -> bool {
    let bound = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric() && c != '_');
    attrs.match_indices(needle).any(|(i, _)| {
        bound(attrs[..i].chars().next_back())
            && bound(attrs[i + needle.len()..].chars().next())
            && !attrs[..i].ends_with("not(")
    })
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
    let stripped = crate::strip_comments(s, true, false, false);
    let mut normalized = String::with_capacity(stripped.len());
    let chars: Vec<char> = stripped.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        // Replace identifiers with placeholder, keep Rust keywords
        if chars[i].is_alphabetic() || chars[i] == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            let lower = ident.to_lowercase();
            match lower.as_str() {
                "fn" | "pub" | "struct" | "enum" | "trait" | "impl" | "mod" | "use" | "let"
                | "mut" | "const" | "static" | "return" | "if" | "else" | "while" | "for"
                | "loop" | "match" | "break" | "continue" | "self" | "super" | "crate" | "true"
                | "false" | "none" | "some" | "ok" | "err" | "type" | "where" | "as" | "in"
                | "ref" | "move" | "async" | "await" | "dyn" | "box" | "unsafe" | "extern"
                | "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32"
                | "i64" | "i128" | "isize" | "f32" | "f64" | "bool" | "char" | "str" | "string"
                | "vec" | "option" | "result" => {
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
