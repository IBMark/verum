use verum_nucleus::{Finding, FindingKind, Ir, Language, Severity, SymbolKind};

use crate::{NamingConfig, NamingConvention, NamingRules};

/// Check naming conventions (per-language, configurable) and synonym-prefix
/// inconsistencies.
pub fn analyse(ir: &Ir, config: &NamingConfig) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (_id, sym) in &ir.symbols {
        // Infrastructure resources (K8s names, Terraform addresses, Dockerfile
        // stages) follow their own naming rules - code conventions don't apply.
        if matches!(
            sym.language,
            Language::Kubernetes | Language::Terraform | Language::Docker | Language::Unknown
        ) {
            continue;
        }
        if sym.name.starts_with("__file_scope_") || sym.name.starts_with("blade::") {
            continue;
        }
        let path_str = sym.file.to_string_lossy();
        if path_str.contains("vendor/") || path_str.contains("node_modules/") {
            continue;
        }

        // Go uses MixedCaps for everything, with capitalization encoding export
        // (exported `PascalCase`, unexported `camelCase`). A single cross-language
        // convention flags every unexported type and half the methods, and
        // golint-style checks are too pedantic to run by default. Skip Go until
        // dedicated idiomatic rules exist.
        if sym.language == Language::Go {
            continue;
        }

        let rules = get_rules_for_language(&sym.language, config);

        match &sym.kind {
            SymbolKind::Class | SymbolKind::Interface | SymbolKind::Trait | SymbolKind::Enum => {
                let convention = rules
                    .as_ref()
                    .and_then(|r| r.classes.as_ref())
                    .unwrap_or(&NamingConvention::PascalCase);

                if !check_convention(&sym.name, convention) {
                    findings.push(Finding {
                        id: format!("naming-class-{}", sym.fully_qualified),
                        kind: FindingKind::ConventionViolation,
                        severity: Severity::Low,
                        confidence: 0.95,
                        file: sym.file.clone(),
                        line_start: sym.line_start,
                        line_end: sym.line_end,
                        symbol: Some(*_id),
                        message: format!(
                            "Class `{}` should be {}",
                            sym.name,
                            convention_name(convention)
                        ),
                        suggestion: format!(
                            "Rename to `{}`",
                            convert_to_convention(&sym.name, convention)
                        ),
                        auto_fixable: false,
                        related: Vec::new(),
                    });
                }
            }
            SymbolKind::Method | SymbolKind::StaticMethod => {
                if sym.name.starts_with("__") {
                    continue;
                }

                let convention = match rules
                    .as_ref()
                    .and_then(|r| r.methods.as_ref())
                    .cloned()
                    .or_else(|| default_callable_convention(&sym.language))
                {
                    Some(c) => c,
                    None => continue,
                };
                let convention = &convention;

                if !check_convention(&sym.name, convention) {
                    findings.push(Finding {
                        id: format!("naming-method-{}", sym.fully_qualified),
                        kind: FindingKind::ConventionViolation,
                        severity: Severity::Low,
                        confidence: 0.95,
                        file: sym.file.clone(),
                        line_start: sym.line_start,
                        line_end: sym.line_end,
                        symbol: Some(*_id),
                        message: format!(
                            "Method `{}` should be {}",
                            sym.name,
                            convention_name(convention)
                        ),
                        suggestion: format!(
                            "Rename to `{}`",
                            convert_to_convention(&sym.name, convention)
                        ),
                        auto_fixable: false,
                        related: Vec::new(),
                    });
                }
            }
            SymbolKind::Function => {
                // Uppercase JS/TS function = React component, own convention.
                let is_component =
                    matches!(sym.language, Language::TypeScript | Language::JavaScript)
                        && sym.name.chars().next().is_some_and(|c| c.is_uppercase());

                if is_component {
                    let convention = rules
                        .as_ref()
                        .and_then(|r| r.components.as_ref())
                        .unwrap_or(&NamingConvention::PascalCase);

                    if !check_convention(&sym.name, convention) {
                        findings.push(Finding {
                            id: format!("naming-component-{}", sym.fully_qualified),
                            kind: FindingKind::ConventionViolation,
                            severity: Severity::Low,
                            confidence: 0.95,
                            file: sym.file.clone(),
                            line_start: sym.line_start,
                            line_end: sym.line_end,
                            symbol: Some(*_id),
                            message: format!(
                                "Component `{}` should be {}",
                                sym.name,
                                convention_name(convention)
                            ),
                            suggestion: format!(
                                "Rename to `{}`",
                                convert_to_convention(&sym.name, convention)
                            ),
                            auto_fixable: false,
                            related: Vec::new(),
                        });
                    }
                } else {
                    let convention = match rules
                        .as_ref()
                        .and_then(|r| r.functions.as_ref())
                        .cloned()
                        .or_else(|| default_callable_convention(&sym.language))
                    {
                        Some(c) => c,
                        None => continue,
                    };
                    let convention = &convention;

                    if !check_convention(&sym.name, convention) {
                        findings.push(Finding {
                            id: format!("naming-function-{}", sym.fully_qualified),
                            kind: FindingKind::ConventionViolation,
                            severity: Severity::Low,
                            confidence: 0.95,
                            file: sym.file.clone(),
                            line_start: sym.line_start,
                            line_end: sym.line_end,
                            symbol: Some(*_id),
                            message: format!(
                                "Function `{}` should be {}",
                                sym.name,
                                convention_name(convention)
                            ),
                            suggestion: format!(
                                "Rename to `{}`",
                                convert_to_convention(&sym.name, convention)
                            ),
                            auto_fixable: false,
                            related: Vec::new(),
                        });
                    }
                }
            }
            SymbolKind::Constant => {
                let convention = match rules
                    .as_ref()
                    .and_then(|r| r.constants.as_ref())
                    .cloned()
                    .or_else(|| default_constant_convention(&sym.language))
                {
                    Some(c) => c,
                    None => continue,
                };
                let convention = &convention;

                if !check_convention(&sym.name, convention) {
                    findings.push(Finding {
                        id: format!("naming-constant-{}", sym.fully_qualified),
                        kind: FindingKind::ConventionViolation,
                        severity: Severity::Low,
                        confidence: 0.90,
                        file: sym.file.clone(),
                        line_start: sym.line_start,
                        line_end: sym.line_end,
                        symbol: Some(*_id),
                        message: format!(
                            "Constant `{}` should be {}",
                            sym.name,
                            convention_name(convention)
                        ),
                        suggestion: format!(
                            "Rename to `{}`",
                            convert_to_convention(&sym.name, convention)
                        ),
                        auto_fixable: false,
                        related: Vec::new(),
                    });
                }
            }
            SymbolKind::Variable | SymbolKind::Property => {
                let convention = match rules
                    .as_ref()
                    .and_then(|r| {
                        if matches!(sym.kind, SymbolKind::Property) {
                            r.properties.as_ref().or(r.variables.as_ref())
                        } else {
                            r.variables.as_ref()
                        }
                    })
                    .cloned()
                    .or_else(|| default_variable_convention(&sym.language))
                {
                    Some(c) => c,
                    None => continue,
                };
                let convention = &convention;

                // Short or special names ($this, $_, _private) aren't worth flagging.
                if sym.name.len() <= 2 || sym.name.starts_with('_') || sym.name.starts_with('$') {
                    continue;
                }

                if !check_convention(&sym.name, convention) {
                    findings.push(Finding {
                        id: format!("naming-variable-{}", sym.fully_qualified),
                        kind: FindingKind::ConventionViolation,
                        severity: Severity::Low,
                        confidence: 0.85,
                        file: sym.file.clone(),
                        line_start: sym.line_start,
                        line_end: sym.line_end,
                        symbol: Some(*_id),
                        message: format!(
                            "Variable `{}` should be {}",
                            sym.name,
                            convention_name(convention)
                        ),
                        suggestion: format!(
                            "Rename to `{}`",
                            convert_to_convention(&sym.name, convention)
                        ),
                        auto_fixable: false,
                        related: Vec::new(),
                    });
                }
            }
        }
    }

    // Synonym prefixes: a project should pick one of get/fetch/load/..., not mix.
    let synonym_groups: &[&[&str]] = &[
        &["get", "fetch", "load", "retrieve", "find"],
        &["delete", "remove", "destroy"],
        &["create", "make", "build", "generate"],
        &["update", "modify", "change", "edit"],
    ];

    let mut method_syms: Vec<&verum_nucleus::Symbol> = ir
        .symbols
        .values()
        .filter(|s| {
            if !matches!(
                s.kind,
                SymbolKind::Method | SymbolKind::StaticMethod | SymbolKind::Function
            ) {
                return false;
            }
            let path_str = s.file.to_string_lossy();
            !path_str.contains("vendor/")
                && !path_str.contains("node_modules/")
                && !path_str.contains("/target/")
        })
        .collect();
    method_syms.sort_by(|a, b| (&a.file, a.line_start).cmp(&(&b.file, b.line_start)));

    for group in synonym_groups {
        // First example symbol per used prefix, in deterministic order.
        let mut used: Vec<(&str, &verum_nucleus::Symbol)> = Vec::new();
        for prefix in *group {
            for sym in &method_syms {
                if is_prefix_variant(&sym.name, prefix) {
                    used.push((prefix, sym));
                    break;
                }
            }
        }
        if used.len() > 1 {
            let variants: Vec<&str> = used.iter().map(|(p, _)| *p).collect();
            let first_sym = used[0].1;
            let related: Vec<verum_nucleus::Location> = used
                .iter()
                .map(|(prefix, sym)| verum_nucleus::Location {
                    file: sym.file.clone(),
                    line: sym.line_start,
                    description: format!("`{}` uses `{}`", sym.name, prefix),
                })
                .collect();
            findings.push(Finding {
                id: format!("naming-inconsistency-{}", variants.join("-")),
                kind: FindingKind::NamingInconsistency,
                severity: Severity::Medium,
                confidence: 0.75,
                file: first_sym.file.clone(),
                line_start: first_sym.line_start,
                line_end: first_sym.line_start,
                symbol: None,
                message: format!(
                    "Inconsistent naming: project uses multiple synonyms: {}",
                    variants
                        .iter()
                        .map(|v| format!("`{}`", v))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                suggestion: format!("Standardize on one prefix (e.g., `{}`)", variants[0]),
                auto_fixable: false,
                related,
            });
        }
    }

    findings
}

/// A name counts as a variant of a synonym prefix only at a word boundary:
/// the name IS the prefix exactly, or the character after the prefix is an
/// uppercase letter (camelCase: `loadUser`) or an underscore (snake_case:
/// `load_user`). Lowercase continuation (`loading`, `editor`) is a different
/// word, not a variant.
fn is_prefix_variant(name: &str, prefix: &str) -> bool {
    let mut chars = name.chars();
    for pc in prefix.chars() {
        match chars.next() {
            Some(nc) if nc.to_ascii_lowercase() == pc => {}
            _ => return false,
        }
    }
    match chars.next() {
        None => true,
        Some(c) => c.is_uppercase() || c == '_',
    }
}

/// Default convention for functions/methods when no config is provided.
/// `None` means "don't check" - Go idiomatically mixes PascalCase (exported)
/// and camelCase (unexported), so an unconfigured check would only produce noise.
fn default_callable_convention(lang: &Language) -> Option<NamingConvention> {
    match lang {
        Language::Php | Language::JavaScript | Language::TypeScript => {
            Some(NamingConvention::CamelCase)
        }
        Language::Rust | Language::Python => Some(NamingConvention::SnakeCase),
        _ => None,
    }
}

fn default_constant_convention(lang: &Language) -> Option<NamingConvention> {
    match lang {
        Language::Go => None,
        _ => Some(NamingConvention::ScreamingSnakeCase),
    }
}

fn default_variable_convention(lang: &Language) -> Option<NamingConvention> {
    match lang {
        Language::Php | Language::JavaScript | Language::TypeScript => {
            Some(NamingConvention::CamelCase)
        }
        Language::Rust | Language::Python => Some(NamingConvention::SnakeCase),
        _ => None,
    }
}

fn get_rules_for_language<'a>(
    lang: &Language,
    config: &'a NamingConfig,
) -> Option<&'a NamingRules> {
    match lang {
        Language::Php => config.php.as_ref(),
        Language::TypeScript => config.typescript.as_ref().or(config.javascript.as_ref()),
        Language::JavaScript => config.javascript.as_ref(),
        Language::Rust => config.rust.as_ref(),
        Language::Python => config.python.as_ref(),
        Language::Go => config.go.as_ref(),
        _ => None,
    }
}

fn check_convention(name: &str, convention: &NamingConvention) -> bool {
    match convention {
        NamingConvention::PascalCase => is_pascal_case(name),
        NamingConvention::CamelCase => is_camel_case(name),
        NamingConvention::SnakeCase => is_snake_case(name),
        NamingConvention::ScreamingSnakeCase => is_screaming_snake_case(name),
    }
}

fn convention_name(convention: &NamingConvention) -> &'static str {
    match convention {
        NamingConvention::PascalCase => "PascalCase",
        NamingConvention::CamelCase => "camelCase",
        NamingConvention::SnakeCase => "snake_case",
        NamingConvention::ScreamingSnakeCase => "SCREAMING_SNAKE_CASE",
    }
}

/// Best-effort rename suggestion.
fn convert_to_convention(name: &str, convention: &NamingConvention) -> String {
    match convention {
        NamingConvention::PascalCase => to_pascal_case(name),
        NamingConvention::CamelCase => to_camel_case(name),
        NamingConvention::SnakeCase => to_snake_case(name),
        NamingConvention::ScreamingSnakeCase => to_screaming_snake_case(name),
    }
}

fn is_pascal_case(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s.chars().next().unwrap();
    first.is_uppercase() && !s.contains('_')
}

fn is_camel_case(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s.chars().next().unwrap();
    first.is_lowercase() && !s.contains('_')
}

fn is_snake_case(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let chars: Vec<char> = s.chars().collect();
    if chars[0] == '_' || chars[chars.len() - 1] == '_' {
        return false;
    }
    for (i, c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            return false;
        }
        if *c == '_' && i + 1 < chars.len() && chars[i + 1] == '_' {
            return false;
        }
        if !c.is_alphanumeric() && *c != '_' {
            return false;
        }
    }
    true
}

fn is_screaming_snake_case(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    for c in s.chars() {
        if c.is_lowercase() {
            return false;
        }
        if !c.is_alphanumeric() && c != '_' {
            return false;
        }
    }
    true
}

/// Split a name into word segments by camelCase/PascalCase boundaries and underscores.
fn split_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();

    for c in s.chars() {
        if c == '_' {
            if !current.is_empty() {
                words.push(current.clone());
                current.clear();
            }
        } else if c.is_uppercase() && !current.is_empty() {
            words.push(current.clone());
            current.clear();
            current.push(c);
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn to_pascal_case(s: &str) -> String {
    split_words(s)
        .iter()
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().to_string() + &c.as_str().to_lowercase(),
            }
        })
        .collect()
}

fn to_camel_case(s: &str) -> String {
    let pascal = to_pascal_case(s);
    let mut c = pascal.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_lowercase().to_string() + c.as_str(),
    }
}

fn to_snake_case(s: &str) -> String {
    split_words(s)
        .iter()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join("_")
}

fn to_screaming_snake_case(s: &str) -> String {
    split_words(s)
        .iter()
        .map(|w| w.to_uppercase())
        .collect::<Vec<_>>()
        .join("_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NamingConfig;
    use std::path::PathBuf;
    use verum_nucleus::{Symbol, SymbolId, Visibility};

    fn sym(id: u64, name: &str, file: &str) -> Symbol {
        Symbol {
            id: SymbolId(id),
            name: name.to_string(),
            fully_qualified: name.to_string(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            file: PathBuf::from(file),
            line_start: 1,
            line_end: 2,
            col_start: 0,
            col_end: 0,
            language: Language::Php,
            parent: None,
            hash: 0,
            normalized_hash: 0,
            flow_hash: 0,
            param_count: 0,
            is_entry_point: false,
            doc_comment: None,
        }
    }

    fn ir_of(syms: Vec<Symbol>) -> Ir {
        let mut ir = Ir::new();
        for s in syms {
            ir.symbols.insert(s.id, s);
        }
        ir
    }

    fn inconsistencies(ir: &Ir) -> Vec<Finding> {
        analyse(ir, &NamingConfig::default())
            .into_iter()
            .filter(|f| matches!(f.kind, FindingKind::NamingInconsistency))
            .collect()
    }

    #[test]
    fn prefix_variant_word_boundary() {
        // Exact match and camelCase/snake_case continuations count.
        assert!(is_prefix_variant("load", "load"));
        assert!(is_prefix_variant("loadUser", "load"));
        assert!(is_prefix_variant("load_user", "load"));
        assert!(is_prefix_variant("GetUser", "get"));
        // Lowercase continuation is a different word, not a variant.
        assert!(!is_prefix_variant("loading", "load"));
        assert!(!is_prefix_variant("editor", "edit"));
        assert!(!is_prefix_variant("generated", "generate"));
        assert!(!is_prefix_variant("findings", "find"));
    }

    #[test]
    fn loading_does_not_pair_with_get_user() {
        // `loading` merely starts with "load" - it must not count as a load
        // variant, so getUser + loading is NOT a get/load inconsistency.
        let ir = ir_of(vec![
            sym(1, "loading", "src/a.php"),
            sym(2, "getUser", "src/b.php"),
        ]);
        let found = inconsistencies(&ir);
        assert!(
            found.is_empty(),
            "loading + getUser must not produce a synonym inconsistency, got: {:?}",
            found.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn load_user_still_pairs_with_get_user() {
        let ir = ir_of(vec![
            sym(1, "loadUser", "src/a.php"),
            sym(2, "getUser", "src/b.php"),
        ]);
        let found = inconsistencies(&ir);
        assert_eq!(found.len(), 1, "loadUser + getUser is a real get/load mix");
        assert!(found[0].message.contains("`get`"));
        assert!(found[0].message.contains("`load`"));
    }

    #[test]
    fn snake_case_variants_still_pair() {
        let ir = ir_of(vec![
            sym(1, "load_user", "src/a.php"),
            sym(2, "get_user", "src/b.php"),
        ]);
        assert_eq!(inconsistencies(&ir).len(), 1);
    }

    #[test]
    fn vendor_and_target_paths_skipped() {
        let ir = ir_of(vec![
            sym(1, "fetchUser", "vendor/lib/a.php"),
            sym(2, "loadUser", "app/node_modules/pkg/b.php"),
            sym(3, "findUser", "app/target/debug/c.php"),
            sym(4, "getUser", "src/d.php"),
        ]);
        assert!(
            inconsistencies(&ir).is_empty(),
            "symbols under vendor/, node_modules/, /target/ must not feed the synonym scan"
        );
    }
}
