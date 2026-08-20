use std::collections::HashMap;

use verum_nucleus::{Finding, FindingKind, Ir, Severity, SymbolId, SymbolKind};

use crate::Standard;

/// Long functions, oversized parameter lists, god classes.
pub fn analyse(ir: &Ir, standard: &Standard) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Method count per parent class, for the GodClass check.
    let mut methods_per_class: HashMap<SymbolId, usize> = HashMap::new();
    for sym in ir.symbols.values() {
        if matches!(sym.kind, SymbolKind::Method | SymbolKind::StaticMethod) {
            if let Some(parent) = sym.parent {
                *methods_per_class.entry(parent).or_default() += 1;
            }
        }
    }

    for (id, sym) in &ir.symbols {
        if matches!(sym.kind, SymbolKind::Class) {
            let method_count = methods_per_class.get(id).copied().unwrap_or(0);
            if method_count > standard.max_class_methods as usize {
                findings.push(Finding {
                    fingerprint: String::new(),
                    id: format!("complexity-godclass-{}", sym.fully_qualified),
                    kind: FindingKind::GodClass,
                    severity: Severity::Medium,
                    confidence: 1.0,
                    file: sym.file.clone(),
                    line_start: sym.line_start,
                    line_end: sym.line_end,
                    symbol: Some(*id),
                    message: format!(
                        "`{}` has {} methods (max: {})",
                        sym.name, method_count, standard.max_class_methods
                    ),
                    suggestion: "Split responsibilities into smaller collaborating classes"
                        .to_string(),
                    auto_fixable: false,
                    related: Vec::new(),
                });
            }
            continue;
        }
        match &sym.kind {
            SymbolKind::Function | SymbolKind::Method | SymbolKind::StaticMethod => {}
            _ => continue,
        }

        // Inclusive span: a symbol on lines 10..=60 is 51 lines, not 50.
        let line_count = sym.line_end.saturating_sub(sym.line_start) + 1;

        if line_count > standard.max_function_lines {
            findings.push(Finding {
                fingerprint: String::new(),
                id: format!("complexity-long-{}", sym.fully_qualified),
                kind: FindingKind::LongFunction,
                severity: Severity::Medium,
                confidence: 1.0,
                file: sym.file.clone(),
                line_start: sym.line_start,
                line_end: sym.line_end,
                symbol: Some(*id),
                message: format!(
                    "`{}` is {} lines long (max: {})",
                    sym.name, line_count, standard.max_function_lines
                ),
                suggestion: "Break this function into smaller, focused functions".to_string(),
                auto_fixable: false,
                related: Vec::new(),
            });
        }

        if sym.param_count > standard.max_parameters {
            findings.push(Finding {
                fingerprint: String::new(),
                id: format!("complexity-params-{}", sym.fully_qualified),
                kind: FindingKind::TooManyParams,
                severity: Severity::Medium,
                confidence: 1.0,
                file: sym.file.clone(),
                line_start: sym.line_start,
                line_end: sym.line_end,
                symbol: Some(*id),
                message: format!(
                    "`{}` has {} parameters (max: {})",
                    sym.name, sym.param_count, standard.max_parameters
                ),
                suggestion: "Use a parameter object or builder pattern".to_string(),
                auto_fixable: false,
                related: Vec::new(),
            });
        }
    }

    findings
}
