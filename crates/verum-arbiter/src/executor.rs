use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use verum_faber::Forge;
use verum_nucleus::{DecisionRequest, DecisionResponse, Ir, Language, Symbol, SymbolId};

/// Resolve the symbol a decision refers to.
///
/// Decision ids are finding ids (e.g. `dead-App\Foo::bar`), so the primary
/// path is matching the decision back to its `DecisionRequest` and using the
/// finding's `symbol` field. Name matching is only a fallback for decisions
/// whose request can't be found.
fn resolve_symbol<'a>(
    decision: &DecisionResponse,
    requests_by_id: &HashMap<&str, &DecisionRequest>,
    ir: &'a Ir,
) -> Option<(&'a SymbolId, &'a Symbol)> {
    if let Some(request) = requests_by_id.get(decision.id.as_str()) {
        if let Some(symbol_id) = request.finding.symbol {
            if let Some(entry) = ir.symbols.get_key_value(&symbol_id) {
                return Some(entry);
            }
        }
    }
    // Fallback: strip known finding-id prefixes and match by qualified name.
    let name = decision
        .id
        .strip_prefix("dead-")
        .or_else(|| decision.id.strip_prefix("dup-"))
        .unwrap_or(&decision.id);
    ir.symbols
        .iter()
        .find(|(_, s)| s.fully_qualified == name || s.name == name)
}

fn deprecation_comment(language: &Language) -> &'static str {
    match language {
        Language::Python => "# deprecated: flagged by Verum review",
        Language::Rust => "#[deprecated]",
        Language::Go => "// Deprecated: flagged by Verum review",
        _ => "/** @deprecated */",
    }
}

/// Execute the model's decisions. Deletions respect the same safety guard as the
/// deterministic pass and are applied per file bottom-up, so earlier removals
/// can't invalidate later line numbers.
pub fn execute_decisions(
    decisions: &[DecisionResponse],
    requests: &[DecisionRequest],
    ir: &Ir,
    forge: &Forge,
) -> Result<usize> {
    let requests_by_id: HashMap<&str, &DecisionRequest> =
        requests.iter().map(|r| (r.id.as_str(), r)).collect();

    let mut actions_taken = 0;
    let mut deletions: HashMap<PathBuf, Vec<&Symbol>> = HashMap::new();
    // (file, line_start, comment) - applied bottom-up per file.
    let mut deprecations: HashMap<PathBuf, Vec<(u32, &'static str)>> = HashMap::new();

    for decision in decisions {
        match decision.action.as_str() {
            "delete" => {
                if let Some((_, symbol)) = resolve_symbol(decision, &requests_by_id, ir) {
                    if verum_faber::dead_code::is_safe_to_auto_delete(symbol, ir) {
                        deletions
                            .entry(symbol.file.clone())
                            .or_default()
                            .push(symbol);
                        actions_taken += 1;
                    } else {
                        tracing::warn!(
                            "the model requested deletion of `{}` but the safety guard refused",
                            symbol.name
                        );
                    }
                } else {
                    tracing::warn!("Decision `{}` matched no symbol - skipped", decision.id);
                }
            }
            "mark_deprecated" => {
                if let Some((_, symbol)) = resolve_symbol(decision, &requests_by_id, ir) {
                    deprecations
                        .entry(symbol.file.clone())
                        .or_default()
                        .push((symbol.line_start, deprecation_comment(&symbol.language)));
                    actions_taken += 1;
                } else {
                    tracing::warn!("Decision `{}` matched no symbol - skipped", decision.id);
                }
            }
            "keep" => {}
            other => {
                tracing::warn!("Unknown decision action `{}` - ignored", other);
            }
        }
    }

    for (file, symbols) in &deletions {
        if let Err(e) =
            verum_faber::dead_code::remove_dead_symbols_from_file(symbols, forge.config.dry_run)
        {
            tracing::warn!("Failed to apply deletions in {}: {}", file.display(), e);
        }
    }

    for (file, mut inserts) in deprecations {
        if forge.config.dry_run {
            for (line, comment) in &inserts {
                tracing::info!(
                    "[dry-run] Would insert `{}` at {}:{}",
                    comment,
                    file.display(),
                    line
                );
            }
            continue;
        }
        let content = match std::fs::read_to_string(&file) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to read {}: {}", file.display(), e);
                continue;
            }
        };
        let eol = if content.contains("\r\n") {
            "\r\n"
        } else {
            "\n"
        };
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        // Bottom-up so earlier insertions don't shift later line numbers.
        inserts.sort_by(|a, b| b.0.cmp(&a.0));
        for (line_start, comment) in inserts {
            let idx = (line_start as usize).saturating_sub(1).min(lines.len());
            lines.insert(idx, comment.to_string());
        }
        let mut new_content = lines.join(eol);
        if content.ends_with('\n') {
            new_content.push_str(eol);
        }
        if let Err(e) = std::fs::write(&file, new_content) {
            tracing::warn!("Failed to write {}: {}", file.display(), e);
        }
    }

    Ok(actions_taken)
}
