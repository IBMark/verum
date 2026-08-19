pub mod dead_code;
pub mod duplicates;
pub mod recursive;

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;

use verum_nucleus::{DuplicateGroup, Finding, FindingKind, Ir, Symbol};

pub const MAX_PASSES: usize = 20;

pub struct Forge {
    pub config: ForgeConfig,
}

#[derive(Debug, Clone)]
pub struct ForgeConfig {
    /// Minimum confidence to auto-fix. Default 0.85.
    pub auto_fix_threshold: f32,
    /// Report only - no file changes.
    pub dry_run: bool,
}

impl Default for ForgeConfig {
    fn default() -> Self {
        Self {
            auto_fix_threshold: 0.85,
            dry_run: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct ForgeResult {
    pub passes: usize,
    pub symbols_removed: usize,
    pub lines_removed: i64,
    pub calls_remapped: usize,
    pub files_deleted: usize,
}

impl Forge {
    pub fn new(config: ForgeConfig) -> Self {
        Self { config }
    }

    /// Remove dead code for findings at or above the confidence threshold.
    /// Removals are grouped per file and applied bottom-up so line numbers
    /// stay valid.
    pub fn execute_findings(&self, findings: &[Finding], ir: &Ir) -> Result<ForgeResult> {
        let mut result = ForgeResult::default();

        let dead_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.auto_fixable
                    && f.confidence >= self.config.auto_fix_threshold
                    && matches!(
                        f.kind,
                        FindingKind::DeadFunction | FindingKind::DeadClass | FindingKind::DeadFile
                    )
            })
            .collect();

        if dead_findings.is_empty() {
            return Ok(result);
        }

        let mut by_file: HashMap<&Path, Vec<&Finding>> = HashMap::new();
        for f in &dead_findings {
            by_file.entry(f.file.as_path()).or_default().push(f);
        }

        for (file, file_findings) in &by_file {
            let symbols: Vec<&Symbol> = file_findings
                .iter()
                .filter_map(|f| f.symbol.and_then(|sid| ir.symbols.get(&sid)))
                .filter(|sym| dead_code::is_safe_to_auto_delete(sym, ir))
                .collect();

            if symbols.is_empty() {
                continue;
            }

            match dead_code::remove_dead_symbols_from_file(&symbols, self.config.dry_run) {
                Ok(lines) => {
                    result.lines_removed += lines as i64;
                    result.symbols_removed += symbols.len();
                    if !file.exists() && !self.config.dry_run {
                        result.files_deleted += 1;
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to remove dead code from {}: {}", file.display(), e);
                }
            }
        }

        Ok(result)
    }

    /// Execute duplicate groups: remap calls then remove duplicates.
    pub fn execute_groups(&self, groups: &[DuplicateGroup], ir: &Ir) -> Result<ForgeResult> {
        let mut result = ForgeResult::default();

        for group in groups {
            if group.confidence < self.config.auto_fix_threshold {
                continue;
            }

            let canonical = match ir.symbols.get(&group.canonical) {
                Some(sym) => sym,
                None => continue,
            };
            let canonical_name = canonical.name.clone();

            for dup_id in &group.duplicates {
                let dup_sym = match ir.symbols.get(dup_id) {
                    Some(sym) => sym,
                    None => continue,
                };

                match duplicates::remap_calls(
                    &dup_sym.name,
                    &canonical_name,
                    &group.call_sites_to_remap,
                    self.config.dry_run,
                ) {
                    Ok(count) => {
                        result.calls_remapped += count;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to remap calls {} -> {}: {}",
                            dup_sym.name,
                            canonical_name,
                            e
                        );
                    }
                }

                if dead_code::is_safe_to_auto_delete(dup_sym, ir) {
                    match dead_code::remove_dead_symbol(dup_sym, self.config.dry_run) {
                        Ok(lines) => {
                            result.lines_removed += lines as i64;
                            result.symbols_removed += 1;
                        }
                        Err(e) => {
                            tracing::warn!("Failed to remove duplicate {}: {}", dup_sym.name, e);
                        }
                    }
                }
            }
        }

        Ok(result)
    }
}
