use std::fs;

use anyhow::{Context, Result};

use verum_nucleus::{matchable_path, Ir, Language, Symbol, Visibility};

/// Magic method names that should never be auto-deleted.
const MAGIC: &[&str] = &[
    "__construct",
    "__destruct",
    "__get",
    "__set",
    "__call",
    "__callStatic",
    "__toString",
    "__invoke",
    "boot",
    "register",
    "handle",
    "up",
    "down",
    "run",
    "setUp",
    "tearDown",
];

/// Laravel framework methods that are invoked by the framework.
const LARAVEL_FRAMEWORK_METHODS: &[&str] = &[
    "provides",
    "bindings",
    "singletons",
    "execute",
    "schedule",
    "terminate",
    "subscribe",
    "broadcastOn",
    "broadcastAs",
    "toMail",
    "toArray",
    "toDatabase",
    "via",
    "passes",
    "message",
    "messages",
    "rules",
    "authorize",
    "failed",
    "creating",
    "created",
    "updating",
    "updated",
    "deleting",
    "deleted",
    "saving",
    "saved",
    "restoring",
    "restored",
    "forceDeleted",
    "resolveRouteBinding",
    "getRouteKeyName",
    "transform",
    "before",
    "render",
];

/// Safety guard for automatic deletion. Magic methods, framework hooks,
/// vendor code, and test files are never touched regardless of confidence.
pub fn is_safe_to_auto_delete(symbol: &Symbol, _ir: &Ir) -> bool {
    // Pseudo symbols (file scopes, compiled blade views)
    if symbol.name.starts_with("__file_scope_") || symbol.name.starts_with("blade::") {
        return false;
    }

    if MAGIC.contains(&symbol.name.as_str()) {
        return false;
    }

    if LARAVEL_FRAMEWORK_METHODS.contains(&symbol.name.as_str()) {
        return false;
    }

    if symbol.is_entry_point {
        return false;
    }

    let path_str = matchable_path(&symbol.file);

    if path_str.contains("vendor") || path_str.contains("node_modules") {
        return false;
    }

    // Test files, by each supported language's naming convention
    let file_name = symbol
        .file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if path_str.contains("/tests/")
        || path_str.contains("/test/")
        || path_str.contains("/__tests__/")
        || path_str.ends_with("Test.php")
        || path_str.ends_with(".test.ts")
        || path_str.ends_with(".test.tsx")
        || path_str.ends_with(".test.js")
        || path_str.ends_with(".test.jsx")
        || path_str.ends_with(".spec.ts")
        || path_str.ends_with(".spec.tsx")
        || path_str.ends_with(".spec.js")
        || path_str.ends_with("_test.go")
        || path_str.ends_with("_test.rs")
        || path_str.ends_with("_test.py")
        || path_str.ends_with("tests.py")
        || file_name.starts_with("test_")
    {
        return false;
    }

    // Eloquent accessors (getXAttribute), mutators (setXAttribute), scopes (scopeX)
    // - all invoked via magic dispatch, so they look dead to the call graph.
    if symbol.name.starts_with("get")
        && symbol.name.ends_with("Attribute")
        && symbol.name.len() > 12
    {
        return false;
    }
    if symbol.name.starts_with("set")
        && symbol.name.ends_with("Attribute")
        && symbol.name.len() > 12
    {
        return false;
    }
    if symbol.name.starts_with("scope")
        && symbol.name.len() > 5
        && symbol.name.chars().nth(5).is_some_and(|c| c.is_uppercase())
    {
        return false;
    }
    // Fractal includes (includeX)
    if symbol.name.starts_with("include")
        && symbol.name.len() > 7
        && symbol.name.chars().nth(7).is_some_and(|c| c.is_uppercase())
    {
        return false;
    }

    // Laravel paths whose classes are wired up by the framework, not by calls
    if path_str.contains("/Models/")
        || path_str.contains("/Listeners/")
        || path_str.contains("/Events/")
        || path_str.contains("/Observers/")
        || path_str.contains("/Policies/")
        || path_str.contains("/Providers/")
        || path_str.contains("/Console/")
        || path_str.contains("/Jobs/")
        || path_str.contains("/Notifications/")
        || path_str.contains("/Middleware/")
        || path_str.contains("/Transformers/")
    {
        return false;
    }

    if matches!(symbol.language, Language::TypeScript | Language::JavaScript) {
        // Exported React components (PascalCase)
        if matches!(symbol.visibility, Visibility::Public)
            && symbol.name.chars().next().is_some_and(|c| c.is_uppercase())
        {
            return false;
        }
        // Custom hooks (useXxx)
        if symbol.name.starts_with("use")
            && symbol.name.len() > 3
            && symbol.name.chars().nth(3).is_some_and(|c| c.is_uppercase())
        {
            return false;
        }
        // Route/page modules are referenced by convention, not by calls
        if path_str.contains("/routers/") || path_str.contains("/pages/") {
            return false;
        }
    }

    true
}

/// Detect the file's line ending so a rewrite doesn't silently convert CRLF
/// files to LF across their entire contents.
pub(crate) fn line_ending(source: &str) -> &'static str {
    if source.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

/// Write via temp-file + rename so a crash mid-write can't truncate the target.
pub(crate) fn write_atomic(path: &std::path::Path, content: &str) -> Result<()> {
    let tmp = path.with_file_name(format!(
        ".{}.verum-tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    fs::write(&tmp, content).with_context(|| format!("Failed to write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("Failed to replace {}", path.display()))?;
    Ok(())
}

/// True when the remaining lines carry no content worth keeping. Comment
/// lines DO count as content - a file left with only a license header or
/// commented-out code must not be deleted.
fn is_effectively_empty(lines: &[String]) -> bool {
    lines.iter().all(|l| {
        let trimmed = l.trim();
        trimmed.is_empty() || trimmed == "<?php" || trimmed == "?>"
    })
}

/// Remove one dead symbol. Returns the number of lines removed.
pub fn remove_dead_symbol(symbol: &Symbol, dry_run: bool) -> Result<usize> {
    remove_dead_symbols_from_file(&[symbol], dry_run)
}

/// Remove multiple dead symbols from a single file.
///
/// Ranges are de-overlapped first (a method nested inside a class being
/// removed must not be drained separately - after the outer drain its absolute
/// indices would point at unrelated lines further down the file), then
/// processed bottom-up so earlier ranges keep their original indices.
pub fn remove_dead_symbols_from_file(symbols: &[&Symbol], dry_run: bool) -> Result<usize> {
    if symbols.is_empty() {
        return Ok(0);
    }

    let file = &symbols[0].file;
    if !file.exists() {
        return Ok(0);
    }

    let source =
        fs::read_to_string(file).with_context(|| format!("Failed to read {}", file.display()))?;
    let eol = line_ending(&source);

    let mut lines: Vec<String> = source.lines().map(|l| l.to_string()).collect();

    // Build 0-indexed half-open ranges, sorted by (start asc, end desc).
    let mut ranges: Vec<(usize, usize, &str)> = symbols
        .iter()
        .filter_map(|sym| {
            let start = (sym.line_start as usize).saturating_sub(1);
            let end = (sym.line_end as usize).min(lines.len());
            (start < lines.len() && start < end).then_some((start, end, sym.name.as_str()))
        })
        .collect();
    ranges.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));

    // Keep only ranges disjoint from every previously kept range. Nested and
    // partially overlapping ranges are already covered (or unsafe) - skip.
    let mut kept: Vec<(usize, usize, &str)> = Vec::with_capacity(ranges.len());
    for (start, end, name) in ranges {
        match kept.last() {
            Some(&(_, prev_end, _)) if start < prev_end => {
                tracing::debug!(
                    "Skipping `{}` - its range overlaps an already-removed symbol",
                    name
                );
            }
            _ => kept.push((start, end, name)),
        }
    }

    let mut total_removed = 0;

    // Bottom-up: draining high ranges first leaves lower indices valid.
    for (start, end, name) in kept.iter().rev() {
        let removed = end - start;
        if dry_run {
            tracing::info!(
                "[dry-run] Would remove {} ({} lines {}-{}) from {}",
                name,
                removed,
                start + 1,
                end,
                file.display()
            );
        } else {
            lines.drain(*start..*end);
            tracing::info!(
                "Removed {} ({} lines) from {}",
                name,
                removed,
                file.display()
            );
        }
        total_removed += removed;
    }

    if !dry_run {
        if is_effectively_empty(&lines) {
            fs::remove_file(file)
                .with_context(|| format!("Failed to delete empty file {}", file.display()))?;
            tracing::info!("Deleted empty file: {}", file.display());
        } else {
            let mut new_content = lines.join(eol);
            if source.ends_with('\n') {
                new_content.push_str(eol);
            }
            write_atomic(file, &new_content)?;
        }
    }

    Ok(total_removed)
}
