use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result};

use verum_nucleus::Location;

/// Replace `from` with `to` only at identifier boundaries - a bare
/// `str::replace` would also rewrite occurrences inside longer identifiers,
/// string literals with adjoining word characters, and `$variables`.
fn replace_identifier(line: &str, from: &str, to: &str) -> (String, usize) {
    let mut out = String::with_capacity(line.len());
    let mut count = 0;
    let mut i = 0;
    while let Some(pos) = line[i..].find(from) {
        let abs = i + pos;
        let end = abs + from.len();
        let prev_ok = line[..abs]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '$');
        let next_ok = line[end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_');
        out.push_str(&line[i..abs]);
        if prev_ok && next_ok {
            out.push_str(to);
            count += 1;
        } else {
            out.push_str(from);
        }
        i = end;
    }
    out.push_str(&line[i..]);
    (out, count)
}

/// Rewrite call sites from one function name to another. Returns the count
/// of remapped sites.
pub fn remap_calls(
    from_name: &str,
    to_name: &str,
    call_sites: &[Location],
    dry_run: bool,
) -> Result<usize> {
    if call_sites.is_empty() {
        return Ok(0);
    }

    // One read/write per file, not per call site
    let mut by_file: HashMap<&std::path::Path, Vec<&Location>> = HashMap::new();
    for site in call_sites {
        by_file.entry(site.file.as_path()).or_default().push(site);
    }

    let mut total_remapped = 0;

    for (file, sites) in &by_file {
        if !file.exists() {
            tracing::warn!("File not found for call remap: {}", file.display());
            continue;
        }

        let source = fs::read_to_string(file)
            .with_context(|| format!("Failed to read {}", file.display()))?;

        let mut lines: Vec<String> = source.lines().map(|l| l.to_string()).collect();
        let mut file_remapped = 0;

        for site in sites {
            let line_idx = (site.line as usize).saturating_sub(1);
            if line_idx >= lines.len() {
                continue;
            }

            let (new_line, replaced) = replace_identifier(&lines[line_idx], from_name, to_name);
            if replaced > 0 {
                if dry_run {
                    tracing::info!(
                        "[dry-run] Would remap {} -> {} at {}:{}",
                        from_name,
                        to_name,
                        file.display(),
                        site.line
                    );
                } else {
                    lines[line_idx] = new_line;
                }

                file_remapped += 1;
            }
        }

        if !dry_run && file_remapped > 0 {
            let eol = crate::dead_code::line_ending(&source);
            let mut new_content = lines.join(eol);
            if source.ends_with('\n') {
                new_content.push_str(eol);
            }
            crate::dead_code::write_atomic(file, &new_content)?;
        }

        total_remapped += file_remapped;
    }

    if total_remapped > 0 {
        tracing::info!(
            "Remapped {} call sites: {} -> {}",
            total_remapped,
            from_name,
            to_name
        );
    }

    Ok(total_remapped)
}
