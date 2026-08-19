use anyhow::Result;

use verum_lumen::{Prism, Standard};
use verum_mappa::{Atlas, AtlasConfig};

use crate::{Forge, ForgeResult, MAX_PASSES};

/// Re-parse, re-analyse, and fix in a loop until the symbol count stops
/// changing (or MAX_PASSES). Removing one layer of dead code can orphan its
/// callees, so a single pass isn't enough.
pub fn run_until_stable(
    forge: &Forge,
    atlas_config: &AtlasConfig,
    standard: &Standard,
) -> Result<ForgeResult> {
    let mut total = ForgeResult::default();

    for pass in 0..MAX_PASSES {
        let ir = Atlas::new(atlas_config.clone()).build()?;
        let before = ir.symbol_count();

        let result = Prism::analyse(&ir, standard)?;

        let fix_result = forge.execute_findings(&result.auto_fixable, &ir)?;

        let ir_after = Atlas::new(atlas_config.clone()).build()?;
        let after = ir_after.symbol_count();

        tracing::info!("Pass {}: {} -> {} symbols", pass + 1, before, after);

        total.passes += 1;
        total.symbols_removed += before.saturating_sub(after);
        total.lines_removed += fix_result.lines_removed;
        total.files_deleted += fix_result.files_deleted;

        if before == after {
            break;
        }
    }

    Ok(total)
}
