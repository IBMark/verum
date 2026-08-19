//! Analyze a directory with the library API and print the score and findings.
//!
//! Run it against any tree:
//!
//! ```text
//! cargo run --example analyze -- path/to/project
//! ```

use verum::{Atlas, AtlasConfig, Prism, Standard};

fn main() -> anyhow::Result<()> {
    let root = std::env::args().nth(1).unwrap_or_else(|| ".".to_string());

    // Parse the tree into the IR, then run every analysis over it. Both steps
    // are deterministic: the same tree always yields the same result.
    let ir = Atlas::new(AtlasConfig {
        root: root.into(),
        ..Default::default()
    })
    .build()?;
    let result = Prism::analyse(&ir, &Standard::default())?;

    println!("score: {}/100", result.score.overall);
    println!("findings: {}", result.findings.len());
    for f in result.findings.iter().take(20) {
        println!(
            "  {:?}  {}  ({}:{})",
            f.severity,
            f.message,
            f.file.display(),
            f.line_start
        );
    }
    Ok(())
}
