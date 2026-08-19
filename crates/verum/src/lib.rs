//! Verum: a deterministic, whole-program code analyzer.
//!
//! This crate is both the `verum` command-line tool and a library facade over
//! the analysis pipeline. Everything the binary does is available
//! programmatically: parse a tree into an [`Ir`], then run the analyses over it.
//! Results are a pure function of the source - the same tree always yields the
//! same ids, findings, and score - so the library is safe to cache and diff.
//!
//! ```no_run
//! use verum::{Atlas, AtlasConfig, Prism, Standard};
//!
//! let ir = Atlas::new(AtlasConfig {
//!     root: ".".into(),
//!     ..Default::default()
//! })
//! .build()?;
//!
//! let result = Prism::analyse(&ir, &Standard::default())?;
//! println!("score: {}", result.score.overall);
//! for f in &result.findings {
//!     println!("{:?} {} ({}:{})", f.severity, f.message, f.file.display(), f.line_start);
//! }
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! ## Layout
//!
//! - [`core`] re-exports the IR and the finding/score types every stage shares.
//! - [`Atlas`] parses a codebase into an [`Ir`].
//! - [`Prism`] runs the analyses and produces findings plus a [`Score`].
//! - [`Forge`] turns the safe findings into a fix plan (report-only).
//! - [`ai`] is the optional model-backed arbiter for ambiguous findings.

/// The shared IR and the finding, score, and duplicate types every stage
/// produces or consumes.
pub use verum_nucleus as core;

/// The optional AI arbiter. It speaks an OpenAI-compatible chat API and stays
/// inert unless an endpoint is configured; see [`ai::AiHandoff`].
pub use verum_arbiter as ai;

pub use verum_nucleus::{
    Call, CallTarget, DuplicateGroup, Finding, FindingKind, Ir, Language, Route, Score, Severity,
    Symbol, SymbolId, SymbolKind,
};

pub use verum_mappa::{Atlas, AtlasConfig};

pub use verum_lumen::{Prism, PrismResult, Standard};

pub use verum_faber::{Forge, ForgeConfig, ForgeResult};
