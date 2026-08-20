//! Static test-reachability: which functions a test could reach at all.
//!
//! This is **reachability, not coverage**, and the distinction is the whole
//! point of the pass. Coverage is a measured fact - a runtime says this line
//! executed. Reachability is a static estimate: starting from every symbol
//! that is part of the test suite, walk the resolved call graph and mark
//! everything it can arrive at.
//!
//! It errs in both directions, and saying so is the point:
//!
//! * **Too generous** - a reachable function may never actually run, because
//!   the branch that would call it is never taken under test.
//! * **Too harsh** - only *resolved* call edges are followed, so a test that
//!   drives code through trait dispatch, generics or a derive macro leaves no
//!   edge for the walk to follow, and the code it exercises reads as
//!   unreached. Dispatch-heavy libraries score low for this reason alone.
//!
//! So the number is evidence, not a verdict: it says how much of a codebase a
//! test provably reaches by name. The list of files with **zero**
//! test-reachable functions is the part to act on. When ground truth matters,
//! feed Verum a real coverage file instead - see [`crate::lcov`].
//!
//! Roots are:
//!
//! * every function/method declared in a test file or directory, via
//!   [`crate::is_test_path`]; and
//! * Rust functions inside a test module - `#[cfg(test)] mod ...` or a module
//!   named `tests`, which is exactly the pair `verum-mappa`'s Rust parser
//!   already treats as test context, visible downstream as a `tests` segment
//!   in the symbol's fully-qualified name.
//!
//! The denominator is the shipped code: function-like symbols in files that
//! are not auxiliary ([`crate::is_auxiliary_path`] - tests, examples, vendored
//! and generated trees), minus the roots themselves. Counting a test as
//! covering itself would be circular, and counting vendored code the project
//! does not own would be noise.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use verum_nucleus::{CallTarget, Ir, Language, Symbol, SymbolId, SymbolKind};

use crate::loc::{relative_display, resolve_root};
use crate::{is_auxiliary_path, is_test_path};

/// Test-reachability for one shipped source file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FileReachability {
    /// Path relative to the analysed tree's root, `/`-separated.
    pub path: String,
    /// Function-like symbols declared in the file (excluding test roots).
    pub functions: u32,
    /// How many of them a test can reach through the resolved call graph.
    pub reachable: u32,
    /// `reachable / functions`, as a percentage rounded to one decimal.
    pub percent: f32,
}

/// Whole-tree test-reachability plus the per-file breakdown.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TestReachability {
    /// Symbols identified as part of the test suite. Zero means no tests were
    /// found at all - the case the score dimension must not flatter.
    pub test_roots: usize,
    /// Function-like symbols in shipped code.
    pub functions: usize,
    /// How many of them are reachable from a test root.
    pub reachable: usize,
    /// `reachable / functions`, as a percentage rounded to one decimal.
    pub percent: f32,
    /// Every shipped file that declares at least one function, ascending by
    /// path.
    pub files: Vec<FileReachability>,
    /// The headline honest signal: files that declare functions and where a
    /// test can reach *none* of them. Ascending by path.
    pub files_without_reachable_functions: Vec<String>,
}

/// A symbol that can be called, and so can be reached or left unreached.
/// Types, constants and properties are not executable on their own.
fn is_callable(kind: &SymbolKind) -> bool {
    matches!(
        kind,
        SymbolKind::Function | SymbolKind::Method | SymbolKind::StaticMethod
    )
}

/// True for a Rust symbol declared inside a test module - a module named
/// `test` or `tests`, which is where `#[cfg(test)]` code conventionally lives
/// and exactly what `verum-mappa`'s Rust parser already treats as test context
/// for dead-code purposes. The module path survives into the fully-qualified
/// name, so the test module is detectable here without re-parsing anything.
///
/// The last `::` segment is the symbol's own name and is never examined - a
/// production function called `test` is not a test.
fn is_rust_test_symbol(symbol: &Symbol) -> bool {
    if symbol.language != Language::Rust {
        return false;
    }
    let segments: Vec<&str> = symbol.fully_qualified.split("::").collect();
    let module_path = &segments[..segments.len().saturating_sub(1)];
    module_path
        .iter()
        .any(|seg| *seg == "tests" || *seg == "test")
}

/// Walk the resolved call graph from the test suite and report what it reaches.
///
/// Deterministic: the reachable *set* does not depend on traversal order, and
/// every emitted list is sorted by path before it is returned.
pub fn analyse(ir: &Ir, root: Option<&Path>) -> TestReachability {
    let root = resolve_root(ir, root);

    // One relative path per file, computed once - both the test check and the
    // auxiliary check run against the path relative to the analysed tree, so a
    // checkout that happens to live under `/srv/test/` is not mistaken for a
    // test tree.
    let mut relative: HashMap<&PathBuf, String> = HashMap::new();
    for path in ir.files.keys() {
        relative.insert(path, relative_display(path, &root));
    }
    let relative_of = |path: &PathBuf| -> String {
        match relative.get(path) {
            Some(rel) => rel.clone(),
            None => relative_display(path, &root),
        }
    };

    // Classify each file once rather than per symbol.
    let mut file_is_test: HashMap<String, bool> = HashMap::new();
    let mut file_is_auxiliary: HashMap<String, bool> = HashMap::new();
    for rel in relative.values() {
        file_is_test.insert(rel.clone(), is_test_path(rel));
        file_is_auxiliary.insert(rel.clone(), is_auxiliary_path(rel));
    }

    let mut roots: Vec<SymbolId> = Vec::new();
    // (symbol id, relative file path) for shipped, callable, non-test symbols.
    let mut shipped: Vec<(SymbolId, String)> = Vec::new();
    for (id, symbol) in &ir.symbols {
        if !is_callable(&symbol.kind) {
            continue;
        }
        let rel = relative_of(&symbol.file);
        let in_test_file = *file_is_test.get(&rel).unwrap_or(&is_test_path(&rel));
        if in_test_file || is_rust_test_symbol(symbol) {
            roots.push(*id);
            continue;
        }
        let auxiliary = *file_is_auxiliary
            .get(&rel)
            .unwrap_or(&is_auxiliary_path(&rel));
        if !auxiliary {
            shipped.push((*id, rel));
        }
    }
    roots.sort_by_key(|id| id.0);
    shipped.sort_by(|a, b| (&a.1, a.0 .0).cmp(&(&b.1, b.0 .0)));

    let reached = walk(ir, &roots);

    let mut per_file: Vec<FileReachability> = Vec::new();
    for (id, rel) in &shipped {
        if per_file.last().map(|f| &f.path) != Some(rel) {
            per_file.push(FileReachability {
                path: rel.clone(),
                ..Default::default()
            });
        }
        let entry = per_file.last_mut().expect("just pushed");
        entry.functions += 1;
        if reached.contains(id) {
            entry.reachable += 1;
        }
    }
    for file in &mut per_file {
        file.percent = percent(file.reachable as usize, file.functions as usize);
    }

    let functions = shipped.len();
    let reachable = shipped
        .iter()
        .filter(|(id, _)| reached.contains(id))
        .count();
    let files_without_reachable_functions = per_file
        .iter()
        .filter(|f| f.functions > 0 && f.reachable == 0)
        .map(|f| f.path.clone())
        .collect();

    TestReachability {
        test_roots: roots.len(),
        functions,
        reachable,
        percent: percent(reachable, functions),
        files: per_file,
        files_without_reachable_functions,
    }
}

/// Breadth-first walk of the resolved call edges from `roots`.
///
/// Only [`CallTarget::Resolved`] edges are followed: an unresolved or dynamic
/// callee names something the analyzer could not pin to a symbol, and guessing
/// would inflate reachability, which is precisely the dishonesty this pass
/// exists to remove.
fn walk(ir: &Ir, roots: &[SymbolId]) -> HashSet<SymbolId> {
    let mut edges: HashMap<SymbolId, Vec<SymbolId>> = HashMap::new();
    for call in &ir.calls {
        if let CallTarget::Resolved(callee) = call.callee {
            edges.entry(call.caller).or_default().push(callee);
        }
    }

    let mut seen: HashSet<SymbolId> = roots.iter().copied().collect();
    let mut queue: VecDeque<SymbolId> = roots.iter().copied().collect();
    while let Some(current) = queue.pop_front() {
        let Some(callees) = edges.get(&current) else {
            continue;
        };
        for callee in callees {
            if seen.insert(*callee) {
                queue.push_back(*callee);
            }
        }
    }
    seen
}

/// `hit / total` as a percentage rounded to one decimal place. Zero out of
/// zero is 0.0: an empty file has nothing tested about it.
pub(crate) fn percent(hit: usize, total: usize) -> f32 {
    if total == 0 {
        return 0.0;
    }
    ((hit as f32 / total as f32) * 1000.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use verum_nucleus::{Call, FileId, FileInfo, Visibility};

    struct Builder {
        ir: Ir,
        next: u64,
    }

    impl Builder {
        fn new() -> Self {
            Self {
                ir: Ir::new(),
                next: 0,
            }
        }

        fn file(&mut self, path: &str) {
            let id = FileId(self.ir.files.len() as u64 + 1);
            self.ir.files.insert(
                PathBuf::from(path),
                FileInfo {
                    id,
                    path: PathBuf::from(path),
                    language: Language::Rust,
                    line_count: 10,
                    size_bytes: 100,
                    last_modified: 0,
                    hash: 0,
                    symbols: Vec::new(),
                },
            );
        }

        fn func(&mut self, file: &str, fq: &str) -> SymbolId {
            if !self.ir.files.contains_key(Path::new(file)) {
                self.file(file);
            }
            self.next += 1;
            let id = SymbolId(self.next);
            let name = fq.rsplit("::").next().unwrap_or(fq).to_string();
            self.ir.symbols.insert(
                id,
                Symbol {
                    id,
                    name,
                    fully_qualified: fq.to_string(),
                    kind: SymbolKind::Function,
                    visibility: Visibility::Public,
                    file: PathBuf::from(file),
                    line_start: 1,
                    line_end: 2,
                    col_start: 0,
                    col_end: 0,
                    language: Language::Rust,
                    parent: None,
                    hash: 0,
                    normalized_hash: 0,
                    flow_hash: 0,
                    param_count: 0,
                    is_entry_point: false,
                    doc_comment: None,
                },
            );
            id
        }

        fn call(&mut self, caller: SymbolId, callee: SymbolId) {
            self.ir.calls.push(Call {
                caller,
                callee: CallTarget::Resolved(callee),
                file: PathBuf::from("/repo/tests/suite.rs"),
                line: 1,
                col: 0,
            });
        }
    }

    /// A tree with one tested helper, one untested helper, and a file nothing
    /// reaches. `/repo` is the common root of every path.
    fn fixture() -> Ir {
        let mut b = Builder::new();
        let test = b.func("/repo/tests/suite.rs", "checks_helper");
        let used = b.func("/repo/src/lib.rs", "used_helper");
        let _unused = b.func("/repo/src/lib.rs", "unused_helper");
        let _orphan = b.func("/repo/src/orphan.rs", "never_called");
        b.call(test, used);
        b.ir
    }

    #[test]
    fn a_helper_called_only_from_a_test_is_reachable() {
        let report = analyse(&fixture(), Some(Path::new("/repo")));
        assert_eq!(report.test_roots, 1);
        assert_eq!(report.functions, 3, "the test itself is not in the total");
        assert_eq!(report.reachable, 1);
        let lib = report
            .files
            .iter()
            .find(|f| f.path == "src/lib.rs")
            .expect("src/lib.rs is reported");
        assert_eq!((lib.functions, lib.reachable), (2, 1));
        assert_eq!(lib.percent, 50.0);
    }

    #[test]
    fn an_uncalled_helper_is_not_reachable() {
        let report = analyse(&fixture(), Some(Path::new("/repo")));
        assert_eq!(
            report.files_without_reachable_functions,
            vec!["src/orphan.rs".to_string()],
            "the file no test can reach is named"
        );
        assert!(
            report.percent > 33.0 && report.percent < 33.4,
            "1 of 3, got {}",
            report.percent
        );
    }

    #[test]
    fn reachability_is_transitive() {
        let mut b = Builder::new();
        let test = b.func("/repo/tests/suite.rs", "checks");
        let a = b.func("/repo/src/lib.rs", "a");
        let c = b.func("/repo/src/lib.rs", "c");
        b.call(test, a);
        b.call(a, c);
        let report = analyse(&b.ir, Some(Path::new("/repo")));
        assert_eq!(report.reachable, 2, "a and the c it calls");
    }

    #[test]
    fn a_repo_with_no_tests_reaches_nothing() {
        let mut b = Builder::new();
        b.func("/repo/src/lib.rs", "a");
        b.func("/repo/src/lib.rs", "b");
        let report = analyse(&b.ir, Some(Path::new("/repo")));
        assert_eq!(report.test_roots, 0);
        assert_eq!((report.functions, report.reachable), (2, 0));
        assert_eq!(report.percent, 0.0);
        assert_eq!(report.files_without_reachable_functions, vec!["src/lib.rs"]);
    }

    #[test]
    fn rust_inline_test_modules_are_roots_not_denominator() {
        // `#[cfg(test)] mod tests` lives in the source file itself; counting
        // its functions as untested shipped code would punish the very repos
        // that test the most.
        let mut b = Builder::new();
        let test = b.func("/repo/src/lib.rs", "tests::checks_helper");
        let used = b.func("/repo/src/lib.rs", "used_helper");
        b.call(test, used);
        let report = analyse(&b.ir, Some(Path::new("/repo")));
        assert_eq!(report.test_roots, 1);
        assert_eq!((report.functions, report.reachable), (1, 1));
        assert_eq!(report.percent, 100.0);
    }

    #[test]
    fn a_function_named_test_is_not_a_test() {
        let mut b = Builder::new();
        b.func("/repo/src/lib.rs", "helpers::test");
        let report = analyse(&b.ir, Some(Path::new("/repo")));
        assert_eq!(report.test_roots, 0);
        assert_eq!(report.functions, 1);
    }

    #[test]
    fn unresolved_calls_do_not_grant_reachability() {
        let mut b = Builder::new();
        let test = b.func("/repo/tests/suite.rs", "checks");
        b.func("/repo/src/lib.rs", "maybe_called");
        b.ir.calls.push(Call {
            caller: test,
            callee: CallTarget::Unresolved("maybe_called".into()),
            file: PathBuf::from("/repo/tests/suite.rs"),
            line: 1,
            col: 0,
        });
        let report = analyse(&b.ir, Some(Path::new("/repo")));
        assert_eq!(report.reachable, 0, "a guess is not reachability");
    }

    #[test]
    fn vendored_code_is_outside_the_denominator() {
        let mut b = Builder::new();
        b.func("/repo/src/lib.rs", "mine");
        b.func("/repo/node_modules/dep/index.rs", "theirs");
        let report = analyse(&b.ir, Some(Path::new("/repo")));
        assert_eq!(report.functions, 1, "only first-party code is counted");
    }

    #[test]
    fn output_is_sorted_and_repeatable() {
        let ir = fixture();
        let first = analyse(&ir, Some(Path::new("/repo")));
        let second = analyse(&ir, Some(Path::new("/repo")));
        assert_eq!(first, second);
        let paths: Vec<&String> = first.files.iter().map(|f| &f.path).collect();
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted);
    }
}
