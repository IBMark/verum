//! Shared plumbing for the parse targets.
//!
//! Every `verum-mappa` front-end takes a `&Path` and reads the file itself, so
//! a byte-oriented fuzz case has to reach disk somewhere. [`scratch_file`]
//! keeps that as cheap as it can be: one file per target process, in the
//! system temp dir (a tmpfs on the machines this runs on), rewritten in place
//! for every case rather than created and unlinked millions of times.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Write `bytes` into this process's scratch file and hand back its path.
///
/// `name` must be a filename the front-end under test will accept - the
/// extension decides the grammar for `javascript::parse_file`, and several
/// passes branch on path substrings.
pub fn scratch_file(name: &str, bytes: &[u8]) -> &'static Path {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    let path = PATH.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("verum-fuzz-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir is creatable");
        dir.join(name)
    });

    // `create` truncates, so the file never keeps a tail from a longer
    // previous case - which would make findings depend on case order.
    let mut file = std::fs::File::create(path).expect("scratch file is writable");
    file.write_all(bytes).expect("scratch file is writable");
    file.flush().expect("scratch file is writable");
    drop(file);

    path
}
