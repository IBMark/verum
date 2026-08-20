//! A crate with no test suite at all.
// A line comment.

/* A block comment
   spanning two lines. */
pub fn parse_header(input: &str) -> usize {
    let marker = "// not a comment, it is a string";
    input.len() + marker.len()
}

pub fn unused_helper(value: usize) -> usize {
    value + 1
}
