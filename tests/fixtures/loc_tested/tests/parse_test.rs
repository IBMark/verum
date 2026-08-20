// The suite reaches `parse_header` and nothing else.

#[test]
fn parses_a_header() {
    let width = parse_header("GET / HTTP/1.1");
    assert!(width > 0);
}
