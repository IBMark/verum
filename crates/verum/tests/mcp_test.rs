//! End-to-end MCP session over stdio against the php_simple fixture.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn fixture_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/php_simple")
}

/// Spawn the just-built `verum` binary, retrying on ETXTBSY: on CI another
/// process can transiently hold the freshly linked executable open for
/// writing, which makes exec fail with "text file busy".
fn spawn_verum_mcp() -> std::process::Child {
    let mut attempts = 0u32;
    loop {
        let spawned = Command::new(env!("CARGO_BIN_EXE_verum"))
            .arg("mcp")
            .arg(fixture_path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        match spawned {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 50 => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            other => return other.expect("spawn verum mcp"),
        }
    }
}

#[test]
fn mcp_session_answers_fact_queries() {
    let mut child = spawn_verum_mcp();

    let mut stdin = child.stdin.take().unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05"}}}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
    )
    .unwrap();
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}"#).unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"find_symbol","arguments":{{"query":"UserHelper"}}}}}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"dead_code","arguments":{{}}}}}}"#
    )
    .unwrap();
    // Closing stdin ends the session loop.
    drop(stdin);

    let reader = BufReader::new(child.stdout.take().unwrap());
    let responses: Vec<serde_json::Value> = reader
        .lines()
        .map(|l| serde_json::from_str(&l.unwrap()).expect("every stdout line is JSON-RPC"))
        .collect();
    child.wait().unwrap();

    assert_eq!(
        responses.len(),
        4,
        "one response per request, none for the notification"
    );

    let by_id = |id: u64| {
        responses
            .iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("no response with id {id}"))
    };

    assert_eq!(by_id(1)["result"]["serverInfo"]["name"], "verum-mcp");

    let tools: Vec<&str> = by_id(2)["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for expected in [
        "overview",
        "definition_of",
        "references_of",
        "callers_of",
        "impact_of",
        "dead_code",
        "audit_delta",
    ] {
        assert!(
            tools.contains(&expected),
            "missing tool {expected}, got {tools:?}"
        );
    }

    let found: serde_json::Value =
        serde_json::from_str(by_id(3)["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(
        found["symbols"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["name"] == "UserHelper"),
        "find_symbol should locate UserHelper"
    );

    let dead: serde_json::Value =
        serde_json::from_str(by_id(4)["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let dead_names: Vec<String> = dead["dead"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["message"].as_str().unwrap().to_string())
        .collect();
    assert!(
        dead_names.iter().any(|m| m.contains("legacyFormat")),
        "legacyFormat is the fixture's known dead function, got {dead_names:?}"
    );
}
