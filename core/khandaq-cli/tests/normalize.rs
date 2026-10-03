//! `khandaq-core normalize` (spec 020): every finding leaves with its own mappings plus the built-in
//! table's, or the explicit `unmapped` marker.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};

fn finding(rule: &str, mappings: Value) -> Value {
    json!({
        "schema": "khandaq.finding/2",
        "engagement_id": "eng_1",
        "run_id": "run_1",
        "rule_id": rule,
        "severity": "high",
        "source": {"tool": "garak", "version": "1.0"},
        "target_ref": "tgt_1",
        "locations": [{"logicalLocations": [{"fullyQualifiedName": rule}]}],
        "x-khandaq": {"phase": "04-prompt-injection", "mappings": mappings, "evidence": []},
    })
}

#[test]
fn normalize_merges_the_table_into_every_finding() {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("normalize-{}.json", std::process::id()));
    let input = json!([
        finding(
            "garak.dan.dan_11_0",
            json!([{"framework": "custom", "id": "X-1"}])
        ),
        finding("nobody.mapped.this", json!([])),
    ]);
    std::fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_khandaq-core"))
        .arg("normalize")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    let by_rule = |rule: &str| -> Vec<(String, String)> {
        let f = result["canonical"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["rule_id"] == rule)
            .unwrap();
        f["x-khandaq"]["mappings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| {
                (
                    m["framework"].as_str().unwrap().to_string(),
                    m["id"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    let dan = by_rule("garak.dan.dan_11_0");
    assert!(dan.contains(&("custom".into(), "X-1".into())));
    assert!(dan.contains(&("atlas".into(), "AML.T0054".into())));
    assert_eq!(
        by_rule("nobody.mapped.this"),
        vec![("unmapped".into(), "nobody.mapped.this".into())]
    );
}
