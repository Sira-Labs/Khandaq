//! Tests for the canonical finding model (spec 003).

use khandaq_core::{
    dedup, fingerprint, map_frameworks, navigator_layer, validate, Mappings, Severity,
};
use serde_json::{json, Value};

fn finding_json(
    tool: &str,
    rule: &str,
    severity: &str,
    target: &str,
    mappings: &[(&str, &str)],
    evidence: &[&str],
) -> Value {
    json!({
        "schema": "khandaq.finding/1",
        "engagement_id": "eng_1",
        "run_id": "run_1",
        "rule_id": rule,
        "severity": severity,
        "source": {"tool": tool, "version": "1.0"},
        "locations": [{"logicalLocations": [{"fullyQualifiedName": "endpoint"}]}],
        "target_ref": target,
        "x-khandaq": {
            "phase": "04-prompt-injection",
            "mappings": mappings.iter().map(|(f, i)| json!({"framework": f, "id": i})).collect::<Vec<_>>(),
            "evidence": evidence,
        }
    })
}

#[test]
fn validate_accepts_valid_and_rejects_malformed() {
    let good = finding_json(
        "garak",
        "garak.promptinject.hijack",
        "high",
        "tgt_1",
        &[("owasp-llm-2026", "LLM01")],
        &["ev_a"],
    );
    assert!(validate(&good).is_ok());

    // wrong schema id
    let mut bad = good.clone();
    bad["schema"] = json!("nope");
    assert!(validate(&bad).is_err());

    // unknown severity
    let mut bad2 = good.clone();
    bad2["severity"] = json!("spicy");
    assert!(validate(&bad2).is_err());

    // missing required field
    let mut bad3 = good.clone();
    bad3.as_object_mut().unwrap().remove("run_id");
    assert!(validate(&bad3).is_err());
}

#[test]
fn fingerprint_is_stable_and_order_insensitive() {
    let a = validate(&finding_json(
        "garak",
        "r1",
        "high",
        "tgt_1",
        &[("owasp-llm-2026", "LLM01"), ("atlas", "AML.T0051")],
        &[],
    ))
    .unwrap();
    // same identity, mappings listed in a different order
    let b = validate(&finding_json(
        "pyrit",
        "r2",
        "low",
        "tgt_1",
        &[("atlas", "AML.T0051"), ("owasp-llm-2026", "LLM01")],
        &[],
    ))
    .unwrap();
    assert_eq!(
        fingerprint(&a),
        fingerprint(&b),
        "same identity → same fingerprint"
    );

    // different target → different fingerprint
    let c = validate(&finding_json(
        "garak",
        "r1",
        "high",
        "tgt_2",
        &[("owasp-llm-2026", "LLM01"), ("atlas", "AML.T0051")],
        &[],
    ))
    .unwrap();
    assert_ne!(fingerprint(&a), fingerprint(&c));

    assert!(fingerprint(&a).starts_with("sha256:"));
}

#[test]
fn dedup_merges_cross_tool_and_keeps_all_evidence() {
    let f1 = validate(&finding_json(
        "garak",
        "garak.x",
        "medium",
        "tgt_1",
        &[("owasp-llm-2026", "LLM01")],
        &["ev_a"],
    ))
    .unwrap();
    let f2 = validate(&finding_json(
        "pyrit",
        "pyrit.y",
        "high",
        "tgt_1",
        &[("owasp-llm-2026", "LLM01")],
        &["ev_b"],
    ))
    .unwrap();
    // a genuinely different issue (different target)
    let f3 = validate(&finding_json(
        "garak",
        "garak.z",
        "low",
        "tgt_2",
        &[("owasp-llm-2026", "LLM02")],
        &["ev_c"],
    ))
    .unwrap();

    let result = dedup(vec![f1, f2, f3]);
    assert_eq!(result.canonical.len(), 2, "two distinct issues");
    assert_eq!(result.duplicates, 1, "one collapsed duplicate");

    let merged = result
        .canonical
        .iter()
        .find(|f| f.target_ref.as_deref() == Some("tgt_1"))
        .expect("merged finding");
    assert_eq!(merged.severity, "high", "canonical takes the max severity");
    assert_eq!(
        merged.x_khandaq.evidence,
        vec!["ev_a", "ev_b"],
        "evidence merged, nothing dropped"
    );
    assert!(
        merged
            .x_khandaq
            .also_found_by
            .contains(&"pyrit".to_string())
            || merged
                .x_khandaq
                .also_found_by
                .contains(&"garak".to_string())
    );
    assert_eq!(merged.canonical, Some(true));
}

#[test]
fn severity_ordering_and_max() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
    assert_eq!(Severity::parse("nope"), None);
}

#[test]
fn map_frameworks_known_and_unmapped() {
    let known = validate(&finding_json(
        "garak",
        "garak.promptinject.hijack",
        "high",
        "t",
        &[],
        &[],
    ))
    .unwrap();
    let m = Mappings::builtin();
    let ids: Vec<String> = map_frameworks(&known, &m)
        .iter()
        .map(|x| x.id.clone())
        .collect();
    assert!(ids.contains(&"LLM01".to_string()));
    assert!(ids.contains(&"AML.T0051".to_string()));

    let unknown = validate(&finding_json("x", "x.unheard-of", "low", "t", &[], &[])).unwrap();
    let um = map_frameworks(&unknown, &m);
    assert_eq!(um.len(), 1);
    assert_eq!(um[0].framework, "unmapped");
    assert_eq!(um[0].id, "x.unheard-of");
}

#[test]
fn navigator_layer_collects_atlas_techniques() {
    let f = validate(&finding_json(
        "garak",
        "r",
        "high",
        "t",
        &[("atlas", "AML.T0051"), ("owasp-llm-2026", "LLM01")],
        &[],
    ))
    .unwrap();
    let layer = navigator_layer(&[f]);
    assert_eq!(layer["domain"], "atlas");
    let techs = layer["techniques"].as_array().unwrap();
    assert_eq!(techs.len(), 1);
    assert_eq!(techs[0]["techniqueID"], "AML.T0051");
}

#[test]
fn published_schema_is_valid_json() {
    let schema: Value =
        serde_json::from_str(include_str!("../schema/finding.schema.json")).unwrap();
    assert_eq!(schema["properties"]["schema"]["const"], "khandaq.finding/1");
}
