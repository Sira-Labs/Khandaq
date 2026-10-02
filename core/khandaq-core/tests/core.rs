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

// --- hardening (code review, 2026-10-02) -----------------------------------------------------

fn llm01(tool: &str, severity: &str) -> Value {
    finding_json(
        tool,
        &format!("{tool}.rule"),
        severity,
        "tgt_1",
        &[("owasp-llm-2026", "LLM01"), ("atlas", "AML.T0051")],
        &[],
    )
}

#[test]
fn unknown_fields_survive_validation_and_dedup() {
    // The finding is a SARIF superset: tool data the model does not name must not be dropped.
    let mut f = llm01("garak", "high");
    f["message"] = json!({"text": "model followed the injected instruction"});
    f["properties"] = json!({"tags": ["jailbreak"]});
    f["source"]["informationUri"] = json!("https://github.com/NVIDIA/garak");
    f["x-khandaq"]["probe_detail"] = json!({"detector": "AttackRogueString"});
    let parsed = validate(&f).unwrap();
    let back = serde_json::to_value(&parsed).unwrap();
    assert_eq!(back["message"], f["message"]);
    assert_eq!(back["properties"], f["properties"]);
    assert_eq!(
        back["source"]["informationUri"],
        f["source"]["informationUri"]
    );
    assert_eq!(
        back["x-khandaq"]["probe_detail"],
        f["x-khandaq"]["probe_detail"]
    );

    let out = dedup(vec![parsed]);
    let canon = serde_json::to_value(&out.canonical[0]).unwrap();
    assert_eq!(canon["message"], f["message"]);
}

#[test]
fn severity_must_be_canonical_lowercase() {
    // "HIGH" used to validate and be stored as "HIGH", which no filter or sort matches.
    for bad in ["HIGH", "High", " high"] {
        assert!(validate(&llm01("garak", bad)).is_err(), "{bad}");
    }
    assert!(validate(&llm01("garak", "high")).is_ok());
}

#[test]
fn locations_must_be_objects() {
    for bad in [json!(["endpoint"]), json!([1]), json!([null]), json!([[]])] {
        let mut f = llm01("garak", "high");
        f["locations"] = bad.clone();
        assert!(validate(&f).is_err(), "{bad}");
    }
}

#[test]
fn dedup_does_not_depend_on_input_order() {
    let a = validate(&llm01("pyrit", "high")).unwrap();
    let b = validate(&llm01("garak", "high")).unwrap();
    let c = validate(&llm01("promptfoo", "medium")).unwrap();
    let one = dedup(vec![a.clone(), b.clone(), c.clone()]);
    let two = dedup(vec![c, b, a]);
    assert_eq!(one.canonical.len(), 1);
    assert_eq!(one.canonical, two.canonical);
    // Tied on severity, the stable tie-break picks the lexically first tool.
    assert_eq!(one.canonical[0].source.tool, "garak");
    assert_eq!(
        one.canonical[0].x_khandaq.also_found_by,
        ["promptfoo", "pyrit"]
    );
}

#[test]
fn dedup_keeps_every_native_severity() {
    let mut a = llm01("garak", "high");
    a["source"]["native_severity"] = json!("fail_rate>=0.5");
    let mut b = llm01("promptfoo", "medium");
    b["source"]["native_severity"] = json!("medium");
    let out = dedup(vec![validate(&a).unwrap(), validate(&b).unwrap()]);
    let sources = &out.canonical[0].x_khandaq.sources;
    let natives: Vec<_> = sources
        .iter()
        .map(|s| (s.tool.as_str(), s.native_severity.as_deref()))
        .collect();
    assert_eq!(
        natives,
        [
            ("garak", Some("fail_rate>=0.5")),
            ("promptfoo", Some("medium"))
        ]
    );
    // A lone finding carries no redundant per-tool breakdown.
    let lone = dedup(vec![validate(&a).unwrap()]);
    assert!(lone.canonical[0].x_khandaq.sources.is_empty());
}

#[test]
fn re_dedup_unions_also_found_by_and_sources() {
    // Deduplicating an already-merged canonical with a new finding must keep earlier tools.
    let first = dedup(vec![
        validate(&llm01("garak", "high")).unwrap(),
        validate(&llm01("pyrit", "high")).unwrap(),
    ]);
    let merged = first.canonical[0].clone();
    let again = dedup(vec![merged, validate(&llm01("promptfoo", "low")).unwrap()]);
    let canon = &again.canonical[0];
    assert_eq!(canon.source.tool, "garak");
    assert_eq!(canon.x_khandaq.also_found_by, ["promptfoo", "pyrit"]);
    let tools: Vec<_> = canon
        .x_khandaq
        .sources
        .iter()
        .map(|s| s.tool.as_str())
        .collect();
    assert_eq!(tools, ["garak", "promptfoo", "pyrit"]);
}

#[test]
fn navigator_counts_each_technique_once_per_finding() {
    let mut f = llm01("garak", "high");
    f["x-khandaq"]["mappings"] = json!([
        {"framework": "atlas", "id": "AML.T0051"},
        {"framework": "atlas", "id": "aml.t0051"},
        {"framework": "ATLAS", "id": "AML.T0051"},
        {"framework": "atlas", "id": "AML.T0054"},
    ]);
    let g = llm01("pyrit", "high");
    let layer = navigator_layer(&[validate(&f).unwrap(), validate(&g).unwrap()]);
    let techniques: Vec<_> = layer["techniques"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| {
            (
                t["techniqueID"].as_str().unwrap().to_string(),
                t["score"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        techniques,
        [("AML.T0051".to_string(), 2), ("AML.T0054".to_string(), 1)]
    );
}
