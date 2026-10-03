//! Tests for the canonical finding model (spec 003).

use khandaq_core::{
    dedup as dedup_builtin, dedup_with, fingerprint, fingerprint_with, map_frameworks,
    merge_mappings, navigator_layer, validate, DedupResult, Equivalence, Finding, Mappings,
    Severity,
};
use serde_json::{json, Value};

/// The rules these tests treat as one weakness across tools. Since ADR-0013 framework mappings
/// are not identity: tools merge only through an explicit equivalence table.
fn equivalence() -> Equivalence {
    Equivalence::new([
        ("garak.rule", "prompt-injection/direct"),
        ("pyrit.rule", "prompt-injection/direct"),
        ("promptfoo.rule", "prompt-injection/direct"),
        ("garak.x", "prompt-injection/direct"),
        ("pyrit.y", "prompt-injection/direct"),
    ])
}

fn dedup(findings: Vec<Finding>) -> DedupResult {
    dedup_with(findings, &equivalence())
}

fn finding_json(
    tool: &str,
    rule: &str,
    severity: &str,
    target: &str,
    mappings: &[(&str, &str)],
    evidence: &[&str],
) -> Value {
    json!({
        "schema": "khandaq.finding/2",
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
    // same rule, target and location; tool, severity and mappings differ
    let b = validate(&finding_json(
        "garak",
        "r1",
        "low",
        "tgt_1",
        &[("atlas", "AML.T0051")],
        &["ev_b"],
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

fn ids(ms: &[khandaq_core::Mapping]) -> Vec<(String, String)> {
    ms.iter()
        .map(|m| (m.framework.clone(), m.id.clone()))
        .collect()
}

#[test]
fn the_builtin_table_names_a_version_and_source_per_framework() {
    let m = Mappings::builtin();
    for fw in ["atlas", "owasp-llm-2025", "owasp-llm-2026", "nist-ai-rmf"] {
        assert!(m.versions().contains_key(fw), "{fw} has no version");
        assert!(
            m.sources()[fw].starts_with("https://"),
            "{fw} has no source"
        );
    }
    // A framework used without a version, a wrong schema, or an empty rule is refused.
    let table = |versions: &str, rules: &str| {
        format!(
            r#"{{"schema":"khandaq.mappings/1","versions":{versions},"sources":{{"atlas":"https://x"}},"rules":{rules}}}"#
        )
    };
    let rule = r#"{"r":{"mappings":[{"framework":"atlas","id":"AML.T0051"}],"rationale":"x"}}"#;
    assert!(Mappings::from_json(&table(r#"{"atlas":"1"}"#, rule)).is_ok());
    assert!(Mappings::from_json(&table("{}", rule)).is_err());
    assert!(Mappings::from_json(&table(
        r#"{"atlas":"1"}"#,
        r#"{"r":{"mappings":[],"rationale":"x"}}"#
    ))
    .is_err());
    assert!(Mappings::from_json(&table(
        r#"{"atlas":"1"}"#,
        r#"{"r.":{"mappings":[{"framework":"atlas","id":"A"}],"rationale":"x"}}"#
    ))
    .is_err());
    assert!(Mappings::from_json(
        &table(r#"{"atlas":"1"}"#, rule).replace("mappings/1", "mappings/9")
    )
    .is_err());
}

#[test]
fn longest_prefix_on_a_boundary() {
    let m = Mappings::builtin();
    let atlas = |rule: &str| {
        m.for_rule(rule).map(|ms| {
            ms.iter()
                .filter(|x| x.framework == "atlas")
                .map(|x| x.id.clone())
                .collect::<Vec<_>>()
        })
    };
    // A family probe uses the family entry; a colon boundary counts too.
    assert_eq!(
        atlas("garak.promptinject.hijackhatehumansmini"),
        Some(vec!["AML.T0051".into()])
    );
    assert_eq!(
        atlas("promptfoo.harmful:hate"),
        Some(vec!["AML.T0048".into()])
    );
    // The longest key wins over the tool default.
    assert_eq!(atlas("pyrit.crescendo"), Some(vec!["AML.T0054".into()]));
    assert_eq!(atlas("pyrit.something_new"), Some(vec!["AML.T0051".into()]));
    // A non-boundary prefix does not match, and garak has no default.
    assert_eq!(m.for_rule("garak.promptinjectx"), None);
    assert_eq!(m.for_rule("garak.unknownprobe"), None);
    assert_eq!(m.for_rule(""), None);
}

#[test]
fn merge_keeps_adapter_ids_and_adds_the_table() {
    let f = validate(&finding_json(
        "echo",
        "echo.inject",
        "medium",
        "t",
        &[("atlas", "AML.T0051"), ("custom", "X-1")],
        &[],
    ))
    .unwrap();
    let merged = ids(&merge_mappings(&f, &Mappings::builtin()));
    assert!(merged.contains(&("custom".into(), "X-1".into())));
    assert!(merged.contains(&("nist-ai-rmf".into(), "MEASURE-2.7".into())));
    assert!(merged.contains(&("owasp-llm-2025".into(), "LLM01".into())));
    assert_eq!(
        merged
            .iter()
            .filter(|(fw, id)| fw == "atlas" && id == "AML.T0051")
            .count(),
        1
    );
    let mut sorted = merged.clone();
    sorted.sort();
    assert_eq!(merged, sorted);
}

#[test]
fn merge_marks_unmapped_only_when_both_are_empty() {
    let m = Mappings::builtin();
    let bare = validate(&finding_json("x", "x.unheard-of", "low", "t", &[], &[])).unwrap();
    assert_eq!(
        ids(&merge_mappings(&bare, &m)),
        vec![("unmapped".into(), "x.unheard-of".into())]
    );
    let tool_only = validate(&finding_json(
        "x",
        "x.unheard-of",
        "low",
        "t",
        &[("atlas", "AML.T0051")],
        &[],
    ))
    .unwrap();
    assert_eq!(
        ids(&merge_mappings(&tool_only, &m)),
        vec![("atlas".into(), "AML.T0051".into())]
    );
    // Merging twice is stable: an earlier marker does not survive next to real ids.
    let mut again = bare.clone();
    again.x_khandaq.mappings = merge_mappings(&bare, &m);
    assert_eq!(merge_mappings(&again, &m), merge_mappings(&bare, &m));
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
    assert_eq!(
        schema["properties"]["schema"]["enum"],
        json!(["khandaq.finding/2", "khandaq.finding/1"])
    );
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

// --- review on #26: total determinism and no data loss in merges ---------------------------------

#[test]
fn members_that_agree_on_every_named_field_still_pick_one_canonical() {
    let mut a = llm01("garak", "high");
    a["message"] = json!({"text": "first"});
    let mut b = llm01("garak", "high");
    b["message"] = json!({"text": "second"});
    let (a, b) = (validate(&a).unwrap(), validate(&b).unwrap());
    let one = dedup(vec![a.clone(), b.clone()]);
    let two = dedup(vec![b, a]);
    assert_eq!(one.canonical, two.canonical);
}

#[test]
fn groups_come_out_in_the_same_order_whatever_the_input_order() {
    let a = validate(&llm01("garak", "high")).unwrap();
    let mut other = llm01("pyrit", "low");
    other["target_ref"] = json!("tgt_2"); // a different fingerprint
    let b = validate(&other).unwrap();
    let one = dedup(vec![a.clone(), b.clone()]);
    let two = dedup(vec![b, a]);
    assert_eq!(one.canonical.len(), 2);
    assert_eq!(one.canonical, two.canonical);
}

#[test]
fn unnamed_fields_survive_from_every_merged_member() {
    let mut a = llm01("garak", "high");
    a["message"] = json!({"text": "from garak"});
    a["x-khandaq"]["probe_detail"] = json!("garak only");
    let mut b = llm01("pyrit", "medium");
    b["message"] = json!({"text": "from pyrit"});
    b["properties"] = json!({"tags": ["pyrit only"]});
    b["x-khandaq"]["conversation"] = json!("pyrit only");
    let out = dedup(vec![validate(&b).unwrap(), validate(&a).unwrap()]);
    let canon = serde_json::to_value(&out.canonical[0]).unwrap();
    assert_eq!(canon["source"]["tool"], "garak"); // the higher severity
    assert_eq!(canon["message"]["text"], "from garak"); // a conflict: the canonical member wins
    assert_eq!(canon["properties"]["tags"][0], "pyrit only"); // a gap: filled from the other
    assert_eq!(canon["x-khandaq"]["probe_detail"], "garak only");
    assert_eq!(canon["x-khandaq"]["conversation"], "pyrit only");
}

#[test]
fn sources_that_differ_only_in_unnamed_fields_are_both_kept() {
    let mut a = llm01("garak", "high");
    a["source"]["informationUri"] = json!("https://example.test/a");
    let mut b = llm01("garak", "high");
    b["source"]["informationUri"] = json!("https://example.test/b");
    b["run_id"] = json!("run_2");
    let out = dedup(vec![validate(&a).unwrap(), validate(&b).unwrap()]);
    let uris: Vec<_> = out.canonical[0]
        .x_khandaq
        .sources
        .iter()
        .map(|s| s.extra["informationUri"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(uris, ["https://example.test/a", "https://example.test/b"]);
}

#[test]
fn schema_types_the_sources_items_like_the_validator() {
    let schema: Value =
        serde_json::from_str(include_str!("../schema/finding.schema.json")).unwrap();
    let item = &schema["properties"]["x-khandaq"]["properties"]["sources"]["items"];
    for field in ["tool", "version", "native_severity"] {
        assert_eq!(item["properties"][field]["type"], "string", "{field}");
    }
    assert_eq!(item["required"], json!(["tool", "version"]));
}

// --- fingerprint v2 (ADR-0013) -------------------------------------------------------------------

fn rule_finding(tool: &str, rule: &str, mappings: &[(&str, &str)]) -> Finding {
    validate(&finding_json(tool, rule, "high", "tgt_1", mappings, &[])).unwrap()
}

#[test]
fn a_mapping_edit_does_not_change_the_fingerprint() {
    // Curation adds an OWASP 2025 id and an ATLAS technique: the same issue keeps its identity,
    // so its triage state and cross-run dedup survive the edit.
    let before = rule_finding(
        "garak",
        "garak.promptinject.hijack",
        &[("owasp-llm-2026", "LLM01")],
    );
    let after = rule_finding(
        "garak",
        "garak.promptinject.hijack",
        &[
            ("owasp-llm-2025", "LLM01"),
            ("owasp-llm-2026", "LLM01"),
            ("atlas", "AML.T0051"),
        ],
    );
    let unmapped = rule_finding("garak", "garak.promptinject.hijack", &[]);
    assert_eq!(fingerprint(&before), fingerprint(&after));
    assert_eq!(fingerprint(&before), fingerprint(&unmapped));
}

#[test]
fn distinct_rules_with_the_same_mappings_stay_distinct() {
    // Under v1 these collapsed into one finding and dedup kept only one rule_id.
    let a = rule_finding(
        "garak",
        "garak.promptinject.hijack",
        &[("owasp-llm-2026", "LLM01")],
    );
    let b = rule_finding("garak", "garak.dan.dan_11", &[("owasp-llm-2026", "LLM01")]);
    assert_ne!(fingerprint(&a), fingerprint(&b));
    assert_eq!(dedup_builtin(vec![a, b]).canonical.len(), 2);
}

#[test]
fn tools_merge_only_through_the_equivalence_table_and_an_equal_location() {
    let garak = rule_finding(
        "garak",
        "garak.promptinject.hijack",
        &[("owasp-llm-2026", "LLM01")],
    );
    let pyrit = rule_finding(
        "pyrit",
        "pyrit.prompt_injection",
        &[("owasp-llm-2026", "LLM01")],
    );
    // Equal mappings alone are not identity.
    assert_ne!(fingerprint(&garak), fingerprint(&pyrit));

    let table = Equivalence::new([
        ("garak.promptinject.*", "prompt-injection/direct"),
        ("pyrit.prompt_injection", "prompt-injection/direct"),
    ]);
    assert_eq!(
        fingerprint_with(&garak, &table),
        fingerprint_with(&pyrit, &table)
    );
    let merged = dedup_with(vec![garak.clone(), pyrit.clone()], &table);
    assert_eq!(merged.canonical.len(), 1);
    assert_eq!(merged.canonical[0].x_khandaq.also_found_by, ["pyrit"]);

    // The same weakness at a different location is a different finding.
    let mut elsewhere = pyrit;
    elsewhere.locations = vec![json!({"logicalLocations": [{"fullyQualifiedName": "other"}]})];
    assert_ne!(
        fingerprint_with(&garak, &table),
        fingerprint_with(&elsewhere, &table)
    );
}

#[test]
fn a_weakness_key_never_equals_a_rule_identity() {
    // A table entry naming weakness "x" must not collide with a finding whose rule id is "x".
    let table = Equivalence::new([("tool.a", "tool.b")]);
    let a = rule_finding("tool", "tool.a", &[]);
    let b = rule_finding("tool", "tool.b", &[]);
    assert_ne!(fingerprint_with(&a, &table), fingerprint_with(&b, &table));
}

#[test]
fn the_longest_prefix_wins_and_exact_ids_beat_prefixes() {
    let table = Equivalence::new([
        ("garak.*", "generic"),
        ("garak.promptinject.*", "prompt-injection/direct"),
        ("garak.promptinject.special", "special"),
    ]);
    assert_eq!(
        table.weakness_for("garak.promptinject.hijack"),
        Some("prompt-injection/direct")
    );
    assert_eq!(
        table.weakness_for("garak.promptinject.special"),
        Some("special")
    );
    assert_eq!(table.weakness_for("garak.dan.dan_11"), Some("generic"));
    // A prefix matches only at a '.' boundary, and "garak" alone is not under "garak.*".
    assert_eq!(table.weakness_for("garakx.y"), None);
    assert_eq!(table.weakness_for("garak"), None);
}

#[test]
fn the_v2_recipe_is_pinned() {
    // A change to this value is a fingerprint recipe change: it needs a schema version bump and a
    // migration of stored fingerprints (ADR-0003, ADR-0013), never a silent edit.
    let f = rule_finding(
        "garak",
        "garak.promptinject.hijack",
        &[("atlas", "AML.T0051")],
    );
    assert_eq!(fingerprint(&f), PINNED_V2);
}

// Recomputed independently: sha256 over the sorted-key, compact JSON
// {"location":"[{\"logicalLocations\":…}]","target":"tgt_1","v":2,"weakness":"rule:garak.promptinject.hijack"}.
const PINNED_V2: &str = "sha256:cc007ab8ff7e70ce133ae606147250fb80061545f1afb8be66dd45aa693ca1e0";

#[test]
fn v1_records_validate_and_come_out_of_dedup_as_v2() {
    let mut v1 = finding_json("garak", "garak.x", "high", "tgt_1", &[], &[]);
    v1["schema"] = json!("khandaq.finding/1");
    let parsed = validate(&v1).unwrap();
    let out = dedup_builtin(vec![parsed]);
    assert_eq!(out.canonical[0].schema, "khandaq.finding/2");
    let mut v3 = v1.clone();
    v3["schema"] = json!("khandaq.finding/3");
    assert!(validate(&v3).is_err());
}

#[test]
fn the_builtin_equivalence_table_loads() {
    // An unknown rule falls back to its own identity.
    assert_eq!(Equivalence::builtin().weakness_for("no.such.rule"), None);
}
