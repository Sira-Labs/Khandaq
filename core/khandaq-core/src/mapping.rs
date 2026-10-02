//! Framework cross-walk tables and the MITRE ATLAS Navigator export (ADR-0012).
//!
//! Mappings are versioned data (`mappings/builtin.json`), embedded at build time. A finding records
//! every applicable framework id across ATLAS, OWASP LLM (2025 and 2026), OWASP Agentic and NIST. A
//! rule with no mapping yields an explicit `unmapped` marker so curation gaps are visible, not silent.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::finding::{Finding, Mapping};

const BUILTIN: &str = include_str!("../mappings/builtin.json");

#[derive(Debug, Deserialize)]
struct RawMappings {
    rules: HashMap<String, Vec<Mapping>>,
}

/// The loaded cross-walk tables.
#[derive(Debug, Clone)]
pub struct Mappings {
    table: HashMap<String, Vec<Mapping>>,
}

impl Mappings {
    /// Load the built-in (embedded) mapping tables.
    pub fn builtin() -> Self {
        let raw: RawMappings =
            serde_json::from_str(BUILTIN).expect("builtin mappings are valid JSON");
        Mappings { table: raw.rules }
    }

    pub fn for_rule(&self, rule_id: &str) -> Option<&Vec<Mapping>> {
        self.table.get(rule_id)
    }
}

impl Default for Mappings {
    fn default() -> Self {
        Self::builtin()
    }
}

/// Return every framework id for a finding's rule, or a single `unmapped` marker if none is known.
pub fn map_frameworks(finding: &Finding, mappings: &Mappings) -> Vec<Mapping> {
    match mappings.for_rule(&finding.rule_id) {
        Some(found) if !found.is_empty() => found.clone(),
        _ => vec![Mapping {
            framework: "unmapped".to_string(),
            id: finding.rule_id.clone(),
        }],
    }
}

/// Build a MITRE ATLAS Navigator layer from the ATLAS techniques referenced by the findings.
///
/// A technique's score is the number of **findings** that reference it: a finding listing the same
/// technique twice (or as `aml.t0051` and `AML.T0051`) counts once. ATLAS ids are upper-cased, the
/// form the Navigator matches on, and the framework name is matched case-insensitively.
pub fn navigator_layer(findings: &[Finding]) -> Value {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings {
        let techniques: BTreeSet<String> = f
            .x_khandaq
            .mappings
            .iter()
            .filter(|m| m.framework.trim().eq_ignore_ascii_case("atlas"))
            .map(|m| m.id.trim().to_ascii_uppercase())
            .filter(|id| !id.is_empty())
            .collect();
        for id in techniques {
            *counts.entry(id).or_insert(0) += 1;
        }
    }
    let techniques: Vec<Value> = counts
        .into_iter()
        .map(|(id, score)| json!({"techniqueID": id, "score": score, "enabled": true}))
        .collect();

    json!({
        "name": "Khandaq findings",
        "versions": {"layer": "4.5", "navigator": "4.9", "attack": "atlas"},
        "domain": "atlas",
        "description": "ATLAS techniques observed in this engagement's findings.",
        "techniques": techniques,
    })
}
