//! Framework cross-walk tables and the MITRE ATLAS Navigator export (ADR-0012).
//!
//! Mappings are versioned data (`mappings/builtin.json`), embedded at build time. A finding records
//! every applicable framework id across ATLAS, OWASP LLM (2025 and 2026), OWASP Agentic and NIST. A
//! rule with no mapping yields an explicit `unmapped` marker so curation gaps are visible, not silent.

use std::collections::HashMap;

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
pub fn navigator_layer(findings: &[Finding]) -> Value {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for f in findings {
        for m in &f.x_khandaq.mappings {
            if m.framework == "atlas" {
                *counts.entry(m.id.clone()).or_insert(0) += 1;
            }
        }
    }
    let mut techniques: Vec<Value> = counts
        .into_iter()
        .map(|(id, score)| json!({"techniqueID": id, "score": score, "enabled": true}))
        .collect();
    techniques.sort_by(|a, b| a["techniqueID"].as_str().cmp(&b["techniqueID"].as_str()));

    json!({
        "name": "Khandaq findings",
        "versions": {"layer": "4.5", "navigator": "4.9", "attack": "atlas"},
        "domain": "atlas",
        "description": "ATLAS techniques observed in this engagement's findings.",
        "techniques": techniques,
    })
}
