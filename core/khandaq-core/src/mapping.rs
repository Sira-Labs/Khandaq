//! Framework cross-walk tables and the MITRE ATLAS Navigator export (ADR-0012, spec 020).
//!
//! Mappings are versioned data (`mappings/builtin.json`), embedded at build time. A key is a rule-id
//! prefix: a rule matches a key it equals or that it extends on a `.` or `:` boundary, and the
//! longest key wins, so every probe of a family uses the family's entry and a bare tool key is that
//! tool's default. The table names a version and a source for every framework it uses. A rule with
//! no mapping yields an explicit `unmapped` marker so curation gaps are visible, not silent.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::finding::{Finding, Mapping};

const BUILTIN: &str = include_str!("../mappings/builtin.json");

/// The table schema this build reads.
pub const MAPPINGS_SCHEMA: &str = "khandaq.mappings/1";

#[derive(Debug, Deserialize)]
struct RawRule {
    mappings: Vec<Mapping>,
    #[allow(dead_code)] // documentation for curators; not used at runtime
    rationale: String,
}

#[derive(Debug, Deserialize)]
struct RawMappings {
    schema: String,
    versions: BTreeMap<String, String>,
    sources: BTreeMap<String, String>,
    rules: HashMap<String, RawRule>,
}

/// A table that cannot be used: wrong schema, an empty key or rule, or a framework with no version
/// or source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingsError(pub String);

impl std::fmt::Display for MappingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid mapping table: {}", self.0)
    }
}

impl std::error::Error for MappingsError {}

/// The loaded cross-walk tables.
#[derive(Debug, Clone)]
pub struct Mappings {
    table: HashMap<String, Vec<Mapping>>,
    versions: BTreeMap<String, String>,
    sources: BTreeMap<String, String>,
}

impl Mappings {
    /// Load the built-in (embedded) mapping tables. The core tests prove the embedded table is
    /// valid, so a malformed one never reaches a release.
    pub fn builtin() -> Self {
        Self::from_json(BUILTIN).expect("the builtin mapping table is valid")
    }

    /// Parse and check a table in the `khandaq.mappings/1` schema.
    pub fn from_json(text: &str) -> Result<Self, MappingsError> {
        let raw: RawMappings =
            serde_json::from_str(text).map_err(|e| MappingsError(e.to_string()))?;
        if raw.schema != MAPPINGS_SCHEMA {
            return Err(MappingsError(format!(
                "schema {:?}, expected {MAPPINGS_SCHEMA:?}",
                raw.schema
            )));
        }
        let mut table = HashMap::new();
        for (key, rule) in raw.rules {
            if key.trim().is_empty() || key.ends_with(['.', ':']) {
                return Err(MappingsError(format!("bad rule key {key:?}")));
            }
            if rule.mappings.is_empty() {
                return Err(MappingsError(format!("rule {key:?} has no mappings")));
            }
            for m in &rule.mappings {
                if m.id.trim().is_empty() {
                    return Err(MappingsError(format!("rule {key:?} has an empty id")));
                }
                for (what, known) in [("version", &raw.versions), ("source", &raw.sources)] {
                    if !known.contains_key(&m.framework) {
                        return Err(MappingsError(format!(
                            "framework {:?} (rule {key:?}) has no {what}",
                            m.framework
                        )));
                    }
                }
            }
            table.insert(key, rule.mappings);
        }
        Ok(Mappings {
            table,
            versions: raw.versions,
            sources: raw.sources,
        })
    }

    /// The entry for a rule: the longest key the rule id equals or extends on a `.`/`:` boundary.
    pub fn for_rule(&self, rule_id: &str) -> Option<&Vec<Mapping>> {
        let mut end = rule_id.len();
        loop {
            if let Some(found) = self.table.get(&rule_id[..end]) {
                return Some(found);
            }
            end = rule_id[..end].rfind(['.', ':'])?;
        }
    }

    /// Framework → table version (e.g. `atlas` → `v2026.09`).
    pub fn versions(&self) -> &BTreeMap<String, String> {
        &self.versions
    }

    /// Framework → where its ids are defined.
    pub fn sources(&self) -> &BTreeMap<String, String> {
        &self.sources
    }
}

impl Default for Mappings {
    fn default() -> Self {
        Self::builtin()
    }
}

fn unmapped(finding: &Finding) -> Vec<Mapping> {
    vec![Mapping {
        framework: "unmapped".to_string(),
        id: finding.rule_id.clone(),
    }]
}

/// Return every framework id the table has for a finding's rule, or a single `unmapped` marker.
pub fn map_frameworks(finding: &Finding, mappings: &Mappings) -> Vec<Mapping> {
    match mappings.for_rule(&finding.rule_id) {
        Some(found) if !found.is_empty() => found.clone(),
        _ => unmapped(finding),
    }
}

/// The finding's own ids plus the table's, sorted and de-duplicated (spec 020). The tool's ids are
/// kept; the table fills the frameworks the tool does not name. Neither → the `unmapped` marker.
/// A previous marker is dropped first, so merging twice gives the same result.
pub fn merge_mappings(finding: &Finding, mappings: &Mappings) -> Vec<Mapping> {
    let mut merged: Vec<Mapping> = finding
        .x_khandaq
        .mappings
        .iter()
        .filter(|m| m.framework != "unmapped")
        .cloned()
        .collect();
    if let Some(found) = mappings.for_rule(&finding.rule_id) {
        merged.extend(found.iter().cloned());
    }
    if merged.is_empty() {
        return unmapped(finding);
    }
    merged.sort();
    merged.dedup();
    merged
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
