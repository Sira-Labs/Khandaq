//! The canonical finding (a SARIF superset; ADR-0003) and its validation.
//!
//! Validation is performed by deserialising into this typed model and checking the controlled
//! vocabularies. The published JSON Schema (`schema/finding.schema.json`) is the external contract
//! adapters document against and mirrors this model; `validate` is the authoritative check.
//!
//! The finding is a **superset**: fields this model does not name (SARIF `message`, `properties`,
//! `codeFlows`, an adapter's own `x-khandaq` or `source` extras, …) are kept in `extra` and
//! serialised back unchanged, so validation and dedup never silently drop tool data.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::severity::Severity;

/// The current schema id. `/2` changed only the fingerprint recipe (ADR-0013); the record shape
/// is the same, so a `/1` record still validates and is re-fingerprinted under the current recipe.
pub const SCHEMA_ID: &str = "khandaq.finding/2";

/// Schema ids `validate` accepts: the current one and every earlier one with the same shape.
pub const ACCEPTED_SCHEMA_IDS: [&str; 2] = ["khandaq.finding/1", SCHEMA_ID];

/// A framework cross-walk entry, e.g. `{framework: "atlas", id: "AML.T0051"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Mapping {
    pub framework: String,
    pub id: String,
}

/// The upstream tool that produced the finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub tool: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_severity: Option<String>,
    /// Fields this model does not name, preserved verbatim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn default_status() -> String {
    "open".to_string()
}

/// Khandaq-specific extension data (lives under the `x-khandaq` property).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XKhandaq {
    pub phase: String,
    #[serde(default)]
    pub mappings: Vec<Mapping>,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_of: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen_run: Option<String>,
    #[serde(default = "default_status")]
    pub status: String,
    /// Tools that independently produced an equivalent finding (filled in on dedup merge).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_found_by: Vec<String>,
    /// Every contributing tool's own report of the finding (tool, version, native severity),
    /// filled in on dedup merge so no tool's native severity is lost.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<Source>,
    /// Fields this model does not name, preserved verbatim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn default_confidence() -> String {
    "firm".to_string()
}

/// The canonical finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub engagement_id: String,
    pub run_id: String,
    pub rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub severity: String,
    #[serde(default = "default_confidence")]
    pub confidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    pub source: Source,
    #[serde(default)]
    pub locations: Vec<Value>,
    #[serde(rename = "x-khandaq")]
    pub x_khandaq: XKhandaq,
    #[serde(default, rename = "canonical", skip_serializing_if = "Option::is_none")]
    pub canonical: Option<bool>,
    /// Fields this model does not name (the SARIF superset), preserved verbatim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

const VALID_CONFIDENCE: [&str; 3] = ["tentative", "firm", "confirmed"];
const VALID_STATUS: [&str; 5] = [
    "open",
    "triaged",
    "accepted_risk",
    "fixed",
    "false_positive",
];

/// Why a value is not a valid canonical finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError(pub String);

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid finding: {}", self.0)
    }
}

impl std::error::Error for SchemaError {}

/// Validate a JSON value as a canonical finding, returning the typed model.
pub fn validate(value: &Value) -> Result<Finding, SchemaError> {
    let finding: Finding =
        serde_json::from_value(value.clone()).map_err(|e| SchemaError(e.to_string()))?;
    if !ACCEPTED_SCHEMA_IDS.contains(&finding.schema.as_str()) {
        return Err(SchemaError(format!(
            "schema must be one of {ACCEPTED_SCHEMA_IDS:?}, got '{}'",
            finding.schema
        )));
    }
    // The canonical scale is lowercase (as in the published schema): "HIGH" is not accepted, so
    // a stored severity always compares, filters and sorts as one of the five canonical values.
    if Severity::parse(&finding.severity).map(Severity::as_str) != Some(finding.severity.as_str()) {
        return Err(SchemaError(format!(
            "unknown severity '{}' (expected one of info, low, medium, high, critical)",
            finding.severity
        )));
    }
    if !VALID_CONFIDENCE.contains(&finding.confidence.as_str()) {
        return Err(SchemaError(format!(
            "unknown confidence '{}'",
            finding.confidence
        )));
    }
    if !VALID_STATUS.contains(&finding.x_khandaq.status.as_str()) {
        return Err(SchemaError(format!(
            "unknown status '{}'",
            finding.x_khandaq.status
        )));
    }
    if let Some(i) = finding.locations.iter().position(|l| !l.is_object()) {
        return Err(SchemaError(format!(
            "locations[{i}] must be an object (a SARIF location)"
        )));
    }
    if finding.engagement_id.is_empty() || finding.run_id.is_empty() || finding.rule_id.is_empty() {
        return Err(SchemaError(
            "engagement_id, run_id and rule_id are required".into(),
        ));
    }
    Ok(finding)
}
