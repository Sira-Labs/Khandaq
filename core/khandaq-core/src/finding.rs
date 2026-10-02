//! The canonical finding (a SARIF superset; ADR-0003) and its validation.
//!
//! Validation is performed by deserialising into this typed model and checking the controlled
//! vocabularies. The published JSON Schema (`schema/finding.schema.json`) is the external contract
//! adapters document against and mirrors this model; `validate` is the authoritative check.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::severity::Severity;

pub const SCHEMA_ID: &str = "khandaq.finding/1";

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
    if finding.schema != SCHEMA_ID {
        return Err(SchemaError(format!(
            "schema must be '{SCHEMA_ID}', got '{}'",
            finding.schema
        )));
    }
    if Severity::parse(&finding.severity).is_none() {
        return Err(SchemaError(format!(
            "unknown severity '{}'",
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
    if finding.engagement_id.is_empty() || finding.run_id.is_empty() || finding.rule_id.is_empty() {
        return Err(SchemaError(
            "engagement_id, run_id and rule_id are required".into(),
        ));
    }
    Ok(finding)
}
