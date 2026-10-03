//! PyO3 bindings exposing the Khandaq core to Python as the `khandaq_core` module (ADR-0011).
//!
//! The interface is JSON-in / JSON-out (strings): the Python control plane passes a finding (or an
//! array of findings) as JSON and receives JSON back. This keeps the boundary simple and avoids a
//! Python object-mapping dependency. Invalid input raises ValueError.

use kcore::ledger::{self, LedgerEntry};
use kcore::{
    dedup as kdedup, fingerprint as kfingerprint, map_frameworks,
    merge_mappings as core_merge_mappings, navigator_layer, validate, Mappings, MAPPINGS_SCHEMA,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::Value;

fn parse(s: &str) -> PyResult<Value> {
    serde_json::from_str(s).map_err(|e| PyValueError::new_err(format!("invalid JSON: {e}")))
}

fn parse_findings(s: &str) -> PyResult<Vec<kcore::Finding>> {
    let value = parse(s)?;
    let items = match value {
        Value::Array(items) => items,
        other => vec![other],
    };
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let f = validate(item).map_err(|e| PyValueError::new_err(format!("finding {i}: {e}")))?;
        out.push(f);
    }
    Ok(out)
}

/// Validate a finding; raises ValueError if invalid, returns True otherwise.
#[pyfunction]
fn validate_finding(finding_json: &str) -> PyResult<bool> {
    let v = parse(finding_json)?;
    validate(&v).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(true)
}

/// Return the stable fingerprint (`sha256:…`) for a finding.
#[pyfunction]
fn fingerprint(finding_json: &str) -> PyResult<String> {
    let v = parse(finding_json)?;
    let f = validate(&v).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(kfingerprint(&f))
}

/// Deduplicate an array of findings; returns JSON `{canonical: [...], duplicates: n}`.
#[pyfunction]
fn dedup(findings_json: &str) -> PyResult<String> {
    let findings = parse_findings(findings_json)?;
    let result = kdedup(findings);
    let out = serde_json::json!({
        "canonical": result.canonical,
        "duplicates": result.duplicates,
    });
    Ok(out.to_string())
}

/// Return the framework mappings for a finding's rule as JSON (built-in tables).
#[pyfunction]
fn framework_mappings(finding_json: &str) -> PyResult<String> {
    let v = parse(finding_json)?;
    let f = validate(&v).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let mappings = map_frameworks(&f, &Mappings::builtin());
    serde_json::to_string(&mappings).map_err(|e| PyValueError::new_err(e.to_string()))
}

fn table(overlay: Option<&str>) -> PyResult<Mappings> {
    let builtin = Mappings::builtin();
    match overlay {
        None => Ok(builtin),
        Some(text) => builtin
            .with_overlay(text)
            .map_err(|e| PyValueError::new_err(e.to_string())),
    }
}

/// The finding's own mappings plus the table's (built-in, extended by an optional overlay's JSON
/// text), or the `unmapped` marker (specs 020, 021).
#[pyfunction]
#[pyo3(signature = (finding_json, overlay=None))]
fn merge_mappings(finding_json: &str, overlay: Option<&str>) -> PyResult<String> {
    let v = parse(finding_json)?;
    let f = validate(&v).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let mappings = core_merge_mappings(&f, &table(overlay)?);
    serde_json::to_string(&mappings).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// The table's schema, framework versions and sources as JSON. Raises ValueError for an invalid
/// overlay, so it doubles as the overlay check.
#[pyfunction]
#[pyo3(signature = (overlay=None))]
fn mapping_table(overlay: Option<&str>) -> PyResult<String> {
    let m = table(overlay)?;
    Ok(serde_json::json!({
        "schema": MAPPINGS_SCHEMA,
        "versions": m.versions(),
        "sources": m.sources(),
    })
    .to_string())
}

/// Build a MITRE ATLAS Navigator layer from an array of findings; returns JSON.
#[pyfunction]
fn navigator(findings_json: &str) -> PyResult<String> {
    let findings = parse_findings(findings_json)?;
    Ok(navigator_layer(&findings).to_string())
}

// --- Evidence ledger (spec 004) ---

fn parse_entries(entries_json: &str) -> PyResult<Vec<LedgerEntry>> {
    serde_json::from_str(entries_json)
        .map_err(|e| PyValueError::new_err(format!("invalid ledger entries JSON: {e}")))
}

/// Compute the next ledger entry after `prev_json` (None for the first); returns the entry as JSON.
#[pyfunction]
#[pyo3(signature = (prev_json, evidence_hash))]
fn ledger_append(prev_json: Option<&str>, evidence_hash: &str) -> PyResult<String> {
    let prev: Option<LedgerEntry> = match prev_json {
        Some(s) => Some(serde_json::from_str(s).map_err(|e| PyValueError::new_err(e.to_string()))?),
        None => None,
    };
    let entry = ledger::append(prev.as_ref(), evidence_hash)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    serde_json::to_string(&entry).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Verify a chain (JSON array of entries); returns a VerifyResult as JSON. With a pinned
/// `expected_root` and `expected_count` (a report records both), the chain must also still contain
/// that state, which detects entries removed from its end.
#[pyfunction]
#[pyo3(signature = (entries_json, expected_root=None, expected_count=None))]
fn ledger_verify(
    entries_json: &str,
    expected_root: Option<&str>,
    expected_count: Option<usize>,
) -> PyResult<String> {
    let entries = parse_entries(entries_json)?;
    let result = match (expected_root, expected_count) {
        (None, None) => ledger::verify(&entries),
        (Some(root), Some(count)) => ledger::verify_pinned(&entries, root, count),
        _ => {
            return Err(PyValueError::new_err(
                "expected_root and expected_count must be given together",
            ))
        }
    };
    serde_json::to_string(&result).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Return the `evidence_hash` a format-2 ledger entry seals for an evidence row (ADR-0014): a hash
/// over its content hash and metadata. The record must carry exactly the `EvidenceRecord` fields.
#[pyfunction]
fn evidence_record_hash(record_json: &str) -> PyResult<String> {
    let record: ledger::EvidenceRecord = serde_json::from_str(record_json)
        .map_err(|e| PyValueError::new_err(format!("invalid evidence record JSON: {e}")))?;
    ledger::evidence_record_hash(&record).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Return the chain root (last entry hash) or None for an empty chain.
#[pyfunction]
fn ledger_root(entries_json: &str) -> PyResult<Option<String>> {
    Ok(ledger::root(&parse_entries(entries_json)?))
}

#[pymodule]
fn khandaq_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(validate_finding, m)?)?;
    m.add_function(wrap_pyfunction!(fingerprint, m)?)?;
    m.add_function(wrap_pyfunction!(dedup, m)?)?;
    m.add_function(wrap_pyfunction!(framework_mappings, m)?)?;
    m.add_function(wrap_pyfunction!(merge_mappings, m)?)?;
    m.add_function(wrap_pyfunction!(mapping_table, m)?)?;
    m.add_function(wrap_pyfunction!(navigator, m)?)?;
    m.add_function(wrap_pyfunction!(ledger_append, m)?)?;
    m.add_function(wrap_pyfunction!(ledger_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ledger_root, m)?)?;
    m.add_function(wrap_pyfunction!(evidence_record_hash, m)?)?;
    Ok(())
}
