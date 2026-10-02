//! PyO3 bindings exposing the Khandaq core to Python as the `khandaq_core` module (ADR-0011).
//!
//! The interface is JSON-in / JSON-out (strings): the Python control plane passes a finding (or an
//! array of findings) as JSON and receives JSON back. This keeps the boundary simple and avoids a
//! Python object-mapping dependency. Invalid input raises ValueError.

use kcore::{dedup as kdedup, fingerprint as kfingerprint, map_frameworks, navigator_layer, validate, Mappings};
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

/// Build a MITRE ATLAS Navigator layer from an array of findings; returns JSON.
#[pyfunction]
fn navigator(findings_json: &str) -> PyResult<String> {
    let findings = parse_findings(findings_json)?;
    Ok(navigator_layer(&findings).to_string())
}

#[pymodule]
fn khandaq_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(validate_finding, m)?)?;
    m.add_function(wrap_pyfunction!(fingerprint, m)?)?;
    m.add_function(wrap_pyfunction!(dedup, m)?)?;
    m.add_function(wrap_pyfunction!(framework_mappings, m)?)?;
    m.add_function(wrap_pyfunction!(navigator, m)?)?;
    Ok(())
}
