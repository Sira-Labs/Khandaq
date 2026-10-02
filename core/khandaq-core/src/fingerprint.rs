//! Stable fingerprint for cross-tool / cross-run deduplication (ADR-0003).
//!
//! The fingerprint is a sha256 over a normalised identity: the set of framework-mapping ids (so the
//! same issue found by two tools and mapped to the same framework id collapses), the target, and a
//! canonical location key. When a finding has no mappings yet, the rule id is used as the fallback
//! identity. serde_json serialises object keys in sorted order by default, so the input is
//! canonical and the hash is stable across irrelevant field reordering.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::finding::Finding;

fn canonical_location(locations: &[Value]) -> String {
    if locations.is_empty() {
        return String::new();
    }
    // Sorted-key JSON of the locations array; deterministic and order-insensitive per key.
    serde_json::to_string(locations).unwrap_or_default()
}

/// Compute the stable fingerprint, e.g. `sha256:ab12…`.
pub fn fingerprint(finding: &Finding) -> String {
    let mut identity: Vec<String> = finding
        .x_khandaq
        .mappings
        .iter()
        .map(|m| format!("{}:{}", m.framework, m.id))
        .collect();
    if identity.is_empty() {
        identity.push(format!("rule:{}", finding.rule_id));
    }
    identity.sort();
    identity.dedup();

    let input = json!({
        "identity": identity,
        "target": finding.target_ref.clone().unwrap_or_default(),
        "location": canonical_location(&finding.locations),
    });
    let serialised = input.to_string();

    let mut hasher = Sha256::new();
    hasher.update(serialised.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}
