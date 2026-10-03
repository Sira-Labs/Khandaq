//! Stable fingerprint for cross-tool / cross-run deduplication (ADR-0003, recipe v2 per ADR-0013).
//!
//! The fingerprint is a sha256 over `{v: 2, weakness, target, location}`:
//!
//! - `weakness` is `rule:<rule_id>`, unless the versioned **equivalence table**
//!   (`mappings/equivalence.json`) maps the rule to a shared weakness key, giving `weakness:<key>`.
//!   Framework mappings are deliberately **not** part of the identity: they are curated data that
//!   changes (ADR-0012), and a mapping edit must never re-fingerprint an issue that is already
//!   triaged. Changing the equivalence table is an explicit, reviewed act with a migration note.
//! - `target` is the server-assigned `target_ref`.
//! - `location` is the canonical (sorted-key) JSON of the SARIF locations.
//!
//! serde_json serialises object keys in sorted order by default, so the input is canonical and the
//! hash is stable across irrelevant field reordering.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::finding::Finding;

/// The fingerprint recipe version; bumping it is a schema version bump (ADR-0003).
pub const FINGERPRINT_VERSION: u64 = 2;

const BUILTIN_EQUIVALENCE: &str = include_str!("../mappings/equivalence.json");

#[derive(Debug, Deserialize)]
struct RawEquivalence {
    weaknesses: HashMap<String, String>,
}

/// Rule-id → shared weakness key table. Keys are exact rule ids, or a prefix ending in `.*`
/// (`garak.promptinject.*`) that matches every rule id under it.
#[derive(Debug, Clone, Default)]
pub struct Equivalence {
    exact: HashMap<String, String>,
    /// `(prefix including the trailing '.', weakness)`, longest prefix first.
    prefixes: Vec<(String, String)>,
}

impl Equivalence {
    /// Build a table from `rule pattern → weakness key` pairs.
    pub fn new<I, K, V>(entries: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut table = Equivalence::default();
        for (pattern, weakness) in entries {
            let (pattern, weakness) = (pattern.into(), weakness.into());
            match pattern.strip_suffix('*') {
                Some(prefix) if prefix.ends_with('.') => {
                    table.prefixes.push((prefix.to_string(), weakness))
                }
                _ => {
                    table.exact.insert(pattern, weakness);
                }
            }
        }
        // Longest prefix wins; ties broken by the prefix itself so the order is total.
        table
            .prefixes
            .sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        table
    }

    /// The built-in (embedded) equivalence table, parsed once per process.
    pub fn builtin() -> &'static Self {
        static BUILTIN: OnceLock<Equivalence> = OnceLock::new();
        BUILTIN.get_or_init(|| {
            let raw: RawEquivalence = serde_json::from_str(BUILTIN_EQUIVALENCE)
                .expect("builtin equivalence table is valid JSON");
            Equivalence::new(raw.weaknesses)
        })
    }

    /// The shared weakness key for a rule id, if the table names one.
    pub fn weakness_for(&self, rule_id: &str) -> Option<&str> {
        if let Some(w) = self.exact.get(rule_id) {
            return Some(w);
        }
        self.prefixes
            .iter()
            .find(|(prefix, _)| rule_id.starts_with(prefix.as_str()))
            .map(|(_, w)| w.as_str())
    }
}

fn canonical_location(locations: &[Value]) -> String {
    if locations.is_empty() {
        return String::new();
    }
    // Sorted-key JSON of the locations array; deterministic and order-insensitive per key.
    serde_json::to_string(locations).unwrap_or_default()
}

/// Compute the stable fingerprint under an explicit equivalence table.
pub fn fingerprint_with(finding: &Finding, equivalence: &Equivalence) -> String {
    let weakness = match equivalence.weakness_for(&finding.rule_id) {
        Some(key) => format!("weakness:{key}"),
        None => format!("rule:{}", finding.rule_id),
    };
    let input = json!({
        "v": FINGERPRINT_VERSION,
        "weakness": weakness,
        "target": finding.target_ref.clone().unwrap_or_default(),
        "location": canonical_location(&finding.locations),
    });

    let mut hasher = Sha256::new();
    hasher.update(input.to_string().as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Compute the stable fingerprint under the built-in equivalence table, e.g. `sha256:ab12…`.
pub fn fingerprint(finding: &Finding) -> String {
    fingerprint_with(finding, Equivalence::builtin())
}
