//! Cross-tool / cross-run deduplication (ADR-0003).
//!
//! Findings sharing a fingerprint collapse into one canonical finding carrying the highest severity,
//! the union of evidence refs and framework mappings, and the set of tools that found it. Nothing is
//! dropped: every contributing tool and evidence ref is preserved on the canonical finding.

use std::collections::BTreeMap;

use crate::finding::Finding;
use crate::fingerprint::fingerprint;
use crate::severity::Severity;

#[derive(Debug, Clone)]
pub struct DedupResult {
    /// One canonical finding per fingerprint, each with merged evidence/mappings/tools.
    pub canonical: Vec<Finding>,
    /// How many input findings were duplicates (collapsed away).
    pub duplicates: usize,
}

fn sev_rank(s: &str) -> Severity {
    Severity::parse(s).unwrap_or(Severity::Info)
}

/// Deduplicate a batch of findings by fingerprint.
pub fn dedup(findings: Vec<Finding>) -> DedupResult {
    // Preserve first-seen order of groups for deterministic output.
    let mut order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, Vec<Finding>> = BTreeMap::new();

    for mut f in findings {
        let fp = fingerprint(&f);
        f.fingerprint = Some(fp.clone());
        if !groups.contains_key(&fp) {
            order.push(fp.clone());
        }
        groups.entry(fp).or_default().push(f);
    }

    let total: usize = groups.values().map(|v| v.len()).sum();
    let mut canonical = Vec::new();

    for fp in order {
        let group = groups.remove(&fp).expect("group present");
        // Canonical = highest-severity member (first wins on a tie).
        let mut best_idx = 0;
        for (i, f) in group.iter().enumerate() {
            if sev_rank(&f.severity) > sev_rank(&group[best_idx].severity) {
                best_idx = i;
            }
        }
        let mut canon = group[best_idx].clone();

        // Merge evidence, mappings, and the set of tools across the group.
        let mut evidence = canon.x_khandaq.evidence.clone();
        let mut mappings = canon.x_khandaq.mappings.clone();
        let mut tools: Vec<String> = vec![canon.source.tool.clone()];
        for f in &group {
            evidence.extend(f.x_khandaq.evidence.iter().cloned());
            mappings.extend(f.x_khandaq.mappings.iter().cloned());
            tools.push(f.source.tool.clone());
        }
        evidence.sort();
        evidence.dedup();
        mappings.sort();
        mappings.dedup();
        tools.sort();
        tools.dedup();
        // "also_found_by" is every contributing tool except the canonical's own.
        tools.retain(|t| t != &canon.source.tool);

        canon.x_khandaq.evidence = evidence;
        canon.x_khandaq.mappings = mappings;
        canon.x_khandaq.also_found_by = tools;
        canon.x_khandaq.dedup_of = None;
        canon.canonical = Some(true);
        canonical.push(canon);
    }

    let duplicates = total - canonical.len();
    DedupResult {
        canonical,
        duplicates,
    }
}
