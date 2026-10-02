//! Cross-tool / cross-run deduplication (ADR-0003).
//!
//! Findings sharing a fingerprint collapse into one canonical finding carrying the highest severity,
//! the union of evidence refs and framework mappings, and the set of tools that found it. Nothing is
//! dropped: every contributing tool, its native severity (`x-khandaq.sources`) and every evidence
//! ref is preserved on the canonical finding. The result does not depend on the input order.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::finding::{Finding, Source};
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

/// Total order used to pick the canonical member of a group: highest severity first, then a
/// stable tie-break on (tool, version, run, rule), so the pick never depends on input order.
fn canonical_order(a: &Finding, b: &Finding) -> Ordering {
    sev_rank(&b.severity)
        .cmp(&sev_rank(&a.severity))
        .then_with(|| a.source.tool.cmp(&b.source.tool))
        .then_with(|| a.source.version.cmp(&b.source.version))
        .then_with(|| a.run_id.cmp(&b.run_id))
        .then_with(|| a.rule_id.cmp(&b.rule_id))
}

fn source_key(s: &Source) -> (&str, &str, Option<&str>) {
    (&s.tool, &s.version, s.native_severity.as_deref())
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
        let mut group = groups.remove(&fp).expect("group present");
        group.sort_by(canonical_order);
        let mut canon = group[0].clone();

        // Merge evidence, mappings, tools and per-tool sources across the group. A member that is
        // itself a merged canonical (re-dedup) contributes its own also_found_by and sources too.
        let mut evidence = Vec::new();
        let mut mappings = Vec::new();
        let mut tools: Vec<String> = Vec::new();
        let mut sources: Vec<Source> = Vec::new();
        for f in &group {
            evidence.extend(f.x_khandaq.evidence.iter().cloned());
            mappings.extend(f.x_khandaq.mappings.iter().cloned());
            tools.push(f.source.tool.clone());
            tools.extend(f.x_khandaq.also_found_by.iter().cloned());
            sources.push(f.source.clone());
            sources.extend(f.x_khandaq.sources.iter().cloned());
        }
        evidence.sort();
        evidence.dedup();
        mappings.sort();
        mappings.dedup();
        tools.sort();
        tools.dedup();
        // "also_found_by" is every contributing tool except the canonical's own.
        tools.retain(|t| t != &canon.source.tool);
        sources.sort_by(|a, b| source_key(a).cmp(&source_key(b)));
        sources.dedup_by(|a, b| source_key(a) == source_key(b));

        canon.x_khandaq.evidence = evidence;
        canon.x_khandaq.mappings = mappings;
        canon.x_khandaq.also_found_by = tools;
        // A lone finding needs no per-tool breakdown: its own `source` already says it all.
        canon.x_khandaq.sources = if sources.len() > 1 {
            sources
        } else {
            Vec::new()
        };
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
