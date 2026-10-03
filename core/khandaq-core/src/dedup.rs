//! Cross-tool / cross-run deduplication (ADR-0003).
//!
//! Findings sharing a fingerprint collapse into one canonical finding carrying the highest severity,
//! the union of evidence refs and framework mappings, and the set of tools that found it. Nothing is
//! dropped: every contributing tool, its native severity (`x-khandaq.sources`) and every evidence
//! ref is preserved on the canonical finding. The result does not depend on the input order.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::finding::{Finding, Source, SCHEMA_ID};
use crate::fingerprint::{fingerprint_with, Equivalence};
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

/// The value as canonical JSON (serde_json maps serialise with sorted keys): a total, stable key
/// for whole records, so two records that differ anywhere never compare equal.
fn canonical_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Total order used to pick the canonical member of a group: highest severity first, then
/// (tool, version, run, rule), and finally the whole record, so the pick never depends on input
/// order even between members that agree on every named field.
fn canonical_order(a: &Finding, b: &Finding) -> Ordering {
    sev_rank(&b.severity)
        .cmp(&sev_rank(&a.severity))
        .then_with(|| a.source.tool.cmp(&b.source.tool))
        .then_with(|| a.source.version.cmp(&b.source.version))
        .then_with(|| a.run_id.cmp(&b.run_id))
        .then_with(|| a.rule_id.cmp(&b.rule_id))
        .then_with(|| canonical_json(a).cmp(&canonical_json(b)))
}

/// Add the fields `from` has and `into` lacks. Fields `into` already has win: the canonical
/// member's own values are kept, and other members fill gaps in canonical order.
fn fill_missing(into: &mut Map<String, Value>, from: &Map<String, Value>) {
    for (key, value) in from {
        into.entry(key.clone()).or_insert_with(|| value.clone());
    }
}

/// Deduplicate a batch of findings by fingerprint, under the built-in equivalence table.
///
/// Groups are emitted in fingerprint order, so the output does not depend on the input order.
pub fn dedup(findings: Vec<Finding>) -> DedupResult {
    dedup_with(findings, Equivalence::builtin())
}

/// Deduplicate a batch of findings by fingerprint under an explicit equivalence table.
///
/// Every canonical finding is emitted with the current schema id: it carries a fingerprint
/// computed under the current recipe, whichever schema version its input was written in.
pub fn dedup_with(findings: Vec<Finding>, equivalence: &Equivalence) -> DedupResult {
    let mut groups: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    for mut f in findings {
        let fp = fingerprint_with(&f, equivalence);
        f.fingerprint = Some(fp.clone());
        groups.entry(fp).or_default().push(f);
    }

    let total: usize = groups.values().map(|v| v.len()).sum();
    let mut canonical = Vec::new();

    for (_, mut group) in groups {
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
        // Fields the model does not name (the SARIF superset) survive from every member.
        for f in &group[1..] {
            fill_missing(&mut canon.extra, &f.extra);
            fill_missing(&mut canon.x_khandaq.extra, &f.x_khandaq.extra);
        }
        evidence.sort();
        evidence.dedup();
        mappings.sort();
        mappings.dedup();
        tools.sort();
        tools.dedup();
        // "also_found_by" is every contributing tool except the canonical's own.
        tools.retain(|t| t != &canon.source.tool);
        // Only identical records collapse: a source differing in any field (extras included) stays.
        sources.sort_by_cached_key(canonical_json);
        sources.dedup();

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
        canon.schema = SCHEMA_ID.to_string();
        canonical.push(canon);
    }

    let duplicates = total - canonical.len();
    DedupResult {
        canonical,
        duplicates,
    }
}
