//! Append-only, hash-chained evidence ledger (ADR-0007).
//!
//! Each entry binds the evidence hash to the previous entry's hash, so the chain is tamper-evident:
//! altering or dropping any entry breaks verification at a known sequence number. This module is
//! pure — it computes and verifies the chain; persistence (append-only object store + rows) is the
//! caller's responsibility, and the module exposes no mutate/delete.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub seq: i64,
    pub evidence_hash: String,
    pub prev_hash: Option<String>,
    pub entry_hash: String,
}

/// `entry_hash = sha256(seq || evidence_hash || prev_hash)`, domain-separated by NUL bytes.
pub fn entry_hash(seq: i64, evidence_hash: &str, prev_hash: Option<&str>) -> String {
    let mut h = Sha256::new();
    h.update(seq.to_string().as_bytes());
    h.update([0u8]);
    h.update(evidence_hash.as_bytes());
    h.update([0u8]);
    h.update(prev_hash.unwrap_or("").as_bytes());
    format!("sha256:{}", hex::encode(h.finalize()))
}

/// Why an entry cannot be appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerError(pub String);

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ledger: {}", self.0)
    }
}

impl std::error::Error for LedgerError {}

/// Whether `h` is a well-formed hash: `sha256:` followed by 64 lowercase hex digits. Only this
/// one spelling is accepted, so two spellings of the same digest can never both enter a chain.
pub fn is_hash(h: &str) -> bool {
    h.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn next_seq(prev: Option<&LedgerEntry>) -> Option<i64> {
    match prev {
        None => Some(1),
        Some(p) => p.seq.checked_add(1),
    }
}

/// Build the next entry after `prev` (the first entry has seq 1 and no prev_hash).
///
/// Refuses an evidence hash that is not a well-formed `sha256:<64 hex>` digest, a `prev` whose
/// own hash is malformed, and a sequence number that would overflow.
pub fn append(prev: Option<&LedgerEntry>, evidence_hash: &str) -> Result<LedgerEntry, LedgerError> {
    if !is_hash(evidence_hash) {
        return Err(LedgerError(format!(
            "evidence hash must be 'sha256:' + 64 lowercase hex digits, got '{evidence_hash}'"
        )));
    }
    if let Some(p) = prev {
        if !is_hash(&p.entry_hash) {
            return Err(LedgerError(format!(
                "previous entry {} has a malformed entry_hash",
                p.seq
            )));
        }
    }
    let seq = next_seq(prev).ok_or_else(|| LedgerError("sequence number overflow".into()))?;
    let prev_hash = prev.map(|p| p.entry_hash.clone());
    let entry_hash = entry_hash(seq, evidence_hash, prev_hash.as_deref());
    Ok(LedgerEntry {
        seq,
        evidence_hash: evidence_hash.to_string(),
        prev_hash,
        entry_hash,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResult {
    pub ok: bool,
    pub count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn broken(seq: i64, count: usize, reason: &str) -> VerifyResult {
    VerifyResult {
        ok: false,
        count,
        broken_at: Some(seq),
        reason: Some(reason.to_string()),
    }
}

/// Verify the whole chain: contiguous sequence, well-formed hashes, correct linkage, and
/// recomputed entry hashes.
///
/// This proves the entries are internally consistent; it cannot notice entries removed from the
/// **end** of the chain. Use [`verify_pinned`] against a root and count recorded earlier (a report
/// pins both) to detect that.
pub fn verify(entries: &[LedgerEntry]) -> VerifyResult {
    let mut prev: Option<&LedgerEntry> = None;
    for e in entries {
        if Some(e.seq) != next_seq(prev) {
            return broken(e.seq, entries.len(), "non-contiguous sequence");
        }
        if !is_hash(&e.evidence_hash) || !is_hash(&e.entry_hash) {
            return broken(e.seq, entries.len(), "malformed hash");
        }
        let expected_prev = prev.map(|p| p.entry_hash.clone());
        if e.prev_hash != expected_prev {
            return broken(
                e.seq,
                entries.len(),
                "prev_hash does not match the previous entry",
            );
        }
        if e.entry_hash != entry_hash(e.seq, &e.evidence_hash, e.prev_hash.as_deref()) {
            return broken(
                e.seq,
                entries.len(),
                "entry_hash mismatch (entry was tampered)",
            );
        }
        prev = Some(e);
    }
    VerifyResult {
        ok: true,
        count: entries.len(),
        broken_at: None,
        reason: None,
    }
}

/// Verify the chain, and that it still contains the state pinned earlier: the entry at
/// `expected_count` must exist and its hash must be `expected_root`. The chain may have grown
/// since (appends are expected), but it must not have been truncated or rewritten below the pin.
pub fn verify_pinned(
    entries: &[LedgerEntry],
    expected_root: &str,
    expected_count: usize,
) -> VerifyResult {
    let result = verify(entries);
    if !result.ok {
        return result;
    }
    let pinned_seq = i64::try_from(expected_count).unwrap_or(i64::MAX);
    match expected_count.checked_sub(1).and_then(|i| entries.get(i)) {
        None if expected_count == 0 => {
            broken(0, entries.len(), "the pinned count must be at least 1")
        }
        None => broken(
            pinned_seq,
            entries.len(),
            "the chain is shorter than the pinned count (entries were removed)",
        ),
        Some(e) if e.entry_hash != expected_root => broken(
            e.seq,
            entries.len(),
            "the entry at the pinned count does not match the pinned root",
        ),
        Some(_) => result,
    }
}

/// The chain root is the last entry's hash; a report pins it.
pub fn root(entries: &[LedgerEntry]) -> Option<String> {
    entries.last().map(|e| e.entry_hash.clone())
}
