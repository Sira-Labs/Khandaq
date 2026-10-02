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

/// Build the next entry after `prev` (the first entry has seq 1 and no prev_hash).
pub fn append(prev: Option<&LedgerEntry>, evidence_hash: &str) -> LedgerEntry {
    let seq = prev.map(|p| p.seq + 1).unwrap_or(1);
    let prev_hash = prev.map(|p| p.entry_hash.clone());
    let entry_hash = entry_hash(seq, evidence_hash, prev_hash.as_deref());
    LedgerEntry {
        seq,
        evidence_hash: evidence_hash.to_string(),
        prev_hash,
        entry_hash,
    }
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

/// Verify the whole chain: contiguous sequence, correct linkage, and recomputed entry hashes.
pub fn verify(entries: &[LedgerEntry]) -> VerifyResult {
    let mut prev: Option<&LedgerEntry> = None;
    for e in entries {
        let expected_seq = prev.map(|p| p.seq + 1).unwrap_or(1);
        if e.seq != expected_seq {
            return broken(e.seq, entries.len(), "non-contiguous sequence");
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

/// The chain root is the last entry's hash; a report pins it.
pub fn root(entries: &[LedgerEntry]) -> Option<String> {
    entries.last().map(|e| e.entry_hash.clone())
}
