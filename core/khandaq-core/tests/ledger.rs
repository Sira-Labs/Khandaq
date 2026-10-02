//! Tests for the hash-chained evidence ledger (spec 004).

use khandaq_core::ledger::{append, root, verify, LedgerEntry};

fn build(hashes: &[&str]) -> Vec<LedgerEntry> {
    let mut chain: Vec<LedgerEntry> = Vec::new();
    for h in hashes {
        let prev = chain.last();
        chain.push(append(prev, h));
    }
    chain
}

#[test]
fn chain_builds_and_verifies() {
    let chain = build(&["sha256:a", "sha256:b", "sha256:c"]);
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0].seq, 1);
    assert_eq!(chain[0].prev_hash, None);
    assert_eq!(
        chain[1].prev_hash.as_deref(),
        Some(chain[0].entry_hash.as_str())
    );
    let r = verify(&chain);
    assert!(r.ok && r.broken_at.is_none() && r.count == 3);
}

#[test]
fn root_is_last_entry_and_stable_until_append() {
    let mut chain = build(&["sha256:a", "sha256:b"]);
    let r1 = root(&chain).unwrap();
    assert_eq!(r1, chain.last().unwrap().entry_hash);
    // Appending changes the root; the prior entries are unchanged.
    chain.push(append(chain.last(), "sha256:c"));
    assert_ne!(root(&chain).unwrap(), r1);
}

#[test]
fn tampering_with_evidence_is_detected_at_its_seq() {
    let mut chain = build(&["sha256:a", "sha256:b", "sha256:c"]);
    // Flip the stored evidence hash of entry 2 without recomputing its entry_hash.
    chain[1].evidence_hash = "sha256:evil".to_string();
    let r = verify(&chain);
    assert!(!r.ok);
    assert_eq!(r.broken_at, Some(2));
}

#[test]
fn deleting_an_entry_breaks_the_chain() {
    let mut chain = build(&["sha256:a", "sha256:b", "sha256:c"]);
    chain.remove(1); // drop seq 2; seq 3 now follows seq 1
    let r = verify(&chain);
    assert!(!r.ok);
    assert_eq!(r.broken_at, Some(3));
}

#[test]
fn reordering_breaks_the_chain() {
    let mut chain = build(&["sha256:a", "sha256:b", "sha256:c"]);
    chain.swap(0, 1);
    let r = verify(&chain);
    assert!(!r.ok);
}
