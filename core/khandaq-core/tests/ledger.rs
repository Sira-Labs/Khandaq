//! Tests for the hash-chained evidence ledger (spec 004).

use khandaq_core::ledger::{append, is_hash, root, verify, verify_pinned, LedgerEntry};

/// A well-formed synthetic evidence hash: `sha256:` + 64 hex digits.
fn h(n: u8) -> String {
    format!("sha256:{}", format!("{n:02x}").repeat(32))
}

fn build(n: u8) -> Vec<LedgerEntry> {
    let mut chain: Vec<LedgerEntry> = Vec::new();
    for i in 1..=n {
        let next = append(chain.last(), &h(i)).expect("well-formed hash");
        chain.push(next);
    }
    chain
}

#[test]
fn chain_builds_and_verifies() {
    let chain = build(3);
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
    let mut chain = build(2);
    let r1 = root(&chain).unwrap();
    assert_eq!(r1, chain.last().unwrap().entry_hash);
    // Appending changes the root; the prior entries are unchanged.
    let next = append(chain.last(), &h(3)).unwrap();
    chain.push(next);
    assert_ne!(root(&chain).unwrap(), r1);
}

#[test]
fn tampering_with_evidence_is_detected_at_its_seq() {
    let mut chain = build(3);
    // Swap in another (well-formed) evidence hash for entry 2 without recomputing its entry_hash.
    chain[1].evidence_hash = h(99);
    let r = verify(&chain);
    assert!(!r.ok);
    assert_eq!(r.broken_at, Some(2));
}

#[test]
fn deleting_an_entry_breaks_the_chain() {
    let mut chain = build(3);
    chain.remove(1); // drop seq 2; seq 3 now follows seq 1
    let r = verify(&chain);
    assert!(!r.ok);
    assert_eq!(r.broken_at, Some(3));
}

#[test]
fn reordering_breaks_the_chain() {
    let mut chain = build(3);
    chain.swap(0, 1);
    let r = verify(&chain);
    assert!(!r.ok);
}

// --- hardening (code review, 2026-10-02) -----------------------------------------------------

#[test]
fn append_refuses_malformed_evidence_hashes() {
    for bad in [
        "",
        "sha256:a",
        "abcd",
        &h(1).to_uppercase(),  // one spelling only: lowercase hex
        &format!("{}0", h(1)), // 65 hex digits
        &h(1).replace("sha256:", "md5:"),
        &format!("sha256:{}", "g".repeat(64)),
    ] {
        assert!(append(None, bad).is_err(), "{bad}");
        assert!(!is_hash(bad), "{bad}");
    }
    assert!(is_hash(&h(1)));
}

#[test]
fn append_refuses_a_sequence_overflow() {
    let mut last = append(None, &h(1)).unwrap();
    last.seq = i64::MAX;
    assert!(append(Some(&last), &h(2)).is_err());
}

#[test]
fn verify_does_not_panic_on_a_maximal_seq() {
    // `seq + 1` used to overflow (a panic across the Python binding) on a hostile chain.
    let mut chain = build(2);
    chain[0].seq = i64::MAX;
    assert!(!verify(&chain).ok);
}

#[test]
fn verify_rejects_malformed_hashes() {
    let mut chain = build(2);
    chain[0].evidence_hash = "sha256:a".into();
    let r = verify(&chain);
    assert!(!r.ok && r.broken_at == Some(1));
}

#[test]
fn verify_pinned_detects_truncation() {
    let chain = build(3);
    let pinned_root = root(&chain).unwrap();
    // Plain verify cannot tell a chain with its tail removed from a shorter honest chain.
    assert!(verify(&chain[..2]).ok);
    let r = verify_pinned(&chain[..2], &pinned_root, 3);
    assert!(!r.ok, "{r:?}");
    assert!(r.reason.unwrap().contains("shorter"));
}

#[test]
fn verify_pinned_allows_growth_but_not_rewrites() {
    let mut chain = build(3);
    let pinned_root = root(&chain).unwrap();
    let next = append(chain.last(), &h(4)).unwrap();
    chain.push(next);
    assert!(verify_pinned(&chain, &pinned_root, 3).ok); // appended since the pin: fine

    // An attacker rebuilds a consistent chain from entry 2 onwards: it verifies on its own,
    // but no longer matches the pin.
    let mut forged = vec![chain[0].clone()];
    for i in 2..=4 {
        let next = append(forged.last(), &h(100 + i)).unwrap();
        forged.push(next);
    }
    assert!(verify(&forged).ok);
    let r = verify_pinned(&forged, &pinned_root, 3);
    assert!(!r.ok && r.broken_at == Some(3), "{r:?}");
    assert!(!verify_pinned(&chain, &pinned_root, 0).ok);
}
