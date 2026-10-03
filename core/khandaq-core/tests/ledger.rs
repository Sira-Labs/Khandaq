//! Tests for the hash-chained evidence ledger (spec 004).

use khandaq_core::ledger::{
    append, entry_hash, entry_hash_for, evidence_record_hash, is_hash, root, verify, verify_pinned,
    EvidenceRecord, LedgerEntry, LEDGER_FORMAT,
};

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

// --- ADR-0014: format 2 binds the evidence metadata ------------------------------------------

/// A chain as the pre-ADR-0014 core wrote it: format 1 throughout.
fn build_v1(n: u8) -> Vec<LedgerEntry> {
    let mut chain: Vec<LedgerEntry> = Vec::new();
    for i in 1..=n {
        let prev_hash = chain.last().map(|p| p.entry_hash.clone());
        let seq = i64::from(i);
        chain.push(LedgerEntry {
            seq,
            evidence_hash: h(i),
            entry_hash: entry_hash(seq, &h(i), prev_hash.as_deref()),
            prev_hash,
            format: 1,
        });
    }
    chain
}

fn record() -> EvidenceRecord {
    EvidenceRecord {
        id: "ev_1".into(),
        engagement_id: "eng_1".into(),
        run_id: "run_1".into(),
        kind: "transcript".into(),
        object_key: "eng_1/run_1/e1.json".into(),
        sha256: h(1),
        bytes: 42,
        redacted: false,
    }
}

#[test]
fn append_writes_the_current_format() {
    let chain = build(2);
    assert!(chain
        .iter()
        .all(|e| e.format == LEDGER_FORMAT && e.format == 2));
    // The format tag is part of the hash: the same inputs hash differently under format 1.
    assert_ne!(chain[0].entry_hash, entry_hash(1, &h(1), None));
    assert_eq!(
        Some(chain[0].entry_hash.clone()),
        entry_hash_for(2, 1, &h(1), None)
    );
}

#[test]
fn an_existing_format_1_chain_still_verifies_and_can_grow() {
    let mut chain = build_v1(3);
    assert!(verify(&chain).ok);
    let next = append(chain.last(), &h(4)).unwrap();
    assert_eq!(next.format, 2);
    chain.push(next);
    assert!(verify(&chain).ok);
}

#[test]
fn entries_without_a_format_field_read_as_format_1() {
    let chain = build_v1(1);
    let mut json = serde_json::to_value(&chain[0]).unwrap();
    json.as_object_mut().unwrap().remove("format");
    let back: LedgerEntry = serde_json::from_value(json).unwrap();
    assert_eq!(back, chain[0]);
}

#[test]
fn a_format_2_entry_cannot_be_relabelled_as_format_1() {
    // The downgrade attack: re-read a metadata-bound entry under the content-hash-only format.
    let mut chain = build(2);
    chain[1].format = 1;
    let r = verify(&chain);
    assert!(!r.ok && r.broken_at == Some(2), "{r:?}");
    let mut chain = build(1);
    chain[0].format = 1;
    assert!(!verify(&chain).ok);
}

#[test]
fn formats_may_not_go_down_along_the_chain() {
    // A well-formed format-1 entry after a format-2 one is refused, even with a correct hash.
    let mut chain = build(1);
    let prev_hash = Some(chain[0].entry_hash.clone());
    chain.push(LedgerEntry {
        seq: 2,
        evidence_hash: h(2),
        entry_hash: entry_hash(2, &h(2), prev_hash.as_deref()),
        prev_hash,
        format: 1,
    });
    let r = verify(&chain);
    assert!(!r.ok && r.broken_at == Some(2), "{r:?}");
}

#[test]
fn an_unknown_format_is_refused() {
    let mut chain = build(1);
    chain[0].format = 3;
    let r = verify(&chain);
    assert!(
        !r.ok && r.reason.as_deref() == Some("unknown entry format"),
        "{r:?}"
    );
}

#[test]
fn every_evidence_field_is_bound() {
    let base = evidence_record_hash(&record()).unwrap();
    let variants: [fn(&mut EvidenceRecord); 8] = [
        |r| r.id = "ev_2".into(),
        |r| r.engagement_id = "eng_2".into(),
        |r| r.run_id = "run_2".into(),
        |r| r.kind = "artefact".into(),
        |r| r.object_key = "eng_1/run_1/other.json".into(),
        |r| r.sha256 = h(2),
        |r| r.bytes = 43,
        |r| r.redacted = true,
    ];
    for (i, change) in variants.iter().enumerate() {
        let mut r = record();
        change(&mut r);
        assert_ne!(evidence_record_hash(&r).unwrap(), base, "field {i}");
    }
}

#[test]
fn malformed_evidence_records_are_refused() {
    let mut r = record();
    r.sha256 = "sha256:a".into();
    assert!(evidence_record_hash(&r).is_err());
    let mut r = record();
    r.object_key = String::new();
    assert!(evidence_record_hash(&r).is_err());
    let mut r = record();
    r.bytes = -1;
    assert!(evidence_record_hash(&r).is_err());
    // Unknown fields are refused, so a caller cannot believe it bound a field it did not.
    let mut json = serde_json::to_value(record()).unwrap();
    json["created_at"] = serde_json::json!("2026-10-03T00:00:00Z");
    assert!(serde_json::from_value::<EvidenceRecord>(json).is_err());
}

#[test]
fn the_evidence_record_hash_is_pinned() {
    // A change here changes every format-2 chain: it needs a new ledger format, never an edit.
    assert_eq!(evidence_record_hash(&record()).unwrap(), PINNED_RECORD);
    assert_eq!(entry_hash_for(2, 1, &h(1), None).unwrap(), PINNED_ENTRY);
}

// Both recomputed independently: sha256 over the sorted-key compact JSON of the record plus
// `"schema":"khandaq.evidence/2"`, and sha256("khandaq.ledger/2" NUL "1" NUL evidence_hash NUL "").
const PINNED_RECORD: &str =
    "sha256:1ce259a34653bf5fd84796c89607bfcdd408742746a653422fd1962c6f452f66";
const PINNED_ENTRY: &str =
    "sha256:f51fb48fae03d259855b3e41ebbf42f3b2304f6c4b221f67eacc343a5cb521c7";
