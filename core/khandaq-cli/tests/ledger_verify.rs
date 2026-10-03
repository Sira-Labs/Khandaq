//! `khandaq-core ledger-verify` (spec 013): offline verification of an exported ledger against a
//! report's pin. Chains are built with the core's own `append` over synthetic hashes.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use khandaq_core::{ledger_append, ledger_root, LedgerEntry};
use serde_json::json;

fn chain(n: usize) -> Vec<LedgerEntry> {
    let mut entries: Vec<LedgerEntry> = Vec::new();
    for i in 0..n {
        let evidence = format!("sha256:{:064x}", i + 1);
        entries.push(ledger_append(entries.last(), &evidence).unwrap());
    }
    entries
}

/// Write `value` to a fresh file in the target's temp dir and return its path.
fn write(value: &serde_json::Value) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join(format!(
        "ledger-{}-{}.json",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    path
}

fn verify(file: &PathBuf, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_khandaq-core"))
        .arg("ledger-verify")
        .arg(file)
        .args(args)
        .output()
        .unwrap()
}

fn report(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn ledger_verify_intact() {
    let entries = chain(3);
    let root = ledger_root(&entries[..2]).unwrap();
    // The whole `GET /ledger` response, extra keys included, as an auditor would save it.
    let file = write(&json!({"entries": entries, "root": ledger_root(&entries), "count": 3}));

    let plain = verify(&file, &[]);
    assert_eq!(plain.status.code(), Some(0));
    assert_eq!(report(&plain)["ok"], true);

    // A pin taken when the chain had two entries still holds after a third was appended.
    let pinned = verify(&file, &["--root", &root, "--count", "2"]);
    assert_eq!(pinned.status.code(), Some(0), "{}", report(&pinned));
    assert_eq!(report(&pinned)["count"], 3);

    // A bare entries array is accepted too.
    let bare = write(&serde_json::to_value(&entries).unwrap());
    assert_eq!(verify(&bare, &[]).status.code(), Some(0));
}

#[test]
fn ledger_verify_pin_mismatch() {
    let entries = chain(3);
    let root = ledger_root(&entries).unwrap();
    let file = write(&serde_json::to_value(&entries[..2]).unwrap()); // last entry removed

    let out = verify(&file, &["--root", &root, "--count", "3"]);
    assert_eq!(out.status.code(), Some(1));
    let r = report(&out);
    assert_eq!(r["ok"], false);
    assert!(r["reason"]
        .as_str()
        .unwrap()
        .contains("entries were removed"));

    let forged = format!("sha256:{}", "ab".repeat(32));
    let full = write(&serde_json::to_value(&entries).unwrap());
    let out = verify(&full, &["--root", &forged, "--count", "3"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(report(&out)["broken_at"], 3);
}

#[test]
fn ledger_verify_tampered() {
    let mut entries = chain(3);
    let root = ledger_root(&entries).unwrap();
    entries[1].evidence_hash = format!("sha256:{}", "0".repeat(64));
    let file = write(&serde_json::to_value(&entries).unwrap());

    for args in [vec![], vec!["--root", root.as_str(), "--count", "3"]] {
        let out = verify(&file, &args);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(report(&out)["broken_at"], 2);
    }
}

#[test]
fn ledger_verify_requires_root_and_count_together() {
    let entries = chain(1);
    let root = ledger_root(&entries).unwrap();
    let file = write(&serde_json::to_value(&entries).unwrap());
    assert_eq!(verify(&file, &["--root", &root]).status.code(), Some(2));
    assert_eq!(verify(&file, &["--count", "1"]).status.code(), Some(2));
}

#[test]
fn ledger_verify_bad_input() {
    let missing = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("no-such-ledger.json");
    assert_eq!(verify(&missing, &[]).status.code(), Some(2));
    let not_a_ledger = write(&json!({"entries": [{"seq": "one"}]}));
    assert_eq!(verify(&not_a_ledger, &[]).status.code(), Some(2));
}
