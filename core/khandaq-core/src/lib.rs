//! Khandaq core: the canonical finding model and the integrity-critical operations on it
//! (validate, fingerprint, dedup, severity, framework mapping). See ADR-0003, ADR-0011.
//!
//! This crate is pure and deterministic; it performs no I/O. It is consumed by the Python control
//! plane through the `khandaq-py` PyO3 wheel and by the `khandaq-cli` binary.

pub mod dedup;
pub mod finding;
pub mod fingerprint;
pub mod ledger;
pub mod mapping;
pub mod severity;

pub use dedup::{dedup, DedupResult};
pub use finding::{validate, Finding, Mapping, SchemaError, Source, XKhandaq, SCHEMA_ID};
pub use fingerprint::fingerprint;
pub use ledger::{
    append as ledger_append, entry_hash, root as ledger_root, verify as ledger_verify,
    verify_pinned as ledger_verify_pinned, LedgerEntry, LedgerError, VerifyResult,
};
pub use mapping::{map_frameworks, navigator_layer, Mappings};
pub use severity::{AdapterSeverityTable, Severity};
