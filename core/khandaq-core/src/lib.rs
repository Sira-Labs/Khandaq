//! Khandaq core: the canonical finding model and the integrity-critical operations on it
//! (validate, fingerprint, dedup, severity, framework mapping). See ADR-0003, ADR-0011.
//!
//! This crate is pure and deterministic; it performs no I/O. It is consumed by the Python control
//! plane through the `khandaq-py` PyO3 wheel and by the `khandaq-cli` binary.

pub mod dedup;
pub mod finding;
pub mod fingerprint;
pub mod mapping;
pub mod severity;

pub use dedup::{dedup, DedupResult};
pub use finding::{validate, Finding, Mapping, SchemaError, Source, XKhandaq, SCHEMA_ID};
pub use fingerprint::fingerprint;
pub use mapping::{map_frameworks, navigator_layer, Mappings};
pub use severity::{AdapterSeverityTable, Severity};
