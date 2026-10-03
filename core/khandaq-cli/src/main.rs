//! `khandaq-core` — offline CLI over the Khandaq core.
//!
//! Lets an operator validate findings, normalise them (fingerprint + framework mapping + dedup),
//! export a MITRE ATLAS Navigator layer and verify an exported evidence ledger against a report's
//! pin, without the full control plane (ADR-0011, spec 013). Input is a JSON finding or an array of
//! findings (or, for `ledger-verify`, a ledger export); output is JSON on stdout.

use std::fs;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use khandaq_core::{
    dedup, ledger_verify, ledger_verify_pinned, merge_mappings, navigator_layer, validate,
    LedgerEntry, Mappings,
};
use serde_json::Value;

#[derive(Parser)]
#[command(name = "khandaq-core", about = "Offline Khandaq findings tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a finding or an array of findings against the canonical schema.
    Validate { file: String },
    /// Normalise findings: validate, fingerprint, apply framework mappings, then dedup.
    Normalize {
        file: String,
        /// Adapter name (recorded for provenance; reserved for per-adapter normalisation, spec 006).
        #[arg(long)]
        adapter: Option<String>,
    },
    /// Export a MITRE ATLAS Navigator layer from a set of findings.
    Navigator { file: String },
    /// Verify an exported evidence ledger, optionally against a report's pin (spec 013).
    ///
    /// FILE is the JSON of `GET /api/engagements/{id}/ledger`, or just its `entries` array. Exits
    /// 0 when intact, 1 when broken, 2 on unreadable input.
    LedgerVerify {
        file: String,
        /// The report's pinned ledger root (`evidence.root`).
        #[arg(long, requires = "count")]
        root: Option<String>,
        /// The number of entries the pinned root covers (`evidence.count`); at least 1.
        #[arg(long, requires = "root")]
        count: Option<usize>,
    },
}

/// `ledger-verify` exit codes; clap's own usage errors also exit 2.
const EXIT_BROKEN: u8 = 1;
const EXIT_BAD_INPUT: u8 = 2;

fn load(file: &str) -> Result<Vec<Value>, String> {
    let text = fs::read_to_string(file).map_err(|e| format!("cannot read {file}: {e}"))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("invalid JSON: {e}"))?;
    Ok(match value {
        Value::Array(items) => items,
        other => vec![other],
    })
}

fn load_ledger(file: &str) -> Result<Vec<LedgerEntry>, String> {
    let text = fs::read_to_string(file).map_err(|e| format!("cannot read {file}: {e}"))?;
    let mut value: Value = serde_json::from_str(&text).map_err(|e| format!("invalid JSON: {e}"))?;
    if let Some(entries) = value.get_mut("entries") {
        value = entries.take(); // the whole `GET /ledger` response
    }
    serde_json::from_value(value).map_err(|e| format!("not a ledger entry array: {e}"))
}

/// Verify offline, without trusting the instance's verdict: the entries must chain together and,
/// with a pin, still reach the pinned root at the pinned count (catches truncation). The entries'
/// `evidence_hash` values are taken as exported; recomputing them needs the evidence itself.
fn ledger_verify_cmd(file: &str, pin: Option<(String, usize)>) -> ExitCode {
    let entries = match load_ledger(file) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(EXIT_BAD_INPUT);
        }
    };
    let result = match &pin {
        Some((root, count)) => ledger_verify_pinned(&entries, root, *count),
        None => ledger_verify(&entries),
    };
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    if result.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_BROKEN)
    }
}

fn run() -> Result<ExitCode, String> {
    match Cli::parse().command {
        Command::Validate { file } => {
            let items = load(&file)?;
            for (i, item) in items.iter().enumerate() {
                validate(item).map_err(|e| format!("finding {i}: {e}"))?;
            }
            println!("ok: {} finding(s) valid", items.len());
        }
        Command::Normalize { file, adapter: _ } => {
            let items = load(&file)?;
            let mappings = Mappings::builtin();
            let mut findings = Vec::new();
            for (i, item) in items.iter().enumerate() {
                let mut f = validate(item).map_err(|e| format!("finding {i}: {e}"))?;
                f.x_khandaq.mappings = merge_mappings(&f, &mappings);
                findings.push(f);
            }
            let result = dedup(findings);
            let out = serde_json::json!({
                "canonical": result.canonical,
                "duplicates": result.duplicates,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        Command::Navigator { file } => {
            let items = load(&file)?;
            let mut findings = Vec::new();
            for (i, item) in items.iter().enumerate() {
                findings.push(validate(item).map_err(|e| format!("finding {i}: {e}"))?);
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&navigator_layer(&findings)).unwrap()
            );
        }
        Command::LedgerVerify { file, root, count } => {
            // clap's `requires` guarantees both or neither.
            return Ok(ledger_verify_cmd(&file, root.zip(count)));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
