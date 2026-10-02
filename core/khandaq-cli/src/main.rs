//! `khandaq-core` — offline CLI over the Khandaq core.
//!
//! Lets an operator validate findings, normalise them (fingerprint + framework mapping + dedup) and
//! export a MITRE ATLAS Navigator layer without the full control plane (ADR-0011). Input is a JSON
//! finding or an array of findings; output is JSON on stdout.

use std::fs;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use khandaq_core::{dedup, map_frameworks, navigator_layer, validate, Mappings};
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
}

fn load(file: &str) -> Result<Vec<Value>, String> {
    let text = fs::read_to_string(file).map_err(|e| format!("cannot read {file}: {e}"))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("invalid JSON: {e}"))?;
    Ok(match value {
        Value::Array(items) => items,
        other => vec![other],
    })
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
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
                if f.x_khandaq.mappings.is_empty() {
                    f.x_khandaq.mappings = map_frameworks(&f, &mappings);
                }
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
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
