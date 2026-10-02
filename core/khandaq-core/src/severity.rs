//! Normalised five-level severity and per-adapter mapping (ADR-0004).

use std::collections::HashMap;

/// The normalised severity scale. Ordered: Info < Low < Medium < High < Critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// An adapter's documented mapping from a tool's native severity to the canonical scale.
#[derive(Debug, Clone, Default)]
pub struct AdapterSeverityTable {
    map: HashMap<String, Severity>,
    default: Option<Severity>,
}

impl AdapterSeverityTable {
    pub fn new(
        entries: impl IntoIterator<Item = (String, Severity)>,
        default: Option<Severity>,
    ) -> Self {
        Self {
            map: entries
                .into_iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), v))
                .collect(),
            default,
        }
    }

    /// Map a native severity string to the canonical scale, falling back to the table default.
    pub fn map(&self, native: &str) -> Option<Severity> {
        self.map
            .get(&native.to_ascii_lowercase())
            .copied()
            .or(self.default)
    }
}
