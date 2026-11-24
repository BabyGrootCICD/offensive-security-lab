use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub impact: String,
    pub remediation: String,
}

#[derive(Debug)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn get(&self, id: &str) -> Result<&Rule, String> {
        self.rules
            .iter()
            .find(|rule| rule.id == id)
            .ok_or_else(|| format!("unknown rule {id}"))
    }
}

pub fn load_rules(path: &Path) -> Result<RuleSet, String> {
    let text = fs::read_to_string(path).map_err(|err| format!("read rules: {err}"))?;
    let parsed: RuleFile =
        serde_json::from_str(&text).map_err(|err| format!("parse rules: {err}"))?;
    if parsed.version != 1 {
        return Err(format!("unsupported rules version {}", parsed.version));
    }
    for rule in &parsed.rules {
        if rule.severity != "high" && rule.severity != "medium" {
            return Err(format!(
                "rule {} has unsupported severity {}",
                rule.id, rule.severity
            ));
        }
    }
    let set = RuleSet {
        rules: parsed.rules,
    };
    for id in ["SSRF-001", "SSRF-002", "SSRF-003", "SSRF-004", "SSRF-005"] {
        set.get(id)?;
    }
    Ok(set)
}

#[derive(Deserialize)]
struct RuleFile {
    version: u32,
    rules: Vec<Rule>,
}
