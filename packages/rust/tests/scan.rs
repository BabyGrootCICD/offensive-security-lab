use std::path::PathBuf;

use ssrf_scan::{load_rules, render_markdown, scan_path};

fn rules() -> ssrf_scan::RuleSet {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/ssrf-rules.json");
    load_rules(&path).expect("rules")
}

fn scan_fixture(name: &str) -> Vec<ssrf_scan::Finding> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    scan_path(&path, &rules()).expect("scan")
}

#[test]
fn markdown_states_static_limit() {
    let text = render_markdown(&ssrf_scan::document(Vec::new()));
    assert!(text.contains("可能的 SSRF"));
    assert!(text.contains("沒有對任何網址送出請求"));
    assert!(text.contains("需要人工確認"));
}

#[test]
fn fixtures_match_rule_ids() {
    assert!(has(&scan_fixture("vulnerable"), "SSRF-001", "high"));
    assert!(absent(
        &scan_fixture("fixed"),
        &["SSRF-001", "SSRF-002", "SSRF-003", "SSRF-004", "SSRF-005"]
    ));
    assert!(absent(&scan_fixture("allowlist"), &["SSRF-001"]));
    assert!(has(&scan_fixture("denylist"), "SSRF-002", "medium"));
    assert!(has(&scan_fixture("substring"), "SSRF-003", "medium"));
    assert!(has(&scan_fixture("redirect"), "SSRF-004", "medium"));
    assert!(has(&scan_fixture("loopback"), "SSRF-005", "medium"));
}

fn has(findings: &[ssrf_scan::Finding], rule_id: &str, severity: &str) -> bool {
    findings
        .iter()
        .any(|finding| finding.rule_id == rule_id && finding.severity == severity)
}

fn absent(findings: &[ssrf_scan::Finding], ids: &[&str]) -> bool {
    findings
        .iter()
        .all(|finding| !ids.contains(&finding.rule_id.as_str()))
}
