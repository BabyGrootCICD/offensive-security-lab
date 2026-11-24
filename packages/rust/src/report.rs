use serde::Serialize;

use crate::scan::Finding;

#[derive(Serialize)]
pub struct Document {
    pub version: u32,
    pub scanner: &'static str,
    pub findings: Vec<Finding>,
}

pub fn document(findings: Vec<Finding>) -> Document {
    Document {
        version: 1,
        scanner: "rust",
        findings,
    }
}

pub fn render_markdown(doc: &Document) -> String {
    let mut high = 0;
    let mut medium = 0;
    for finding in &doc.findings {
        match finding.severity.as_str() {
            "high" => high += 1,
            "medium" => medium += 1,
            _ => {}
        }
    }
    let mut out = String::new();
    out.push_str("# 可能的 SSRF\n\n");
    out.push_str(
        "此報告只來自原始碼靜態檢查，沒有對任何網址送出請求。結果是啟發式判斷，需要人工確認。\n\n",
    );
    out.push_str("## 摘要\n\n");
    out.push_str(&format!(
        "- 發現數：{}\n- 高：{high}\n- 中：{medium}\n\n",
        doc.findings.len()
    ));
    out.push_str("## 發現\n\n");
    if doc.findings.is_empty() {
        out.push_str("沒有發現符合規則的寫法。仍須人工確認掃描範圍是否涵蓋實際的 HTTP client。\n");
    }
    for (index, finding) in doc.findings.iter().enumerate() {
        out.push_str(&format!(
            "### {}. {} {}\n\n- 嚴重度：{}\n- 檔案：`{}`\n- 行號：{}\n- Source：`{}`\n- Sink：`{}`\n- 影響：{}\n- 修復建議：{}\n\n片段：\n\n```\n{}\n```\n\n",
            index + 1,
            finding.rule_id,
            finding.title,
            finding.severity,
            finding.file,
            finding.line,
            inline(&finding.source),
            inline(&finding.sink),
            finding.impact,
            finding.remediation,
            finding.snippet
        ));
    }
    out
}

fn inline(value: &str) -> String {
    value.replace('`', "'")
}
