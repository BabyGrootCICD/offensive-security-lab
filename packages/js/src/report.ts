import type { Finding, Report } from "./types.js";

export function createReport(findings: Finding[]): Report {
  return { version: 1, scanner: "js", findings };
}

export function renderMarkdown(report: Report): string {
  let high = 0;
  let medium = 0;
  for (const finding of report.findings) {
    if (finding.severity === "high") {
      high += 1;
    } else if (finding.severity === "medium") {
      medium += 1;
    }
  }
  const lines = [
    "# 可能的 SSRF",
    "",
    "此報告只來自原始碼靜態檢查，沒有對任何網址送出請求。結果是啟發式判斷，需要人工確認。",
    "",
    "## 摘要",
    "",
    `- 發現數：${report.findings.length}`,
    `- 高：${high}`,
    `- 中：${medium}`,
    "",
    "## 發現",
    "",
  ];
  if (report.findings.length === 0) {
    lines.push("沒有發現符合規則的寫法。仍須人工確認掃描範圍是否涵蓋實際的 HTTP client。");
    lines.push("");
  }
  report.findings.forEach((finding, index) => {
    lines.push(`### ${index + 1}. ${finding.ruleId} ${finding.title}`, "");
    lines.push(`- 嚴重度：${finding.severity}`);
    lines.push(`- 檔案：\`${finding.file}\``);
    lines.push(`- 行號：${finding.line}`);
    lines.push(`- Source：\`${inline(finding.source)}\``);
    lines.push(`- Sink：\`${inline(finding.sink)}\``);
    lines.push(`- 影響：${finding.impact}`);
    lines.push(`- 修復建議：${finding.remediation}`, "");
    lines.push("片段：", "", "```", finding.snippet, "```", "");
  });
  return lines.join("\n");
}

function inline(value: string): string {
  return value.replaceAll("`", "'");
}
