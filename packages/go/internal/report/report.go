// Package report 把靜態檢查結果寫成 JSON 與 Markdown。
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Finding 是一筆原始碼發現。它描述寫法與修法，不是一筆可重播的請求。
type Finding struct {
	RuleID      string `json:"ruleId"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Source      string `json:"source"`
	Sink        string `json:"sink"`
	Impact      string `json:"impact"`
	Remediation string `json:"remediation"`
	Snippet     string `json:"snippet"`
}

// Document 是一份掃描器報告。
type Document struct {
	Version  int       `json:"version"`
	Scanner  string    `json:"scanner"`
	Findings []Finding `json:"findings"`
}

// New 建立版本固定的報告。沒有發現時 findings 仍是空陣列，而不是 null。
func New(scanner string, findings []Finding) Document {
	if findings == nil {
		findings = []Finding{}
	}
	return Document{Version: 1, Scanner: scanner, Findings: findings}
}

// WriteJSON 以縮排 JSON 寫出報告。
func WriteJSON(w io.Writer, doc Document) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}
	return nil
}

// WriteMarkdown 寫出繁體中文報告。沒有發現時仍說明這是靜態結果，需要人工確認。
func WriteMarkdown(w io.Writer, doc Document) error {
	var b strings.Builder
	b.WriteString("# 可能的 SSRF\n\n")
	b.WriteString("此報告只來自原始碼靜態檢查，沒有對任何網址送出請求。結果是啟發式判斷，需要人工確認。\n\n")
	high, medium := 0, 0
	for _, finding := range doc.Findings {
		switch finding.Severity {
		case "high":
			high++
		case "medium":
			medium++
		}
	}
	fmt.Fprintf(&b, "## 摘要\n\n- 發現數：%d\n- 高：%d\n- 中：%d\n\n## 發現\n\n", len(doc.Findings), high, medium)
	if len(doc.Findings) == 0 {
		b.WriteString("沒有發現符合規則的寫法。仍須人工確認掃描範圍是否涵蓋實際的 HTTP client。\n")
	}
	for i, finding := range doc.Findings {
		fmt.Fprintf(&b, "### %d. %s %s\n\n", i+1, finding.RuleID, finding.Title)
		fmt.Fprintf(&b, "- 嚴重度：%s\n", finding.Severity)
		fmt.Fprintf(&b, "- 檔案：`%s`\n", finding.File)
		fmt.Fprintf(&b, "- 行號：%d\n", finding.Line)
		fmt.Fprintf(&b, "- Source：`%s`\n", inline(finding.Source))
		fmt.Fprintf(&b, "- Sink：`%s`\n", inline(finding.Sink))
		fmt.Fprintf(&b, "- 影響：%s\n", finding.Impact)
		fmt.Fprintf(&b, "- 修復建議：%s\n\n", finding.Remediation)
		b.WriteString("片段：\n\n```\n")
		b.WriteString(finding.Snippet)
		b.WriteString("\n```\n\n")
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write markdown report: %w", err)
	}
	return nil
}

func inline(value string) string {
	return strings.ReplaceAll(value, "`", "'")
}
