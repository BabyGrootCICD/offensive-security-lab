package report

import (
	"strings"
	"testing"
)

func TestMarkdownStatesStaticLimit(t *testing.T) {
	var b strings.Builder
	doc := New("go", nil)
	if err := WriteMarkdown(&b, doc); err != nil {
		t.Fatal(err)
	}
	text := b.String()
	if !strings.Contains(text, "可能的 SSRF") {
		t.Fatal("missing title")
	}
	if !strings.Contains(text, "沒有對任何網址送出請求") {
		t.Fatal("missing static-only statement")
	}
	if !strings.Contains(text, "需要人工確認") {
		t.Fatal("missing human review statement")
	}
}
