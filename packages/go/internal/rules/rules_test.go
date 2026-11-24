package rules

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadSharedRules(t *testing.T) {
	set, err := Load(sharedRulesPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, id := range []string{"SSRF-001", "SSRF-002", "SSRF-003", "SSRF-004", "SSRF-005"} {
		rule, err := set.Get(id)
		if err != nil {
			t.Fatalf("Get %s: %v", id, err)
		}
		if rule.Severity != "high" && rule.Severity != "medium" {
			t.Fatalf("%s severity = %s", id, rule.Severity)
		}
	}
	high, err := set.Get("SSRF-001")
	if err != nil {
		t.Fatal(err)
	}
	if high.Severity != "high" {
		t.Fatalf("SSRF-001 severity = %s", high.Severity)
	}
	if len(high.Sinks["go"]) == 0 || len(high.Sinks["js"]) == 0 || len(high.Sinks["rust"]) == 0 {
		t.Fatal("SSRF-001 is missing a language sink list")
	}
}

func sharedRulesPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "rules", "ssrf-rules.json"))
}
