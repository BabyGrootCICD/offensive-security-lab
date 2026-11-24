package scan

import (
	"path/filepath"
	"runtime"
	"testing"

	"offensive-security-lab/packages/go/internal/report"
	"offensive-security-lab/packages/go/internal/rules"
)

func TestFixtures(t *testing.T) {
	ruleSet := loadRules(t)
	tests := []struct {
		dir    string
		ruleID string
		sev    string
		absent []string
	}{
		{dir: "vulnerable", ruleID: "SSRF-001", sev: "high"},
		{dir: "fixed", absent: []string{"SSRF-001", "SSRF-002", "SSRF-003", "SSRF-004", "SSRF-005"}},
		{dir: "allowlist", absent: []string{"SSRF-001"}},
		{dir: "denylist", ruleID: "SSRF-002", sev: "medium"},
		{dir: "substring", ruleID: "SSRF-003", sev: "medium"},
		{dir: "redirect", ruleID: "SSRF-004", sev: "medium"},
		{dir: "loopback", ruleID: "SSRF-005", sev: "medium"},
	}
	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			findings, err := Scan(filepath.Join(testdataDir(t), tt.dir), ruleSet)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if tt.ruleID != "" && !hasFinding(findings, tt.ruleID, tt.sev) {
				t.Fatalf("missing %s/%s in %#v", tt.ruleID, tt.sev, findings)
			}
			for _, id := range tt.absent {
				if hasRule(findings, id) {
					t.Fatalf("unexpected %s in %#v", id, findings)
				}
			}
		})
	}
}

func hasFinding(findings []report.Finding, ruleID, severity string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID && finding.Severity == severity {
			return true
		}
	}
	return false
}

func hasRule(findings []report.Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}

func loadRules(t *testing.T) *rules.Set {
	t.Helper()
	set, err := rules.Load(filepath.Join(repoRoot(t), "rules", "ssrf-rules.json"))
	if err != nil {
		t.Fatalf("Load rules: %v", err)
	}
	return set
}

func testdataDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "packages", "go", "internal", "scan", "testdata")
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}
