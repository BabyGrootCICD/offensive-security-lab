// Package rules 讀取共用的 SSRF 靜態規則。規則只描述弱點與修法，不含可送出的請求。
package rules

import (
	"encoding/json"
	"fmt"
	"os"
)

// requiredIDs 是三個掃描器都必須能解釋的規則。
var requiredIDs = []string{"SSRF-001", "SSRF-002", "SSRF-003", "SSRF-004", "SSRF-005"}

// Rule 是一條給報告使用的靜態規則。
type Rule struct {
	ID          string              `json:"id"`
	Severity    string              `json:"severity"`
	Title       string              `json:"title"`
	Impact      string              `json:"impact"`
	Remediation string              `json:"remediation"`
	Sinks       map[string][]string `json:"sinks,omitempty"`
}

// Set 是一份規則檔。
type Set struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
	byID    map[string]Rule
}

// Load 從 JSON 檔載入規則，並確認必要規則都在。
func Load(path string) (*Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	var set Set
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	if set.Version != 1 {
		return nil, fmt.Errorf("unsupported rules version %d", set.Version)
	}
	set.byID = make(map[string]Rule, len(set.Rules))
	for _, rule := range set.Rules {
		if rule.ID == "" || rule.Title == "" || rule.Impact == "" || rule.Remediation == "" {
			return nil, fmt.Errorf("rule %q is missing text", rule.ID)
		}
		switch rule.Severity {
		case "high", "medium":
		default:
			return nil, fmt.Errorf("rule %s has unsupported severity %q", rule.ID, rule.Severity)
		}
		set.byID[rule.ID] = rule
	}
	for _, id := range requiredIDs {
		if _, ok := set.byID[id]; !ok {
			return nil, fmt.Errorf("rules file missing %s", id)
		}
	}
	return &set, nil
}

// Get 回傳指定規則。
func (s *Set) Get(id string) (Rule, error) {
	rule, ok := s.byID[id]
	if !ok {
		return Rule{}, fmt.Errorf("unknown rule %s", id)
	}
	return rule, nil
}
