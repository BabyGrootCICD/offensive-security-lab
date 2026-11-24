import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createReport, renderMarkdown } from "../dist/report.js";
import { scanPath } from "../dist/scan.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../../..");
const rules = path.join(repoRoot, "rules", "ssrf-rules.json");
const fixtures = path.join(here, "fixtures");

test("markdown states the static limit", () => {
  const text = renderMarkdown(createReport([]));
  assert.match(text, /可能的 SSRF/);
  assert.match(text, /沒有對任何網址送出請求/);
  assert.match(text, /需要人工確認/);
});

test("fixtures match rule ids and severities", () => {
  const cases = [
    { dir: "vulnerable", ruleId: "SSRF-001", severity: "high" },
    { dir: "fixed", absent: ["SSRF-001", "SSRF-002", "SSRF-003", "SSRF-004", "SSRF-005"] },
    { dir: "allowlist", absent: ["SSRF-001"] },
    { dir: "denylist", ruleId: "SSRF-002", severity: "medium" },
    { dir: "substring", ruleId: "SSRF-003", severity: "medium" },
    { dir: "redirect", ruleId: "SSRF-004", severity: "medium" },
    { dir: "loopback", ruleId: "SSRF-005", severity: "medium" },
  ];
  for (const item of cases) {
    const findings = scanPath(path.join(fixtures, item.dir), rules);
    if (item.ruleId) {
      assert.ok(
        findings.some((finding) => finding.ruleId === item.ruleId && finding.severity === item.severity),
        `${item.dir} missing ${item.ruleId}`,
      );
    }
    for (const id of item.absent ?? []) {
      assert.equal(
        findings.some((finding) => finding.ruleId === id),
        false,
        `${item.dir} unexpected ${id}`,
      );
    }
  }
});
