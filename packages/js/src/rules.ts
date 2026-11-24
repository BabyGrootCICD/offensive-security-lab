import fs from "node:fs";
import type { Rule } from "./types.js";

const required = ["SSRF-001", "SSRF-002", "SSRF-003", "SSRF-004", "SSRF-005"];

export function loadRules(file: string): Map<string, Rule> {
  const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as {
    version: number;
    rules: Rule[];
  };
  if (parsed.version !== 1) {
    throw new Error(`unsupported rules version ${parsed.version}`);
  }
  const rules = new Map<string, Rule>();
  for (const rule of parsed.rules) {
    if (rule.severity !== "high" && rule.severity !== "medium") {
      throw new Error(`rule ${rule.id} has unsupported severity`);
    }
    rules.set(rule.id, rule);
  }
  for (const id of required) {
    if (!rules.has(id)) {
      throw new Error(`rules file missing ${id}`);
    }
  }
  return rules;
}
