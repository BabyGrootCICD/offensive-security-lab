#!/usr/bin/env node
import fs from "node:fs";
import { scanReport, reportMarkdown } from "./scan.js";

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const report = scanReport(args.path, args.rules);
  const json = `${JSON.stringify(report, null, 2)}\n`;
  const markdown = reportMarkdown(report);
  if (!args.jsonOut && !args.mdOut) {
    process.stdout.write(json);
    return;
  }
  if (args.jsonOut) {
    fs.writeFileSync(args.jsonOut, json);
  }
  if (args.mdOut) {
    fs.writeFileSync(args.mdOut, markdown);
  }
}

function parseArgs(argv: string[]): { path: string; rules: string; jsonOut: string; mdOut: string } {
  let scanPath = "";
  let rules = "";
  let jsonOut = "";
  let mdOut = "";
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1] ?? "";
    if (arg === "--path") {
      scanPath = next;
      i += 1;
    } else if (arg === "--rules") {
      rules = next;
      i += 1;
    } else if (arg === "--json-out") {
      jsonOut = next;
      i += 1;
    } else if (arg === "--md-out") {
      mdOut = next;
      i += 1;
    } else if (arg === "--help") {
      console.log("ssrf-scan --path <dir> --rules <rules.json> [--json-out file] [--md-out file]");
      process.exit(0);
    } else {
      throw new Error(`未知參數 ${arg}`);
    }
  }
  if (!scanPath || !rules) {
    throw new Error("需要 --path 與 --rules");
  }
  return { path: scanPath, rules, jsonOut, mdOut };
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`ssrf-scan: ${message}`);
  process.exit(1);
}
