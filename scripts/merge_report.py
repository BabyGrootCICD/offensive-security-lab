#!/usr/bin/env python3
"""Merge scanner JSON reports into one JSON file and one Traditional Chinese Markdown file."""

import argparse
import json
import sys
from pathlib import Path

SEVERITY_FAILS = {
    "none": set(),
    "high": {"high"},
    "medium": {"high", "medium"},
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="append", default=[], dest="json_files")
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--md-out", required=True)
    parser.add_argument("--fail-on", required=True, choices=sorted(SEVERITY_FAILS))
    args = parser.parse_args()

    findings = []
    for name in args.json_files:
        path = Path(name)
        if not path.exists():
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        findings.extend(document.get("findings", []))

    merged = dedupe(findings)
    report = {"version": 1, "scanner": "merged", "findings": merged}
    Path(args.json_out).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    Path(args.md_out).write_text(render_markdown(merged), encoding="utf-8")
    if any(item.get("severity") in SEVERITY_FAILS[args.fail_on] for item in merged):
        return 1
    return 0


def dedupe(findings: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for finding in findings:
        key = (finding.get("file"), finding.get("line"), finding.get("ruleId"), finding.get("sink"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    unique.sort(key=lambda item: (str(item.get("file")), int(item.get("line") or 0), str(item.get("ruleId"))))
    return unique


def render_markdown(findings: list[dict]) -> str:
    high = sum(1 for finding in findings if finding.get("severity") == "high")
    medium = sum(1 for finding in findings if finding.get("severity") == "medium")
    lines = [
        "# 可能的 SSRF",
        "",
        "此報告只來自原始碼靜態檢查，沒有對任何網址送出請求。結果是啟發式判斷，需要人工確認。",
        "",
        "## 摘要",
        "",
        f"- 發現數：{len(findings)}",
        f"- 高：{high}",
        f"- 中：{medium}",
        "",
        "## 發現",
        "",
    ]
    if not findings:
        lines.append("沒有發現符合規則的寫法。仍須人工確認掃描範圍是否涵蓋實際的 HTTP client。")
        lines.append("")
    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"### {index}. {finding.get('ruleId', '')} {finding.get('title', '')}",
                "",
                f"- 嚴重度：{finding.get('severity', '')}",
                f"- 檔案：`{finding.get('file', '')}`",
                f"- 行號：{finding.get('line', '')}",
                f"- Source：`{inline(str(finding.get('source', '')))}`",
                f"- Sink：`{inline(str(finding.get('sink', '')))}`",
                f"- 影響：{finding.get('impact', '')}",
                f"- 修復建議：{finding.get('remediation', '')}",
                "",
                "片段：",
                "",
                "```",
                str(finding.get("snippet", "")),
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def inline(value: str) -> str:
    return value.replace("`", "'")


if __name__ == "__main__":
    raise SystemExit(main())
