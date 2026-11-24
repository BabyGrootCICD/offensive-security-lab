export interface Rule {
  id: string;
  severity: "high" | "medium";
  title: string;
  impact: string;
  remediation: string;
}

export interface Finding {
  ruleId: string;
  severity: "high" | "medium";
  title: string;
  file: string;
  line: number;
  source: string;
  sink: string;
  impact: string;
  remediation: string;
  snippet: string;
}

export interface Report {
  version: 1;
  scanner: "js";
  findings: Finding[];
}
