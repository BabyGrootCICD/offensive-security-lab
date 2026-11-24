import fs from "node:fs";
import path from "node:path";
import ts from "typescript";
import { loadRules } from "./rules.js";
import { createReport, renderMarkdown } from "./report.js";
import type { Finding, Report } from "./types.js";
import type { Rule } from "./types.js";

const skipDirs = new Set(["node_modules", "dist", "vendor", "target", ".git"]);
const hostNames = new Set([
  "host",
  "hostname",
  "url",
  "uri",
  "raw",
  "dest",
  "target",
  "endpoint",
  "addr",
  "address",
  "stockapi",
]);
const privileged = /admin|delete|manage/i;

interface Sink {
  name: string;
  url: ts.Expression;
  at: ts.Node;
}

interface State {
  name: string;
  scope: ts.Node;
  hasParse: boolean;
  hasExactHost: boolean;
  denylist?: ts.Node;
  substring?: ts.Node;
  redirect?: ts.Node;
  loopback: boolean;
  remote: boolean;
  denyLiteral: boolean;
  sinks: Sink[];
}

export function scanPath(root: string, rulesFile: string): Finding[] {
  const rules = loadRules(rulesFile);
  const findings: Finding[] = [];
  const stat = fs.statSync(root);
  if (stat.isDirectory()) {
    walk(root, root, rules, findings);
  } else {
    scanFile(root, path.dirname(root), rules, findings);
  }
  return findings;
}

export function scanReport(root: string, rulesFile: string): Report {
  return createReport(scanPath(root, rulesFile));
}

export function reportMarkdown(report: Report): string {
  return renderMarkdown(report);
}

function walk(dir: string, root: string, rules: Map<string, Rule>, findings: Finding[]): void {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!skipDirs.has(entry.name)) {
        walk(path.join(dir, entry.name), root, rules, findings);
      }
      continue;
    }
    if (/\.(?:[cm]?js|jsx|tsx?)$/.test(entry.name)) {
      scanFile(path.join(dir, entry.name), root, rules, findings);
    }
  }
}

function scanFile(file: string, root: string, rules: Map<string, Rule>, findings: Finding[]): void {
  const text = fs.readFileSync(file, "utf8");
  const kind = file.endsWith(".ts") || file.endsWith(".tsx") ? ts.ScriptKind.TS : ts.ScriptKind.JS;
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, kind);
  const rel = path.relative(root, file) || path.basename(file);
  const top = newState("file", source);
  const visit = (node: ts.Node, state: State): void => {
    if (isFunctionLike(node) && node.body) {
      const nested = newState(functionName(node), node.body);
      ts.forEachChild(node.body, (child) => visit(child, nested));
      emit(nested, source, rel, rules, findings);
      return;
    }
    collect(node, state);
    ts.forEachChild(node, (child) => visit(child, state));
  };
  ts.forEachChild(source, (node) => visit(node, top));
  emit(top, source, rel, rules, findings);
}

function newState(name: string, scope: ts.Node): State {
  return {
    name,
    scope,
    hasParse: false,
    hasExactHost: false,
    loopback: false,
    remote: false,
    denyLiteral: false,
    sinks: [],
  };
}

function isFunctionLike(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node)
  );
}

function functionName(node: ts.FunctionLikeDeclaration): string {
  if ("name" in node && node.name && ts.isIdentifier(node.name)) {
    return node.name.text;
  }
  return "anonymous";
}

function collect(node: ts.Node, state: State): void {
  if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "URL") {
    state.hasParse = true;
  }
  if (ts.isPropertyAccessExpression(node)) {
    if (node.name.text === "remoteAddress") {
      state.remote = true;
    }
    if (node.name.text === "isLoopback") {
      state.loopback = true;
    }
  }
  if (ts.isBinaryExpression(node)) {
    noteCompare(node, state);
  }
  if (!ts.isCallExpression(node)) {
    return;
  }
  noteParseCall(node, state);
  noteStringMethod(node, state);
  noteRedirect(node, state);
  const sink = matchSink(node);
  if (sink) {
    state.sinks.push(sink);
  }
}

function noteParseCall(node: ts.CallExpression, state: State): void {
  if (!ts.isPropertyAccessExpression(node.expression) || node.expression.name.text !== "parse") {
    return;
  }
  const receiver = receiverName(node.expression.expression);
  if (receiver === "URL" || receiver === "url") {
    state.hasParse = true;
  }
}

function noteCompare(node: ts.BinaryExpression, state: State): void {
  if (
    node.operatorToken.kind !== ts.SyntaxKind.EqualsEqualsEqualsToken &&
    node.operatorToken.kind !== ts.SyntaxKind.ExclamationEqualsEqualsToken &&
    node.operatorToken.kind !== ts.SyntaxKind.EqualsEqualsToken &&
    node.operatorToken.kind !== ts.SyntaxKind.ExclamationEqualsToken
  ) {
    return;
  }
  const pair = literalAndOther(node.left, node.right);
  if (!pair) {
    return;
  }
  if (isDenylistLiteral(pair.literal)) {
    state.denyLiteral = true;
    return;
  }
  if (isHostAccess(pair.other)) {
    state.hasExactHost = true;
  }
}

function noteStringMethod(node: ts.CallExpression, state: State): void {
  if (!ts.isPropertyAccessExpression(node.expression)) {
    return;
  }
  const method = node.expression.name.text;
  if (method !== "includes" && method !== "startsWith" && method !== "endsWith") {
    return;
  }
  const arg = node.arguments[0];
  if (!arg || !ts.isStringLiteral(arg)) {
    return;
  }
  if (isDenylistLiteral(arg.text)) {
    state.denylist = node;
    state.denyLiteral = true;
    return;
  }
  if (isHostAccess(node.expression.expression)) {
    state.substring = node;
  }
}

function noteRedirect(node: ts.CallExpression, state: State): void {
  const options = node.arguments[1];
  if (!options || !ts.isObjectLiteralExpression(options)) {
    return;
  }
  for (const prop of options.properties) {
    if (!ts.isPropertyAssignment(prop) || !ts.isIdentifier(prop.name)) {
      continue;
    }
    if (
      prop.name.text === "redirect" &&
      ts.isStringLiteral(prop.initializer) &&
      prop.initializer.text === "follow"
    ) {
      state.redirect = prop.initializer;
    }
  }
}

function matchSink(node: ts.CallExpression): Sink | undefined {
  const callee = node.expression;
  if (ts.isIdentifier(callee) && (callee.text === "fetch" || callee.text === "got" || callee.text === "axios")) {
    const url = urlArgument(node);
    return url ? { name: callee.text, url, at: node } : undefined;
  }
  if (!ts.isPropertyAccessExpression(callee)) {
    return undefined;
  }
  const objectName = receiverName(callee.expression);
  const method = callee.name.text;
  const httpMethods = new Set(["get", "post", "put", "delete", "request", "head"]);
  if ((objectName === "axios" || objectName === "http" || objectName === "https" || objectName === "got") && httpMethods.has(method)) {
    const url = urlArgument(node);
    return url ? { name: `${objectName}.${method}`, url, at: node } : undefined;
  }
  return undefined;
}

function urlArgument(node: ts.CallExpression): ts.Expression | undefined {
  const arg = node.arguments[0];
  if (!arg) {
    return undefined;
  }
  if (ts.isObjectLiteralExpression(arg)) {
    for (const prop of arg.properties) {
      if (!ts.isPropertyAssignment(prop) || !ts.isIdentifier(prop.name)) {
        continue;
      }
      if (prop.name.text === "url" || prop.name.text === "href") {
        return prop.initializer;
      }
    }
    return undefined;
  }
  return arg;
}

function emit(
  state: State,
  source: ts.SourceFile,
  file: string,
  rules: Map<string, Rule>,
  findings: Finding[],
): void {
  const allowlist = state.hasParse && state.hasExactHost;
  if (!allowlist) {
    for (const sink of state.sinks) {
      if (isConstant(sink.url)) {
        continue;
      }
      findings.push(finding(rules, "SSRF-001", source, file, sink.at, describe(state.scope, sink.url), sink.name));
    }
  }
  if (state.sinks.length > 0) {
    const sinkName = state.sinks[0]?.name ?? "";
    if (state.denylist) {
      findings.push(finding(rules, "SSRF-002", source, file, state.denylist, textOf(state.denylist), sinkName));
    }
    if (state.substring) {
      findings.push(finding(rules, "SSRF-003", source, file, state.substring, textOf(state.substring), sinkName));
    }
    if (state.redirect) {
      findings.push(finding(rules, "SSRF-004", source, file, state.redirect, "redirect: follow", sinkName));
    }
  }
  if (privileged.test(state.name) && (state.loopback || (state.remote && state.denyLiteral))) {
    findings.push(finding(rules, "SSRF-005", source, file, state.scope, "loopback source", state.name));
  }
}

function finding(
  rules: Map<string, Rule>,
  id: string,
  source: ts.SourceFile,
  file: string,
  node: ts.Node,
  from: string,
  sink: string,
): Finding {
  const rule = rules.get(id);
  if (!rule) {
    throw new Error(`unknown rule ${id}`);
  }
  const position = source.getLineAndCharacterOfPosition(node.getStart(source));
  return {
    ruleId: rule.id,
    severity: rule.severity,
    title: rule.title,
    file,
    line: position.line + 1,
    source: truncate(from),
    sink,
    impact: rule.impact,
    remediation: rule.remediation,
    snippet: snippet(source, position.line),
  };
}

function describe(scope: ts.Node, expr: ts.Expression): string {
  if (ts.isIdentifier(expr)) {
    let found = "";
    const visit = (node: ts.Node): void => {
      if (
        ts.isVariableDeclaration(node) &&
        ts.isIdentifier(node.name) &&
        node.name.text === expr.text &&
        node.initializer
      ) {
        found = node.initializer.getText();
      }
      ts.forEachChild(node, visit);
    };
    visit(scope);
    if (found) {
      return found;
    }
  }
  return expr.getText();
}

function isConstant(expr: ts.Expression): boolean {
  return ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr);
}

function literalAndOther(
  left: ts.Expression,
  right: ts.Expression,
): { literal: string; other: ts.Expression } | undefined {
  if (ts.isStringLiteral(left)) {
    return { literal: left.text, other: right };
  }
  if (ts.isStringLiteral(right)) {
    return { literal: right.text, other: left };
  }
  return undefined;
}

function isHostAccess(expr: ts.Expression): boolean {
  if (ts.isPropertyAccessExpression(expr)) {
    return expr.name.text === "hostname" || expr.name.text === "host";
  }
  if (ts.isIdentifier(expr)) {
    return hostNames.has(expr.text.toLowerCase());
  }
  if (ts.isCallExpression(expr) && ts.isPropertyAccessExpression(expr.expression)) {
    return expr.expression.name.text === "hostname" || expr.expression.name.text === "host";
  }
  return false;
}

function isDenylistLiteral(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return normalized === "localhost" || normalized === "127.0.0.1";
}

function receiverName(expr: ts.Expression): string {
  if (ts.isIdentifier(expr)) {
    return expr.text;
  }
  if (ts.isPropertyAccessExpression(expr)) {
    return expr.name.text;
  }
  return "";
}

function textOf(node: ts.Node): string {
  return node.getText();
}

function snippet(source: ts.SourceFile, line: number): string {
  const text = source.getFullText().split(/\r?\n/)[line] ?? "";
  return truncate(text.trim());
}

function truncate(value: string): string {
  const trimmed = value.trim();
  return trimmed.length > 200 ? trimmed.slice(0, 200) : trimmed;
}
