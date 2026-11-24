use std::fs;
use std::path::Path;

use serde::Serialize;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{BinOp, Expr, ExprLit, ImplItem, Item, Lit, Member};

use crate::rules::RuleSet;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub file: String,
    pub line: usize,
    pub source: String,
    pub sink: String,
    pub impact: String,
    pub remediation: String,
    pub snippet: String,
}

struct Sink {
    name: String,
    source: String,
    line: usize,
    constant: bool,
    client_method: bool,
}

struct Hit {
    line: usize,
    source: String,
}

struct Collector {
    name: String,
    fn_line: usize,
    has_parse: bool,
    has_exact_host: bool,
    denylist: Option<Hit>,
    substring: Option<Hit>,
    redirect: Option<Hit>,
    loopback: bool,
    mentions_http: bool,
    sinks: Vec<Sink>,
}

pub fn scan_path(path: &Path, rules: &RuleSet) -> Result<Vec<Finding>, String> {
    let meta = fs::metadata(path).map_err(|err| format!("stat scan path: {err}"))?;
    if meta.is_file() {
        return scan_file(path, path.parent().unwrap_or(Path::new(".")), rules);
    }
    let mut findings = Vec::new();
    walk(path, path, rules, &mut findings)?;
    Ok(findings)
}

fn walk(
    dir: &Path,
    root: &Path,
    rules: &RuleSet,
    findings: &mut Vec<Finding>,
) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|err| format!("read dir {}: {err}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("read dir entry: {err}"))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry.path().is_dir() {
            if matches!(
                name.as_ref(),
                "target" | "vendor" | "node_modules" | "dist" | ".git"
            ) {
                continue;
            }
            walk(&entry.path(), root, rules, findings)?;
            continue;
        }
        if name.ends_with(".rs") {
            findings.extend(scan_file(&entry.path(), root, rules)?);
        }
    }
    Ok(())
}

fn scan_file(path: &Path, root: &Path, rules: &RuleSet) -> Result<Vec<Finding>, String> {
    let text = fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let parsed =
        syn::parse_file(&text).map_err(|err| format!("parse {}: {err}", path.display()))?;
    let rel = relative(root, path);
    let mut findings = Vec::new();
    for item in &parsed.items {
        match item {
            Item::Fn(func) => {
                findings.extend(scan_function(
                    &text,
                    &rel,
                    &func.sig.ident.to_string(),
                    line_of(func.sig.ident.span()),
                    &func.block,
                    rules,
                )?);
            }
            Item::Impl(item) => {
                for impl_item in &item.items {
                    if let ImplItem::Fn(func) = impl_item {
                        findings.extend(scan_function(
                            &text,
                            &rel,
                            &func.sig.ident.to_string(),
                            line_of(func.sig.ident.span()),
                            &func.block,
                            rules,
                        )?);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(findings)
}

fn scan_function(
    text: &str,
    file: &str,
    name: &str,
    fn_line: usize,
    block: &syn::Block,
    rules: &RuleSet,
) -> Result<Vec<Finding>, String> {
    let mut collector = Collector {
        name: name.to_string(),
        fn_line,
        has_parse: false,
        has_exact_host: false,
        denylist: None,
        substring: None,
        redirect: None,
        loopback: false,
        mentions_http: false,
        sinks: Vec::new(),
    };
    collector.visit_block(block);
    collector.finish(text, file, rules)
}

impl Collector {
    fn finish(&self, text: &str, file: &str, rules: &RuleSet) -> Result<Vec<Finding>, String> {
        let mut findings = Vec::new();
        let sinks: Vec<&Sink> = self
            .sinks
            .iter()
            .filter(|sink| !sink.client_method || self.mentions_http)
            .collect();
        if !(self.has_parse && self.has_exact_host) {
            for sink in &sinks {
                if sink.constant {
                    continue;
                }
                findings.push(self.make(
                    rules,
                    "SSRF-001",
                    sink.line,
                    &sink.source,
                    &sink.name,
                    file,
                    text,
                )?);
            }
        }
        if !sinks.is_empty() {
            let sink_name = sinks[0].name.as_str();
            if let Some(hit) = &self.denylist {
                findings.push(self.make(
                    rules,
                    "SSRF-002",
                    hit.line,
                    &hit.source,
                    sink_name,
                    file,
                    text,
                )?);
            }
            if let Some(hit) = &self.substring {
                findings.push(self.make(
                    rules,
                    "SSRF-003",
                    hit.line,
                    &hit.source,
                    sink_name,
                    file,
                    text,
                )?);
            }
            if let Some(hit) = &self.redirect {
                findings.push(self.make(
                    rules,
                    "SSRF-004",
                    hit.line,
                    &hit.source,
                    sink_name,
                    file,
                    text,
                )?);
            }
        }
        if privileged(&self.name) && self.loopback {
            findings.push(self.make(
                rules,
                "SSRF-005",
                self.fn_line,
                "loopback source",
                &self.name,
                file,
                text,
            )?);
        }
        Ok(findings)
    }

    fn make(
        &self,
        rules: &RuleSet,
        id: &str,
        line: usize,
        source: &str,
        sink: &str,
        file: &str,
        text: &str,
    ) -> Result<Finding, String> {
        let rule = rules.get(id)?;
        let line = line.max(1);
        Ok(Finding {
            rule_id: rule.id.clone(),
            severity: rule.severity.clone(),
            title: rule.title.clone(),
            file: file.to_string(),
            line,
            source: truncate(source),
            sink: sink.to_string(),
            impact: rule.impact.clone(),
            remediation: rule.remediation.clone(),
            snippet: snippet(text, line),
        })
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        match expr {
            Expr::Call(call) => {
                let path = expr_path(&call.func);
                note_http_path(self, &path);
                if path.ends_with("::parse") || path == "parse" {
                    self.has_parse = true;
                }
                if let Some(name) = call_sink(&path) {
                    if let Some(arg) = call.args.first() {
                        self.sinks.push(sink_from(name, arg, false));
                    }
                }
            }
            Expr::MethodCall(call) => {
                let method = call.method.to_string();
                if matches!(method.as_str(), "contains" | "starts_with" | "ends_with") {
                    if let Some(lit) = call.args.first().and_then(string_lit) {
                        let hit = Hit {
                            line: line_of(call.method.span()),
                            source: format!("{method}(\"{lit}\")"),
                        };
                        if is_denylist(&lit) {
                            self.denylist = Some(hit);
                        } else if receiver_is_host(&call.receiver) {
                            self.substring = Some(hit);
                        }
                    }
                }
                if method == "redirect" && args_follow(&call.args) {
                    self.redirect = Some(Hit {
                        line: line_of(call.method.span()),
                        source: "redirect follows without review".to_string(),
                    });
                }
                if method == "is_loopback" {
                    self.loopback = true;
                }
                if is_client_method(&method) && receiver_is_client(&call.receiver) {
                    if let Some(arg) = call.args.first() {
                        self.sinks
                            .push(sink_from(format!("client.{method}"), arg, true));
                    }
                }
            }
            Expr::Binary(binary) => {
                if matches!(binary.op, BinOp::Eq(_) | BinOp::Ne(_)) {
                    if let Some(lit) =
                        host_literal(&binary.left).or_else(|| host_literal(&binary.right))
                    {
                        if !is_denylist(&lit)
                            && (mentions_host(&binary.left) || mentions_host(&binary.right))
                        {
                            self.has_exact_host = true;
                        }
                    }
                }
            }
            Expr::Path(path) => note_http_path(self, &path_to_string(&path.path)),
            _ => {}
        }
        syn::visit::visit_expr(self, expr);
    }
}

fn sink_from(name: String, arg: &Expr, client_method: bool) -> Sink {
    Sink {
        name,
        source: expr_source(arg),
        line: line_of(arg.span()),
        constant: is_constant(arg),
        client_method,
    }
}

fn call_sink(path: &str) -> Option<String> {
    const EXACT: &[&str] = &[
        "reqwest::get",
        "reqwest::blocking::get",
        "ureq::get",
        "hyper::Request::get",
    ];
    if EXACT.contains(&path) {
        return Some((*path).to_string());
    }
    let prefixed =
        path.starts_with("reqwest::") || path.starts_with("ureq::") || path.starts_with("hyper::");
    let method = path.rsplit("::").next().unwrap_or("");
    if prefixed
        && matches!(
            method,
            "get" | "post" | "put" | "patch" | "delete" | "head" | "request"
        )
    {
        return Some(path.to_string());
    }
    None
}

fn note_http_path(collector: &mut Collector, path: &str) {
    if path.starts_with("reqwest") || path.starts_with("ureq") || path.starts_with("hyper") {
        collector.mentions_http = true;
    }
}

fn args_follow(args: &syn::punctuated::Punctuated<Expr, syn::Token![,]>) -> bool {
    args.iter().any(|arg| {
        let path = match arg {
            Expr::Call(call) => expr_path(&call.func),
            Expr::Path(path) => path_to_string(&path.path),
            _ => String::new(),
        };
        path.ends_with("::limited")
            || path.ends_with("::default")
            || path == "limited"
            || path == "default"
    })
}

fn is_client_method(method: &str) -> bool {
    matches!(
        method,
        "get" | "post" | "put" | "patch" | "delete" | "head" | "request"
    )
}

fn receiver_is_client(expr: &Expr) -> bool {
    match expr {
        Expr::Path(path) => last_segment(&path.path) == "client",
        Expr::Field(field) => match &field.member {
            Member::Named(name) => name == "client" || receiver_is_client(&field.base),
            Member::Unnamed(_) => receiver_is_client(&field.base),
        },
        Expr::Reference(reference) => receiver_is_client(&reference.expr),
        Expr::Try(try_expr) => receiver_is_client(&try_expr.expr),
        _ => false,
    }
}

fn receiver_is_host(expr: &Expr) -> bool {
    match expr {
        Expr::Path(path) => is_host_name(&last_segment(&path.path)),
        Expr::Field(field) => match &field.member {
            Member::Named(name) => is_host_name(&name.to_string()) || receiver_is_host(&field.base),
            Member::Unnamed(_) => receiver_is_host(&field.base),
        },
        Expr::MethodCall(call) => {
            call.method == "host_str" || call.method == "host" || receiver_is_host(&call.receiver)
        }
        Expr::Reference(reference) => receiver_is_host(&reference.expr),
        _ => false,
    }
}

fn mentions_host(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(call) => {
            matches!(
                call.method.to_string().as_str(),
                "host_str" | "host" | "hostname"
            )
        }
        Expr::Path(path) => matches!(
            last_segment(&path.path).to_ascii_lowercase().as_str(),
            "host" | "hostname" | "url_host"
        ),
        Expr::Field(field) => match &field.member {
            Member::Named(name) => matches!(name.to_string().as_str(), "host" | "hostname"),
            Member::Unnamed(_) => false,
        },
        Expr::Reference(reference) => mentions_host(&reference.expr),
        _ => false,
    }
}

fn is_host_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "hostname" | "url_host" | "raw" | "url" | "uri" | "dest" | "target" | "endpoint"
    )
}

fn host_literal(expr: &Expr) -> Option<String> {
    if let Some(value) = string_lit(expr) {
        return Some(value);
    }
    let Expr::Call(call) = expr else {
        return None;
    };
    if expr_path(&call.func) == "Some" {
        return call.args.first().and_then(string_lit);
    }
    None
}

fn string_lit(expr: &Expr) -> Option<String> {
    let Expr::Lit(ExprLit {
        lit: Lit::Str(value),
        ..
    }) = expr
    else {
        return None;
    };
    Some(value.value())
}

fn is_constant(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Str(_), ..
        }) => true,
        Expr::Reference(reference) => is_constant(&reference.expr),
        _ => false,
    }
}

fn is_denylist(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1"
    )
}

fn privileged(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("admin") || lower.contains("delete") || lower.contains("manage")
}

fn expr_source(expr: &Expr) -> String {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Str(value),
            ..
        }) => format!("\"{}\"", value.value()),
        Expr::Path(path) => path_to_string(&path.path),
        Expr::Reference(reference) => expr_source(&reference.expr),
        Expr::MethodCall(call) => format!("{}.{}()", expr_source(&call.receiver), call.method),
        Expr::Call(call) => format!("{}()", expr_path(&call.func)),
        Expr::Unary(unary) => expr_source(&unary.expr),
        _ => "non-constant".to_string(),
    }
}

fn expr_path(expr: &Expr) -> String {
    match expr {
        Expr::Path(path) => path_to_string(&path.path),
        _ => String::new(),
    }
}

fn path_to_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn last_segment(path: &syn::Path) -> String {
    path.segments
        .last()
        .map(|segment| segment.ident.to_string())
        .unwrap_or_default()
}

fn line_of(span: proc_macro2::Span) -> usize {
    span.start().line
}

fn snippet(text: &str, line: usize) -> String {
    let index = line.saturating_sub(1);
    truncate(text.lines().nth(index).unwrap_or("").trim())
}

fn truncate(value: &str) -> String {
    value.chars().take(200).collect()
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}
