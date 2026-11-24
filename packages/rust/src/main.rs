use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use ssrf_scan::{document, load_rules, render_markdown, scan_path};

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ssrfscan: {err}");
            ExitCode::from(1)
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let mut path = String::new();
    let mut rules = String::new();
    let mut json_out = String::new();
    let mut md_out = String::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let next = args.get(index + 1).cloned().unwrap_or_default();
        match arg.as_str() {
            "--path" => path = next,
            "--rules" => rules = next,
            "--json-out" => json_out = next,
            "--md-out" => md_out = next,
            "--help" => {
                println!(
                    "ssrfscan --path <dir> --rules <rules.json> [--json-out file] [--md-out file]"
                );
                return Ok(());
            }
            other => return Err(format!("未知參數 {other}")),
        }
        index += 2;
    }
    if path.is_empty() || rules.is_empty() {
        return Err("需要 --path 與 --rules".to_string());
    }
    let rule_set = load_rules(PathBuf::from(&rules).as_path())?;
    let findings = scan_path(PathBuf::from(&path).as_path(), &rule_set)?;
    let doc = document(findings);
    let json = serde_json::to_string_pretty(&doc).map_err(|err| format!("encode json: {err}"))?;
    let markdown = render_markdown(&doc);
    if json_out.is_empty() && md_out.is_empty() {
        println!("{json}");
        return Ok(());
    }
    if !json_out.is_empty() {
        fs::write(&json_out, format!("{json}\n"))
            .map_err(|err| format!("write {json_out}: {err}"))?;
    }
    if !md_out.is_empty() {
        fs::write(&md_out, markdown).map_err(|err| format!("write {md_out}: {err}"))?;
    }
    Ok(())
}
