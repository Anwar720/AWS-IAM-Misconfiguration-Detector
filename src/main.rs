use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use aws_config::{ SdkConfig};
use aws_credential_types::Credentials;
use aws_types::region::Region;
use aws_sdk_iam::Client;

mod aws_util;
use aws_util::{ask_for_credentials, extract_user_policies_from_aws};

/// CLI arguments (adds --json flag)
#[derive(Parser, Debug)]
#[command(author, version, about = "IAM Misconfiguration Detector", long_about = None)]
struct Args {
    /// Output JSON instead of colored text
    #[arg(long, default_value_t = false)]
    json: bool,
}

/// Rule structure matching rules.json
#[derive(Debug, Deserialize, Serialize, Clone)]
struct Rule {
    id: String,
    description: String,
    detection: Vec<String>,
    severity: u8,
    impact: Option<String>,
    remediation: Option<String>,
}

/// A single match result
#[derive(Debug, Serialize, Deserialize)]
struct MatchResult {
    rule_id: String,
    description: String,
    severity: u8,
    impact: Option<String>,
    remediation: Option<String>,
    matched_patterns: Vec<String>,
    policy_category: String,
}

/// Results for one file
#[derive(Debug, Serialize, Deserialize)]
struct FileReport {
    file_path: String,
    findings: Vec<MatchResult>,
}

/// Full report
#[derive(Debug, Serialize, Deserialize)]
struct Report {
    scanned_files: usize,
    reports: Vec<FileReport>,
}
#[allow(deprecated)]
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut choice = String::new();

    println!("\nWelcome to the AWS Misconfiguration Detector!\n");
    println!("============== Menu ==============");
    println!("1. Start Scan on a file or directory");
    println!("2. Import Policy File from AWS Account");
    println!("3. Exit");
    println!("Enter choice ( 1,2 or 3 ): ");
    std::io::stdin().read_line(&mut choice).expect("Failed to read line");

    let mut policy_path = PathBuf::from("./policies/user_policy.json");

    match choice.trim() {
        "1" => {
            let mut input = String::new();
            println!("Enter the path to the policy file or directory:");
            std::io::stdin().read_line(&mut input)?;
            policy_path = PathBuf::from(input.trim());
        }
        "2" => {
            println!("\n------ Importing policies from AWS Account ------");

            // Ask user for access_key / secret_key / region
            let creds_input = ask_for_credentials();

            println!("Enter IAM username: ");
            let mut user_name = String::new();
            std::io::stdin().read_line(&mut user_name)?;
            let user_name = user_name.trim();

            // Build AWS region
            let region = Region::new(creds_input.region.clone());

            // Build credentials provider
            let creds_provider = Credentials::new(
                creds_input.access_key.clone(),
                creds_input.secret_key.clone(),
                None, // session token
                None, // expiration
                "manual",
            );

            // Load AWS config
            let config: SdkConfig = aws_config::from_env()
                .region(region)
                .credentials_provider(creds_provider)
                .load()
                .await;

            // IAM client
            let client = Client::new(&config);

            // Fetch IAM policies
            let results = extract_user_policies_from_aws(user_name, &client).await?;

            // Save results
            fs::create_dir_all("./policies")?;
            fs::write(&policy_path, serde_json::to_string_pretty(&results)?)?;

            println!("\nSaved IAM policies → {} \n", policy_path.display());
        }
        _ => {
            println!("Exiting. Goodbye!");
            return Ok(());
        }
    }

    // Load rules
    let rules_path = PathBuf::from("rules.json");
    let rules_text = fs::read_to_string(&rules_path)
        .with_context(|| format!("Failed to read rules file: {}", rules_path.display()))?;

    let rules: Vec<Rule> =
        serde_json::from_str(&rules_text).context("Failed to parse rules.json")?;

    // Precompile regex patterns
    let mut rule_regexes: HashMap<String, Vec<(String, Regex)>> = HashMap::new();
    for r in &rules {
        let mut vec_patterns = Vec::new();
        for pat in &r.detection {
            let regex = build_regex_from_pattern(pat)?;
            vec_patterns.push((pat.clone(), regex));
        }
        rule_regexes.insert(r.id.clone(), vec_patterns);
    }

    // Collect files to scan
    let mut files: Vec<PathBuf> = Vec::new();
    if policy_path.is_file() {
        files.push(policy_path.clone());
    } else if policy_path.is_dir() {
        for entry in WalkDir::new(&policy_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let p = entry.into_path();
            if p.extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("json"))
                .unwrap_or(false)
            {
                files.push(p);
            }
        }
    } else {
        anyhow::bail!(
            "Path is not a file or directory: {}",
            policy_path.display()
        );
    }

    if files.is_empty() {
        println!("No JSON files found at {}", policy_path.display());
        return Ok(());
    }

    // Perform scanning
    let mut reports: Vec<FileReport> = Vec::new();
    for file in &files {
        match process_policy_file(file, &rules, &rule_regexes) {
            Ok(Some(report)) => reports.push(report),
            Ok(None) => {}
            Err(e) => {
                eprintln!(
                    "{}: could not process {} → {}",
                    "ERROR".red(),
                    file.display(),
                    e
                );
            }
        }
    }

    let report = Report {
        scanned_files: files.len(),
        reports,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    print_colored_report(&report);
    Ok(())
}



/// Build a case-insensitive Regex from a detection pattern.
/// Supports wildcard '*' that translates to '.*' (regex). Escapes other chars.
/// Example: "iam:PassRole" -> regex for iam:passrole
///          "Action:*" -> regex for action:.*
/// Returns Regex with case-insensitive flag.
fn build_regex_from_pattern(pat: &str) -> Result<Regex> {
    // If it's a simple substring with no wildcard, build a regex that matches the substring
    // anywhere, case-insensitive.
    // If it contains '*', treat '*' as wildcard -> '.*'
    // Escape other characters.
    let mut escaped = String::new();
    for ch in pat.chars() {
        if ch == '*' {
            escaped.push_str(".*");
        } else {
            // Escape regex metacharacters
            let s = regex::escape(&ch.to_string());
            escaped.push_str(&s);
        }
    }
    // Build regex: look anywhere in the text
    let pattern = format!("(?i){}", escaped); // (?i) = case-insensitive
    let re = Regex::new(&pattern).with_context(|| format!("Failed to compile regex for pattern {}", pat))?;
    Ok(re)
}

/// Processes a single IAM policy JSON file:
/// - Reads and normalizes the file contents
/// - Applies detection rules only to "Allow" statements
/// - Returns `Some(FileReport)` if matches were found, otherwise `None`
fn process_policy_file(
    file_path: &Path,
    detection_rules: &Vec<Rule>,
    compiled_rule_patterns: &HashMap<String, Vec<(String, Regex)>>,
) -> Result<Option<FileReport>> {
    // Read policy file
    let raw_text = fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read policy file: {}", file_path.display()))?;

    // Parse JSON
    let parsed_json: Value = match serde_json::from_str(&raw_text) {
        Ok(v) => v,
        Err(_) => return Ok(None), // fallback to raw text failed
    };

    // Vector to hold (category, statement)
    let mut allow_statements_with_category: Vec<(String, Value)> = Vec::new();

    if let Value::Object(map) = &parsed_json {
        for (key, val) in map {
            // Check for known policy categories
            if ["attached_user_policies", "inline_user_policies",
                "attached_group_policies", "inline_group_policies"]
                .contains(&key.as_str())
            {
                if let Value::Array(policies) = val {
                    for policy_obj in policies {
                        if let Some(doc) = policy_obj.get("document") {
                            let statements = extract_allow_statements(doc);
                            for stmt in statements {
                                allow_statements_with_category.push((key.clone(), stmt));
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: treat as raw policy document (e.g., Statement array)
    if allow_statements_with_category.is_empty() {
        let statements = extract_allow_statements(&parsed_json);
        for stmt in statements {
            allow_statements_with_category.push(("raw_policy".to_string(), stmt));
        }
    }

    if allow_statements_with_category.is_empty() {
        return Ok(None);
    }

    // Build searchable text with category
    let searchable_texts: Vec<(String, String)> = allow_statements_with_category
        .iter()
        .map(|(category, stmt)| {
            let mut parts = Vec::new();

            if let Some(action_val) = stmt.get("Action") {
                match action_val {
                    Value::String(s) => parts.push(s.clone()),
                    Value::Array(arr) => {
                        for a in arr {
                            parts.push(a.as_str().unwrap_or(&a.to_string()).to_string());
                        }
                    }
                    other => parts.push(other.to_string()),
                }
            }

            if let Some(resource_val) = stmt.get("Resource") {
                match resource_val {
                    Value::String(s) => parts.push(s.clone()),
                    Value::Array(arr) => {
                        for r in arr {
                            parts.push(r.as_str().unwrap_or(&r.to_string()).to_string());
                        }
                    }
                    other => parts.push(other.to_string()),
                }
            }

            parts.push("Allow".to_string());
            parts.push(stmt.to_string());

            (category.clone(), parts.join(" "))
        })
        .collect();

    // Run pattern matching
    let mut findings: Vec<MatchResult> = Vec::new();

    for (category, text) in &searchable_texts {
        for rule in detection_rules {
            if let Some(patterns) = compiled_rule_patterns.get(&rule.id) {
                let mut matched_patterns = Vec::new();
                for (orig_pat, re) in patterns {
                    if re.is_match(text) {
                        matched_patterns.push(orig_pat.clone());
                    }
                }
                if !matched_patterns.is_empty() {
                    findings.push(MatchResult {
                        rule_id: rule.id.clone(),
                        description: rule.description.clone(),
                        severity: rule.severity,
                        impact: rule.impact.clone(),
                        remediation: rule.remediation.clone(),
                        matched_patterns,
                        policy_category: category.clone(),
                    });
                }
            }
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort_by_key(|m| std::cmp::Reverse(m.severity));
        Ok(Some(FileReport {
            file_path: file_path.to_string_lossy().into_owned(),
            findings,
        }))
    }
}

/// Recursively extract all statements with Effect = "Allow"
fn extract_allow_statements(value: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut allow_statements = Vec::new();

    match value {
        Value::Object(map) => {
            if let Some(effect) = map.get("Effect").and_then(|v| v.as_str()) {
                if effect.eq_ignore_ascii_case("Allow") {
                    allow_statements.push(Value::Object(map.clone()));
                }
            }

            // Only recurse into arrays or objects that could contain Statements
            for v in map.values() {
                allow_statements.extend(extract_allow_statements(v));
            }
        }
        Value::Array(arr) => {
            for item in arr {
                allow_statements.extend(extract_allow_statements(item));
            }
        }
        _ => {}
    }

    allow_statements
}

/// Print colored report to terminal
fn print_colored_report(report: &Report) {
    println!("{}", "=".repeat(80));
    println!(
        "{}\nScanned files: {}\nReports with findings: {}",
        "IAM Misconfiguration Detector".bold(),
        report.scanned_files,
        report.reports.len()
    );
    println!("{}", "=".repeat(80));

    for file_report in &report.reports {
    println!("{}", format!("📄 File: {}", file_report.file_path).underline().bold());
    for m in &file_report.findings {
        let sev = m.severity;
        let (_sev_label, colorized_sev) = match sev {
            9..=10 => ("CRITICAL", "[CRITICAL]".red().bold()),
            7..=8 => ("HIGH", "[HIGH]".yellow().bold()),
            4..=6 => ("MEDIUM", "[MEDIUM]".blue().bold()),
            1..=3 => ("LOW", "[LOW]".white()),
            _ => ("UNKNOWN", "[UNKNOWN]".white()),
        };

        // Draw a box-style header for each finding
        println!("\n{}", "─".repeat(60));
        println!("Severity: {} ({})",  colorized_sev, sev);
        println!("Policy Category: {}", m.policy_category.green().bold());
        println!("Description: {}", m.description);
        if let Some(ref impact) = m.impact {
            println!("Impact: {}", impact.red());
        }
        if let Some(ref remediation) = m.remediation {
            println!("Remediation: {}", remediation.cyan());
        }
        println!(
            "Matched Patterns: {}",
            m.matched_patterns
                .iter()
                .map(|p| p.magenta().bold().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("{}", "─".repeat(60));
        println!();
    }
    println!("{}", "=".repeat(80));
}

    // Summary
    let total_findings: usize = report.reports.iter().map(|r| r.findings.len()).sum();
    println!(
        "{}: {} files with {} findings",
        "Summary".bold(),
        report.reports.len(),
        total_findings
    );
}