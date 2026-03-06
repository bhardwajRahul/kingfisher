use assert_cmd::Command;
use predicates::prelude::*;
use std::{fs, time::Duration};
use tempfile::TempDir;

const FORMATS: [&str; 4] = ["pretty", "json", "jsonl", "bson"];

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn build_fixture() -> TempDir {
    let work = tempfile::tempdir().expect("tempdir");
    let rules_dir = work.path().join("rules");
    let input_path = work.path().join("input.txt");

    fs::create_dir_all(&rules_dir).expect("create rules dir");
    fs::write(
        rules_dir.join("demo.yml"),
        r#"
rules:
  - id: demo.secret
    name: Demo secret
    pattern: "demo_secret_[0-9]{4}"
    confidence: low
"#,
    )
    .expect("write rule");
    fs::write(&input_path, "demo_secret_1234\n").expect("write input");

    work
}

fn quiet_scan_command(fixture: &TempDir, format: &str, rule_stats: bool) -> Command {
    let rules_dir = fixture.path().join("rules");
    let input_path = fixture.path().join("input.txt");
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.env("NO_COLOR", "1")
        .args([
            "scan",
            input_path.to_str().expect("input path is valid UTF-8"),
            "--confidence=low",
            "--format",
            format,
            "--no-update-check",
            "--no-validate",
            "--quiet",
            "--rules-path",
            rules_dir.to_str().expect("rules path is valid UTF-8"),
            "--load-builtins=false",
        ])
        .timeout(Duration::from_secs(20));

    if rule_stats {
        cmd.arg("--rule-stats");
    }

    cmd
}

#[test]
fn scan_quiet_suppresses_summary() {
    let fixture = build_fixture();
    for format in FORMATS {
        quiet_scan_command(&fixture, format, false)
            .assert()
            .code(200)
            .stdout(predicate::function(|out: &[u8]| !contains_bytes(out, b"Scan Summary")))
            .stdout(predicate::function(|out: &[u8]| {
                !contains_bytes(out, b"Rule Performance Stats")
            }));
    }
}

#[test]
fn scan_quiet_with_rule_stats_prints_rule_stats() {
    let fixture = build_fixture();
    for format in FORMATS {
        quiet_scan_command(&fixture, format, true)
            .assert()
            .code(200)
            .stdout(predicate::function(|out: &[u8]| !contains_bytes(out, b"Scan Summary")))
            .stdout(predicate::function(|out: &[u8]| {
                contains_bytes(out, b"Rule Performance Stats")
            }));
    }
}
