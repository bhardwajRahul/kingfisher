use assert_cmd::Command;
use predicates::{prelude::PredicateBooleanExt, str::contains};
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

mod test {

    use super::*;
    #[test]
    fn cli_lists_rules_pretty() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["rules", "list", "--format", "pretty", "--no-update-check"])
            .assert()
            .success()
            .stdout(contains("kingfisher.aws.").and(contains("Pattern")));
    }
    #[test]
    fn cli_lists_rules_json() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["rules", "list", "--format", "json", "--no-update-check"])
            .assert()
            .success()
            .stdout(contains("kingfisher.aws.").and(contains("pattern")));
    }

    #[test]
    fn cli_version_flag() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .arg("--version")
            .assert()
            .success()
            .stdout(contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn cli_scan_generates_html_audit_report() {
        let temp = tempdir().expect("tempdir should be created");
        let input_dir = temp.path().join("repo");
        let output_html = temp.path().join("audit-report.html");
        fs::create_dir_all(&input_dir).expect("input directory should be created");
        fs::write(input_dir.join("README.txt"), "no credentials here")
            .expect("seed file should be written");

        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                input_dir.to_str().unwrap(),
                "--format",
                "html",
                "--output",
                output_html.to_str().unwrap(),
                "--rule",
                "kingfisher.aws.1",
                "--no-validate",
                "--no-update-check",
            ])
            .assert()
            .success();

        let html = fs::read_to_string(&output_html).expect("html report should be written");
        assert!(html.contains("Kingfisher Audit Report"));
        assert!(html.contains("Scan Summary"));
    }

    #[test]
    fn cli_scan_generates_toon_report_for_llms() {
        let temp = tempdir().expect("tempdir should be created");
        let rules_dir = temp.path().join("rules");
        let input_dir = temp.path().join("repo");
        let output_toon = temp.path().join("findings.toon");

        fs::create_dir_all(&rules_dir).expect("rules directory should be created");
        fs::create_dir_all(&input_dir).expect("input directory should be created");
        fs::write(
            rules_dir.join("demo.yml"),
            r#"
rules:
  - id: kingfisher.demo.1
    name: Demo secret
    pattern: '(demo_secret_[0-9]{4})'
    confidence: medium
"#,
        )
        .expect("rule should be written");
        fs::write(input_dir.join("README.txt"), "demo_secret_1234")
            .expect("seed file should be written");

        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                input_dir.to_str().unwrap(),
                "--format",
                "toon",
                "--output",
                output_toon.to_str().unwrap(),
                "--rules-path",
                rules_dir.to_str().unwrap(),
                "--load-builtins=false",
                "--no-validate",
                "--no-update-check",
            ])
            .assert()
            .code(200);

        let toon = fs::read_to_string(&output_toon).expect("toon report should be written");
        let decoded: Value = toon_format::decode_default(&toon).expect("toon should decode");
        assert_eq!(decoded["schema"], "kingfisher.toon.v1");
        assert_eq!(decoded["scan"]["summary"]["findings"], 1);
        assert_eq!(decoded["findings"][0]["rule_id"], "kingfisher.demo.1");
        assert_eq!(decoded["findings"][0]["validation_status"], "Not Attempted");
    }
}
