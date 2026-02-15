use assert_cmd::Command;
use predicates::{prelude::PredicateBooleanExt, str::contains};
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
        assert!(html.contains("Audit Metadata"));
    }
}
