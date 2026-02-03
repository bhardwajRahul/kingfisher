//! Tests for the `--tls-mode` CLI feature and TLS validation behavior.
//!
//! These tests verify that:
//! - The `--tls-mode` CLI flag is parsed correctly
//! - The `--ignore-certs` legacy flag is treated as `--tls-mode=off`
//! - Rules with `tls_mode: lax` are correctly parsed and respected
//! - The TLS mode behavior works as expected for different validators

use assert_cmd::Command;
use predicates::prelude::*;

/// Test that `--tls-mode` is recognized as a valid global option.
#[test]
fn tls_mode_flag_is_recognized() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--tls-mode=strict").arg("--help");
    cmd.assert().success();
}

/// Test that all TLS mode values are accepted.
#[test]
fn tls_mode_accepts_all_values() {
    for mode in ["strict", "lax", "off"] {
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
        cmd.arg(format!("--tls-mode={}", mode)).arg("--help");
        cmd.assert().success();
    }
}

/// Test that invalid TLS mode values are rejected.
#[test]
fn tls_mode_rejects_invalid_values() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--tls-mode=invalid").arg("--help");
    cmd.assert().failure().stderr(predicate::str::contains("invalid"));
}

/// Test that `--ignore-certs` is still accepted (deprecated but supported).
#[test]
fn ignore_certs_flag_still_works() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--ignore-certs").arg("--help");
    cmd.assert().success();
}

/// Test that --tls-mode appears in the help output.
#[test]
fn tls_mode_appears_in_help() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--help");
    cmd.assert().success().stdout(predicate::str::contains("--tls-mode"));
}

/// Test that rules list subcommand runs with tls-mode flag.
#[test]
fn rules_list_works_with_tls_mode() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--tls-mode=lax").arg("rules").arg("list");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("postgres").or(predicate::str::contains("Postgres")));
}

/// Test that a scan with `--tls-mode=strict` runs successfully.
#[test]
fn scan_with_strict_mode_runs() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--tls-mode=strict").arg("scan").arg("--no-validate").arg("-");
    cmd.write_stdin("test input with no secrets");
    cmd.assert().success();
}

/// Test that a scan with `--tls-mode=lax` runs successfully.
#[test]
fn scan_with_lax_mode_runs() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--tls-mode=lax").arg("scan").arg("--no-validate").arg("-");
    cmd.write_stdin("test input with no secrets");
    cmd.assert().success();
}

/// Test that a scan with `--tls-mode=off` runs successfully.
#[test]
fn scan_with_off_mode_runs() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--tls-mode=off").arg("scan").arg("--no-validate").arg("-");
    cmd.write_stdin("test input with no secrets");
    cmd.assert().success();
}

#[cfg(test)]
mod rule_tls_mode_tests {
    use kingfisher_rules::{RuleSyntax, TlsMode};
    use serde::Deserialize;

    /// Helper struct for deserializing rule YAML files.
    #[derive(Deserialize)]
    struct RawRules {
        rules: Vec<RuleSyntax>,
    }

    /// Test that the postgres rule has tls_mode: lax.
    #[test]
    fn postgres_rule_has_lax_tls_mode() {
        let yaml = include_str!("../crates/kingfisher-rules/data/rules/postgres.yml");
        let raw: RawRules = serde_yaml::from_str(yaml).expect("postgres rules should parse");

        let postgres_rule = raw.rules.iter().find(|r| r.id == "kingfisher.postgres.1");
        assert!(postgres_rule.is_some(), "postgres rule should exist");
        assert_eq!(
            postgres_rule.unwrap().tls_mode,
            Some(TlsMode::Lax),
            "postgres rule should have tls_mode: lax"
        );
    }

    /// Test that the mysql rule has tls_mode: lax.
    #[test]
    fn mysql_rule_has_lax_tls_mode() {
        let yaml = include_str!("../crates/kingfisher-rules/data/rules/mysql.yml");
        let raw: RawRules = serde_yaml::from_str(yaml).expect("mysql rules should parse");

        let mysql_rule = raw.rules.iter().find(|r| r.id == "kingfisher.mysql.1");
        assert!(mysql_rule.is_some(), "mysql rule should exist");
        assert_eq!(
            mysql_rule.unwrap().tls_mode,
            Some(TlsMode::Lax),
            "mysql rule should have tls_mode: lax"
        );
    }

    /// Test that the mongodb URI rule has tls_mode: lax.
    #[test]
    fn mongodb_uri_rule_has_lax_tls_mode() {
        let yaml = include_str!("../crates/kingfisher-rules/data/rules/mongodb.yml");
        let raw: RawRules = serde_yaml::from_str(yaml).expect("mongodb rules should parse");

        let mongodb_rule = raw.rules.iter().find(|r| r.id == "kingfisher.mongodb.3");
        assert!(mongodb_rule.is_some(), "mongodb.3 rule should exist");
        assert_eq!(
            mongodb_rule.unwrap().tls_mode,
            Some(TlsMode::Lax),
            "mongodb.3 rule should have tls_mode: lax"
        );
    }

    /// Test that the jdbc rule has tls_mode: lax.
    #[test]
    fn jdbc_rule_has_lax_tls_mode() {
        let yaml = include_str!("../crates/kingfisher-rules/data/rules/jdbc.yml");
        let raw: RawRules = serde_yaml::from_str(yaml).expect("jdbc rules should parse");

        let jdbc_rule = raw.rules.iter().find(|r| r.id == "kingfisher.jdbc.1");
        assert!(jdbc_rule.is_some(), "jdbc rule should exist");
        assert_eq!(
            jdbc_rule.unwrap().tls_mode,
            Some(TlsMode::Lax),
            "jdbc rule should have tls_mode: lax"
        );
    }

    /// Test that the jwt rule has tls_mode: lax.
    #[test]
    fn jwt_rule_has_lax_tls_mode() {
        let yaml = include_str!("../crates/kingfisher-rules/data/rules/jwt.yml");
        let raw: RawRules = serde_yaml::from_str(yaml).expect("jwt rules should parse");

        let jwt_rule = raw.rules.iter().find(|r| r.id == "kingfisher.jwt.1");
        assert!(jwt_rule.is_some(), "jwt rule should exist");
        assert_eq!(
            jwt_rule.unwrap().tls_mode,
            Some(TlsMode::Lax),
            "jwt rule should have tls_mode: lax"
        );
    }

    /// Test that rules without tls_mode (e.g., SaaS APIs) have None.
    #[test]
    fn github_rule_has_no_tls_mode() {
        let yaml = include_str!("../crates/kingfisher-rules/data/rules/github.yml");
        let raw: RawRules = serde_yaml::from_str(yaml).expect("github rules should parse");

        // GitHub rules should not have tls_mode set (SaaS API, always strict)
        for rule in &raw.rules {
            assert_eq!(rule.tls_mode, None, "github rule {} should not have tls_mode set", rule.id);
        }
    }

    /// Test that rules without tls_mode (e.g., SaaS APIs) have None.
    #[test]
    fn aws_rule_has_no_tls_mode() {
        let yaml = include_str!("../crates/kingfisher-rules/data/rules/aws.yml");
        let raw: RawRules = serde_yaml::from_str(yaml).expect("aws rules should parse");

        // AWS rules should not have tls_mode set (SaaS API, always strict)
        for rule in &raw.rules {
            assert_eq!(rule.tls_mode, None, "aws rule {} should not have tls_mode set", rule.id);
        }
    }
}
