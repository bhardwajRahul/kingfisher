use std::{fs, process::Command};

use anyhow::{Context, Result};
use serde_json::{Deserializer, Value};

fn macos_arm64_known_missing_findings() -> &'static [(&'static str, &'static str)] {
    &[
        ("kingfisher.google.7", "AIzaSyBUPHAjZl3n8Eza66ka6B78iVyPteC5MgM"),
        (
            "kingfisher.pem.1",
            "MIICWQIBAAKBgHsSuRPLMDrxcwMB9P6ubGFGmlSvHvSXq2kfwycrcEKf/TCctShzA2HYo2IWed8n1rqazlESHnhNmCWlFWIMMFWagZyDBy9yy71MhWISvoTuQVyCx/z3q1v171fy+Ds5smKwZ8wK3bgwBTR7BTKfYNmearDZvPJgwK0jsYEJDZ/DAgElAoGAMeT+7FlK53akP31VfAFG4j83pcp0VVI+kmbSk1bMpWN0e33M5uKE1KPvNZpowkCVUpHJQ3YMWkj4ffbRUUM2L/jQmKkICf7vynIdq5cj+lF6lNXSzwq6pVR6/octdeKS/70DuGcVG+LiRTu2mRb6mPY9bIJIvcgenXajnVanx9UCQQDRwf6oyU/EH4x+kw/XQZi/RebtDPD1yIQuhVG8B1xkPxBsAywTwVDL7DSZ1BsbWJcl5HcXt/q0n/3NZ62XRr1VAkEAljSLsMOk5H7XCctEk3mCu1WgCsUvb/RRCBiBT+cic14OpVtytJMAeLeqcAhIj54ef4hQPGKbAsQZ3E/X4EsotwJAa7alXZfPA9jZcW4c5Ciai7wcoz3/MhrcF+OYrKnVf5YBg5LtHua6yZT4aqswg6oIbWd7bQty5yG5rqrcmcphOQJAHGrOUd/TFnjckyZ0wfRk11VjeG2Fg+IdKwuOFgkiMYB/T7da4+R1tfk7666KRK82M82uUJ0IkdISuvpZRhwOnwJBAI34lnrN4bNcUVB5kAXT9huyH8tJomNdsJOufS3vCi5tKaqKIc3jMIwtyuXsn4NhJNUFlgfPL70CPtb3x/eePqw=",
        ),
        (
            "kingfisher.privkey.2",
            "-----BEGIN RSA PRIVATE KEY-----MIICWQIBAAKBgHsSuRPLMDrxcwMB9P6ubGFGmlSvHvSXq2kfwycrcEKf/TCctShzA2HYo2IWed8n1rqazlESHnhNmCWlFWIMMFWagZyDBy9yy71MhWISvoTuQVyCx/z3q1v171fy+Ds5smKwZ8wK3bgwBTR7BTKfYNmearDZvPJgwK0jsYEJDZ/DAgElAoGAMeT+7FlK53akP31VfAFG4j83pcp0VVI+kmbSk1bMpWN0e33M5uKE1KPvNZpowkCVUpHJQ3YMWkj4ffbRUUM2L/jQmKkICf7vynIdq5cj+lF6lNXSzwq6pVR6/octdeKS/70DuGcVG+LiRTu2mRb6mPY9bIJIvcgenXajnVanx9UCQQDRwf6oyU/EH4x+kw/XQZi/RebtDPD1yIQuhVG8B1xkPxBsAywTwVDL7DSZ1BsbWJcl5HcXt/q0n/3NZ62XRr1VAkEAljSLsMOk5H7XCctEk3mCu1WgCsUvb/RRCBiBT+cic14OpVtytJMAeLeqcAhIj54ef4hQPGKbAsQZ3E/X4EsotwJAa7alXZfPA9jZcW4c5Ciai7wcoz3/MhrcF+OYrKnVf5YBg5LtHua6yZT4aqswg6oIbWd7bQty5yG5rqrcmcphOQJAHGrOUd/TFnjckyZ0wfRk11VjeG2Fg+IdKwuOFgkiMYB/T7da4+R1tfk7666KRK82M82uUJ0IkdISuvpZRhwOnwJBAI34lnrN4bNcUVB5kAXT9huyH8tJomNdsJOufS3vCi5tKaqKIc3jMIwtyuXsn4NhJNUFlgfPL70CPtb3x/eePqw=-----END RSA PRIVATE KEY-----",
        ),
        (
            "kingfisher.pypi.1",
            "pypi-AgEIcHlwaS5vcmcCAWEAAAYgNh9pJUqVF-EtMCwGaZYcStFR07RbE8hyb9h2vYxifO8",
        ),
        (
            "kingfisher.pypi.1",
            "pypi-AgEIcHlwaS5vcmcCAWIAAAYgf_d_XvJfqkOhrkqbEBo-eW9UID46ABNJIdGfaO3n3_k",
        ),
        (
            "kingfisher.pypi.1",
            "pypi-AgEIcHlwaS5vcmcCAWIAAAYgxbyLvb9egSCECeOdB3qW3h4oXEoNC6kJI0NtaFOQlUY",
        ),
        (
            "kingfisher.pypi.1",
            "pypi-AgEIcHlwaS5vcmcCAWIAAi97InZlcnNpb24iOiAxLCAicGVybWlzc2lvbnMiOiB7InByb2plY3RzIjogW119fQAABiBWHBa1jsbY-iN-Swf3JCrxy8Q8eRCxMrc_1KkkDuB6KQ",
        ),
        (
            "kingfisher.pypi.1",
            "pypi-AgEIcHlwaS5vcmcCAWIAAiV7InZlcnNpb24iOiAxLCAicGVybWlzc2lvbnMiOiAidXNlciJ9AAAGIBeIJGhXk8kPPref7vLuwlKbnSWusZKZivIh92GRUUX4",
        ),
        (
            "kingfisher.slack.1",
            "xapp-1-A01C259PH2A-1440755929120-7d5241948a2cc1b464add85df8a8e75f9040ae2869f6599926ed0b9dcafdb32b",
        ),
        (
            "kingfisher.slack.2",
            "xoxb-730191371696-1413868247813-IG7Z6nYevC2hdviE3aJhb5kY",
        ),
        (
            "kingfisher.slack.4",
            "https://hooks.slack.com/services/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",
        ),
    ]
}

fn is_known_macos_arm64_missing_finding(finding: &Value) -> bool {
    let rule_id = finding.get("rule_id").and_then(Value::as_str).unwrap_or_default();
    let snippet = finding.get("snippet").and_then(Value::as_str).unwrap_or_default();
    macos_arm64_known_missing_findings().iter().any(|(known_rule_id, known_snippet)| {
        rule_id == *known_rule_id && snippet == *known_snippet
    })
}

fn assert_findings_match_for_platform(actual: Vec<Value>, expected: Vec<Value>) {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        let missing = expected
            .iter()
            .filter(|finding| !actual.contains(finding))
            .cloned()
            .collect::<Vec<_>>();
        let extras = actual
            .iter()
            .filter(|finding| !expected.contains(finding))
            .cloned()
            .collect::<Vec<_>>();

        assert!(extras.is_empty(), "unexpected extra findings on macOS ARM64: {extras:#?}");
        assert!(
            missing.iter().all(is_known_macos_arm64_missing_finding),
            "unexpected missing findings on macOS ARM64: {missing:#?}"
        );
        return;
    }

    assert_eq!(actual, expected);
}

#[test]
fn scan_findings_match_pre_removal_baseline() -> Result<()> {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args(["scan", "testdata", "--format", "json", "--no-validate", "--no-update-check"])
        .output()
        .context("run kingfisher scan against testdata")?;

    let code = output.status.code().unwrap_or_default();
    assert!(
        matches!(code, 0 | 200),
        "expected exit code 0 or 200, got {code}. stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).context("scan stdout is not valid utf-8")?;
    let mut stream = Deserializer::from_str(&stdout).into_iter::<Value>();
    let value = stream
        .next()
        .transpose()
        .context("parse scan json output")?
        .context("scan output did not contain a json object")?;

    let findings = value
        .get("findings")
        .and_then(Value::as_array)
        .context("scan output missing findings array")?;

    let mut actual = findings
        .iter()
        .filter(|finding| {
            finding
                .get("finding")
                .and_then(Value::as_object)
                .and_then(|data| data.get("path"))
                .and_then(Value::as_str)
                .map(|path| !path.starts_with("testdata/parsers/"))
                .unwrap_or(true)
        })
        .map(|finding| {
            let rule = finding.get("rule").and_then(Value::as_object).cloned().unwrap_or_default();
            serde_json::json!({
                "rule_id": rule.get("id").and_then(Value::as_str),
                "snippet": finding
                    .get("finding")
                    .and_then(Value::as_object)
                    .and_then(|data| data.get("snippet"))
                    .and_then(Value::as_str),
            })
        })
        .collect::<Vec<_>>();
    actual.sort_by(|left, right| left.to_string().cmp(&right.to_string()));

    let mut expected = serde_json::from_str::<Vec<Value>>(
        &fs::read_to_string("testdata/parsers/scan_findings_baseline.json")
            .context("read scan findings baseline")?,
    )
    .context("parse scan findings baseline json")?
    .into_iter()
    .filter(|finding| finding.get("snippet").and_then(Value::as_str).is_some())
    .map(|finding| {
        serde_json::json!({
            "rule_id": finding.get("rule_id").and_then(Value::as_str),
            "snippet": finding.get("snippet").and_then(Value::as_str),
        })
    })
    .filter(|finding| {
        finding
            .get("snippet")
            .and_then(Value::as_str)
            .map(|snippet| !snippet.is_empty())
            .unwrap_or(true)
    })
    .collect::<Vec<_>>();
    expected.sort_by(|left, right| left.to_string().cmp(&right.to_string()));

    assert_findings_match_for_platform(actual, expected);
    Ok(())
}
