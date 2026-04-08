use std::{fs, process::Command};

use anyhow::{Context, Result};
use serde_json::{Deserializer, Value};

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

    assert_eq!(actual, expected);
    Ok(())
}
