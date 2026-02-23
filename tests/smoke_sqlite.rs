use assert_cmd::prelude::*;

#[test]
fn smoke_scan_sqlite_database() -> anyhow::Result<()> {
    use rusqlite::Connection;
    use std::process::Command;

    let dir = tempfile::tempdir()?;
    let db_path = dir.path().join("secrets.db");
    let github_pat = "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";

    {
        let conn = Connection::open(&db_path)?;
        conn.execute_batch(&format!(
            "CREATE TABLE user_info (id INTEGER PRIMARY KEY, username TEXT, api_key TEXT);
             INSERT INTO user_info VALUES (1, 'alice', '{github_pat}');"
        ))?;
    }

    let findings_code = 200;

    // With extraction enabled, the secret should be found and the path should
    // reference the table-level logical file (secrets.db/user_info.sql).
    let output = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            db_path.to_str().unwrap(),
            "--confidence=low",
            "--format",
            "json",
            "--no-update-check",
        ])
        .assert()
        .code(findings_code)
        .stdout(predicates::str::contains(github_pat))
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    assert!(
        stdout.contains("user_info.sql"),
        "Expected table-level path in finding, got: {stdout}"
    );

    dir.close()?;
    Ok(())
}
