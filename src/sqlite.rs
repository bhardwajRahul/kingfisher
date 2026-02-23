use std::fmt::Write as FmtWrite;
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use tracing::debug;

const MAX_ROWS_PER_TABLE: usize = 100_000;
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;

/// Extract all user tables from a SQLite database as SQL text.
///
/// Returns a vec of `(logical_name, sql_text)` pairs, one per table.
/// Each entry contains the CREATE TABLE statement followed by INSERT
/// statements with explicit column names so that keyword-based secret
/// detectors can match column names like "api_key" near their values.
pub fn extract_sqlite_contents(path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("Failed to open SQLite database: {}", path.display()))?;

    conn.busy_timeout(std::time::Duration::from_secs(5))?;

    let tables = list_user_tables(&conn)?;
    if tables.is_empty() {
        debug!("SQLite database has no user tables: {}", path.display());
        return Ok(Vec::new());
    }

    let mut results = Vec::with_capacity(tables.len());
    let mut total_bytes: usize = 0;

    for (table_name, create_sql) in &tables {
        if total_bytes >= MAX_TOTAL_BYTES {
            debug!(
                "SQLite extraction hit total size limit ({MAX_TOTAL_BYTES} bytes), \
                 skipping remaining tables in {}",
                path.display()
            );
            break;
        }

        match dump_table(&conn, table_name, create_sql, MAX_TOTAL_BYTES - total_bytes) {
            Ok(sql_text) => {
                total_bytes += sql_text.len();
                let logical_name = format!("{}.sql", table_name);
                results.push((logical_name, sql_text.into_bytes()));
            }
            Err(e) => {
                debug!(
                    "Failed to dump table '{}' from {}: {e:#}",
                    table_name,
                    path.display()
                );
            }
        }
    }

    Ok(results)
}

/// List all user tables (excluding sqlite_* internal tables) along with
/// their CREATE TABLE SQL.
fn list_user_tables(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT name, sql FROM sqlite_master \
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         ORDER BY name",
    )?;

    let rows = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let sql: String = row.get(1)?;
        Ok((name, sql))
    })?;

    let mut tables = Vec::new();
    for row in rows {
        tables.push(row?);
    }
    Ok(tables)
}

/// Dump a single table as SQL text: the CREATE statement followed by
/// INSERT INTO statements with named columns.
fn dump_table(
    conn: &Connection,
    table_name: &str,
    create_sql: &str,
    remaining_budget: usize,
) -> Result<String> {
    let mut out = String::with_capacity(4096);
    writeln!(out, "{create_sql};")?;

    let col_names = column_names(conn, table_name)?;
    if col_names.is_empty() {
        return Ok(out);
    }

    let columns_fragment = col_names
        .iter()
        .map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(",");

    let query = format!("SELECT * FROM \"{}\"", table_name.replace('"', "\"\""));
    let mut stmt = conn.prepare(&query)?;
    let col_count = col_names.len();

    let mut rows_emitted: usize = 0;
    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        if rows_emitted >= MAX_ROWS_PER_TABLE {
            writeln!(out, "-- (truncated after {MAX_ROWS_PER_TABLE} rows)")?;
            break;
        }
        if out.len() >= remaining_budget {
            writeln!(out, "-- (truncated: size limit reached)")?;
            break;
        }

        write!(out, "INSERT INTO \"{table_name}\" ({columns_fragment}) VALUES (")?;

        for i in 0..col_count {
            if i > 0 {
                write!(out, ",")?;
            }
            write_value(&mut out, row, i)?;
        }

        writeln!(out, ");")?;
        rows_emitted += 1;
    }

    Ok(out)
}

fn column_names(conn: &Connection, table_name: &str) -> Result<Vec<String>> {
    let query = format!(
        "PRAGMA table_info(\"{}\")",
        table_name.replace('"', "\"\"")
    );
    let mut stmt = conn.prepare(&query)?;
    let names = stmt
        .query_map([], |row| {
            let name: String = row.get(1)?;
            Ok(name)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names)
}

fn write_value(out: &mut String, row: &rusqlite::Row<'_>, idx: usize) -> Result<()> {
    use rusqlite::types::ValueRef;
    match row.get_ref(idx)? {
        ValueRef::Null => write!(out, "NULL")?,
        ValueRef::Integer(i) => write!(out, "{i}")?,
        ValueRef::Real(f) => write!(out, "{f}")?,
        ValueRef::Text(t) => {
            let s = String::from_utf8_lossy(t);
            write!(out, "'{}'", s.replace('\'', "''"))?;
        }
        ValueRef::Blob(b) => {
            write!(out, "X'")?;
            for byte in b {
                write!(out, "{byte:02X}")?;
            }
            write!(out, "'")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_db() -> (NamedTempFile, std::path::PathBuf) {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE user_info (id INTEGER PRIMARY KEY, username TEXT, api_key TEXT);
             INSERT INTO user_info VALUES (1, 'alice', 'ghp_abc123def456ghi789jkl012mno345pqr678');
             INSERT INTO user_info VALUES (2, 'bob', 'AKIAIOSFODNN7EXAMPLE');
             CREATE TABLE config (key TEXT, value TEXT);
             INSERT INTO config VALUES ('db_password', 's3cret!passw0rd');",
        )
        .unwrap();
        (tmp, path)
    }

    #[test]
    fn extracts_all_tables() {
        let (_tmp, path) = create_test_db();
        let results = extract_sqlite_contents(&path).unwrap();
        assert_eq!(results.len(), 2);

        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"config.sql"));
        assert!(names.contains(&"user_info.sql"));
    }

    #[test]
    fn output_contains_column_names_and_values() {
        let (_tmp, path) = create_test_db();
        let results = extract_sqlite_contents(&path).unwrap();

        let user_info = results
            .iter()
            .find(|(n, _)| n == "user_info.sql")
            .unwrap();
        let sql = String::from_utf8_lossy(&user_info.1);

        assert!(sql.contains("CREATE TABLE"));
        assert!(sql.contains("\"api_key\""));
        assert!(sql.contains("ghp_abc123def456ghi789jkl012mno345pqr678"));
        assert!(sql.contains("INSERT INTO"));
    }

    #[test]
    fn handles_empty_database() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE empty_table (id INTEGER);")
            .unwrap();

        let results = extract_sqlite_contents(&path).unwrap();
        assert_eq!(results.len(), 1);
        let sql = String::from_utf8_lossy(&results[0].1);
        assert!(sql.contains("CREATE TABLE"));
        assert!(!sql.contains("INSERT INTO"));
    }

    #[test]
    fn handles_nonexistent_file() {
        let result = extract_sqlite_contents(Path::new("/nonexistent/database.db"));
        assert!(result.is_err());
    }

    #[test]
    fn handles_special_characters_in_values() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT);
             INSERT INTO t VALUES (1, 'it''s a test');
             INSERT INTO t VALUES (2, NULL);",
        )
        .unwrap();

        let results = extract_sqlite_contents(&path).unwrap();
        let sql = String::from_utf8_lossy(&results[0].1);
        assert!(sql.contains("'it''s a test'"));
        assert!(sql.contains("NULL"));
    }
}
