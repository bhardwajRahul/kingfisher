use anyhow::{Context, Result};
use gouqi::{r#async::Jira, Credentials, SearchOptions};
use reqwest::Client;
use std::path::PathBuf;
use url::Url;

// Re-export the Issue type from gouqi so callers don't depend on the crate.
pub use gouqi::Issue as JiraIssue;

/// Recursively extracts plain text from an Atlassian Document Format (ADF) node.
///
/// Jira Cloud API v3 returns issue descriptions as ADF — a nested JSON structure
/// rather than a plain string. This function walks the content tree and collects
/// all leaf `"type": "text"` node values so that secret scanners can find them.
fn extract_adf_text(node: &serde_json::Value) -> String {
    match node {
        serde_json::Value::Object(map) => {
            if map.get("type").and_then(|v| v.as_str()) == Some("text") {
                return map
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
            }
            map.get("content")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(extract_adf_text)
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default()
        }
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(extract_adf_text)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    }
}

/// Returns true if the value looks like an ADF document root.
fn is_adf(value: &serde_json::Value) -> bool {
    value
        .get("type")
        .and_then(|v| v.as_str())
        .map(|t| t == "doc")
        .unwrap_or(false)
}

pub async fn fetch_issues(
    jira_url: Url,
    jql: &str,
    max_results: usize,
    ignore_certs: bool,
) -> Result<Vec<JiraIssue>> {
    // build a &str without any trailing `/`
    let base = jira_url.as_str().trim_end_matches('/');

    let client = Client::builder()
        .danger_accept_invalid_certs(ignore_certs)
        .build()
        .context("Failed to build HTTP client")?;

    let credentials = match std::env::var("KF_JIRA_TOKEN") {
        Ok(token) => Credentials::Bearer(token),
        Err(_) => Credentials::Anonymous,
    };

    let jira = Jira::from_client(base.to_string(), credentials, client)?;

    let search_options = SearchOptions::builder().max_results(max_results as u64).build();

    let results = jira.search().list(jql, &search_options).await?;
    Ok(results.issues)
}

pub async fn download_issues_to_dir(
    jira_url: Url,
    jql: &str,
    max_results: usize,
    ignore_certs: bool,
    output_dir: &PathBuf,
) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(output_dir)?;
    let issues = fetch_issues(jira_url, jql, max_results, ignore_certs).await?;
    let mut paths = Vec::new();
    for issue in issues {
        let mut issue_value = serde_json::to_value(&issue)?;

        // Jira Cloud API v3 returns descriptions as Atlassian Document Format (ADF),
        // a nested JSON tree whose leaf text nodes contain the actual content.
        // Flatten ADF to a plain string so the secret scanner can match against it.
        if let Some(desc) = issue_value.pointer("/fields/description").cloned() {
            if is_adf(&desc) {
                let plain_text = extract_adf_text(&desc);
                if let Some(fields) = issue_value.pointer_mut("/fields") {
                    fields["description"] = serde_json::Value::String(plain_text);
                }
            }
        }

        // Apply the same ADF flattening to comment bodies.
        if let Some(comments) = issue_value.pointer_mut("/fields/comment/comments") {
            if let Some(arr) = comments.as_array_mut() {
                for comment in arr.iter_mut() {
                    if let Some(body) = comment.get("body").cloned() {
                        if is_adf(&body) {
                            let plain_text = extract_adf_text(&body);
                            comment["body"] = serde_json::Value::String(plain_text);
                        }
                    }
                }
            }
        }

        let file = output_dir.join(format!("{}.json", issue.key));
        std::fs::write(&file, serde_json::to_vec(&issue_value)?)?;
        paths.push(file);
    }
    Ok(paths)
}
