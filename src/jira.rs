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
    enum FrameState {
        Enter,
        Exit {
            node_type: Option<String>,
            child_count: usize,
        },
    }

    struct Frame<'a> {
        node: &'a serde_json::Value,
        state: FrameState,
    }

    let mut stack = vec![Frame {
        node,
        state: FrameState::Enter,
    }];
    let mut values: Vec<String> = Vec::new();

    while let Some(frame) = stack.pop() {
        match frame.state {
            FrameState::Enter => match frame.node {
                serde_json::Value::Object(map) => {
                    let node_type = map.get("type").and_then(|v| v.as_str());
                    if node_type == Some("text") {
                        values.push(
                            map.get("text")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                        );
                        continue;
                    }
                    if node_type == Some("hardBreak") {
                        values.push("\n".to_string());
                        continue;
                    }

                    let child_count = map
                        .get("content")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.len())
                        .unwrap_or(0);
                    stack.push(Frame {
                        node: frame.node,
                        state: FrameState::Exit {
                            node_type: node_type.map(|value| value.to_string()),
                            child_count,
                        },
                    });
                    if let Some(arr) = map.get("content").and_then(|v| v.as_array()) {
                        for child in arr.iter().rev() {
                            stack.push(Frame {
                                node: child,
                                state: FrameState::Enter,
                            });
                        }
                    }
                }
                serde_json::Value::Array(arr) => {
                    let child_count = arr.len();
                    stack.push(Frame {
                        node: frame.node,
                        state: FrameState::Exit {
                            node_type: None,
                            child_count,
                        },
                    });
                    for child in arr.iter().rev() {
                        stack.push(Frame {
                            node: child,
                            state: FrameState::Enter,
                        });
                    }
                }
                _ => values.push(String::new()),
            },
            FrameState::Exit {
                node_type,
                child_count,
            } => {
                let start = values.len().saturating_sub(child_count);
                let child_texts = values.split_off(start);
                let mut text = match node_type.as_deref() {
                    Some("table") => join_texts_with_separator(child_texts, "\n"),
                    Some("tableRow") => join_texts_with_separator(child_texts, " "),
                    _ => child_texts.concat(),
                };

                if matches!(
                    node_type.as_deref(),
                    Some("paragraph" | "heading" | "blockquote" | "listItem" | "codeBlock" | "tableRow" | "table")
                ) && !text.is_empty()
                    && !text.ends_with('\n')
                {
                    text.push('\n');
                }

                values.push(text);
            }
        }
    }

    values.pop().unwrap_or_default()
}

fn join_texts_with_separator(child_texts: Vec<String>, separator: &str) -> String {
    let mut text = String::new();
    let mut last_was_whitespace = true;
    for child_text in child_texts {
        if child_text.is_empty() {
            continue;
        }
        let child_starts_non_whitespace = child_text
            .chars()
            .next()
            .map(|c| !c.is_whitespace())
            .unwrap_or(false);
        let needs_separator = !last_was_whitespace && child_starts_non_whitespace;
        if needs_separator {
            text.push_str(separator);
        }
        text.push_str(&child_text);
        if let Some(last_char) = child_text.chars().rev().next() {
            last_was_whitespace = last_char.is_whitespace();
        }
    }
    text
}

/// Returns true if the value looks like an ADF document root.
fn is_adf(value: &serde_json::Value) -> bool {
    value
        .get("type")
        .and_then(|v| v.as_str())
        .map(|t| t == "doc")
        .unwrap_or(false)
}

fn flatten_adf_fields(issue_value: &mut serde_json::Value) {
    // Jira Cloud API v3 returns descriptions as Atlassian Document Format (ADF),
    // a nested JSON tree whose leaf text nodes contain the actual content.
    // Flatten ADF to a plain string so the secret scanner can match against it.
    if let Some(desc) = issue_value.pointer("/fields/description") {
        if is_adf(desc) {
            let plain_text = extract_adf_text(desc);
            if let Some(fields) = issue_value
                .pointer_mut("/fields")
                .and_then(|value| value.as_object_mut())
            {
                fields.insert(
                    "description".to_string(),
                    serde_json::Value::String(plain_text.trim_end_matches('\n').to_string()),
                );
            }
        }
    }

    // Apply the same ADF flattening to comment bodies.
    if let Some(comments) = issue_value.pointer_mut("/fields/comment/comments") {
        if let Some(arr) = comments.as_array_mut() {
            for comment in arr.iter_mut() {
                let plain_text = comment.get("body").and_then(|body| {
                    if is_adf(body) {
                        Some(extract_adf_text(body))
                    } else {
                        None
                    }
                });
                if let Some(plain_text) = plain_text {
                    if let Some(comment_obj) = comment.as_object_mut() {
                        comment_obj.insert(
                            "body".to_string(),
                            serde_json::Value::String(
                                plain_text.trim_end_matches('\n').to_string(),
                            ),
                        );
                    }
                }
            }
        }
    }
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

        flatten_adf_fields(&mut issue_value);

        let file = output_dir.join(format!("{}.json", issue.key));
        std::fs::write(&file, serde_json::to_vec(&issue_value)?)?;
        paths.push(file);
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::{extract_adf_text, flatten_adf_fields, is_adf};
    use serde_json::json;

    #[test]
    fn is_adf_detects_doc_root() {
        let doc = json!({"type": "doc", "version": 1, "content": []});
        assert!(is_adf(&doc));
        assert!(!is_adf(&json!({"type": "paragraph"})));
        assert!(!is_adf(&json!("not-a-doc")));
    }

    #[test]
    fn extract_adf_text_concatenates_adjacent_text_nodes() {
        let value = json!({
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "sk-"},
                    {"type": "text", "text": "proj-123"}
                ]
            }]
        });
        let text = extract_adf_text(&value);
        assert_eq!(text.trim_end(), "sk-proj-123");
    }

    #[test]
    fn extract_adf_text_preserves_hard_breaks() {
        let value = json!({
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "foo"},
                    {"type": "hardBreak"},
                    {"type": "text", "text": "bar"}
                ]
            }]
        });
        let text = extract_adf_text(&value);
        assert_eq!(text.trim_end(), "foo\nbar");
    }

    #[test]
    fn extract_adf_text_adds_paragraph_separator() {
        let value = json!({
            "type": "doc",
            "version": 1,
            "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": "first"}]},
                {"type": "paragraph", "content": [{"type": "text", "text": "second"}]}
            ]
        });
        let text = extract_adf_text(&value);
        assert_eq!(text.trim_end(), "first\nsecond");
    }

    #[test]
    fn extract_adf_text_returns_empty_for_non_adf_values() {
        let value = json!("plain description string");
        let text = extract_adf_text(&value);
        assert_eq!(text, "");

        let number_value = json!(42);
        let number_text = extract_adf_text(&number_value);
        assert_eq!(number_text, "");

        let null_value = json!(null);
        let null_text = extract_adf_text(&null_value);
        assert_eq!(null_text, "");
    }

    #[test]
    fn extract_adf_text_handles_missing_content_fields() {
        let doc_without_content = json!({
            "type": "doc",
            "version": 1
        });
        let text = extract_adf_text(&doc_without_content);
        assert_eq!(text, "");

        let paragraph_without_content = json!({
            "type": "paragraph"
        });
        let para_text = extract_adf_text(&paragraph_without_content);
        assert_eq!(para_text, "");
    }

    #[test]
    fn extract_adf_text_handles_empty_doc() {
        let empty_doc = json!({
            "type": "doc",
            "version": 1,
            "content": []
        });
        let text = extract_adf_text(&empty_doc);
        assert_eq!(text, "");
    }

    #[test]
    fn extract_adf_text_handles_lists_and_code_blocks() {
        let value = json!({
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "bulletList",
                    "content": [
                        {
                            "type": "listItem",
                            "content": [{
                                "type": "paragraph",
                                "content": [{"type": "text", "text": "item1"}]
                            }]
                        },
                        {
                            "type": "listItem",
                            "content": [{
                                "type": "paragraph",
                                "content": [{"type": "text", "text": "item2"}]
                            }]
                        }
                    ]
                },
                {
                    "type": "codeBlock",
                    "content": [{"type": "text", "text": "code"}]
                }
            ]
        });
        let text = extract_adf_text(&value);
        assert_eq!(text.trim_end(), "item1\nitem2\ncode");
    }

    #[test]
    fn flatten_adf_fields_converts_comment_bodies() {
        let mut issue_value = json!({
            "fields": {
                "comment": {
                    "comments": [
                        {
                            "body": {
                                "type": "doc",
                                "version": 1,
                                "content": [{
                                    "type": "paragraph",
                                    "content": [{"type": "text", "text": "secret"}]
                                }]
                            }
                        }
                    ]
                }
            }
        });
        flatten_adf_fields(&mut issue_value);
        let body = issue_value
            .pointer("/fields/comment/comments/0/body")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(body, "secret");
    }

    #[test]
    fn flatten_adf_fields_converts_description() {
        let mut issue_value = json!({
            "fields": {
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{"type": "text", "text": "desc"}]
                    }]
                }
            }
        });
        flatten_adf_fields(&mut issue_value);
        let desc = issue_value
            .pointer("/fields/description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(desc, "desc");
    }

    #[test]
    fn flatten_adf_fields_leaves_plain_description() {
        let mut issue_value = json!({
            "fields": {
                "description": "plain description"
            }
        });
        flatten_adf_fields(&mut issue_value);
        let desc = issue_value
            .pointer("/fields/description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(desc, "plain description");
    }

    #[test]
    fn flatten_adf_fields_handles_missing_description() {
        let mut issue_value = json!({
            "fields": {
                "summary": "no description here"
            }
        });
        flatten_adf_fields(&mut issue_value);
        assert!(issue_value.pointer("/fields/description").is_none());
    }
}
