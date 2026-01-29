//! Direct secret revocation without pattern matching.
//!
//! This module provides functionality to revoke a known secret directly against
//! a rule's revocation configuration, bypassing the normal pattern-matching phase.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use liquid::Object;
use liquid_core::Value;
use regex::Regex;
use reqwest::Client;
use serde::Serialize;
use tracing::debug;

use crate::{
    cli::{commands::revoke::RevokeArgs, global::GlobalArgs},
    liquid_filters::register_all,
    rule_loader::RuleLoader,
    rules::{rule::Rule, HttpValidation, Revocation},
    validation::httpvalidation::{build_request_builder, retry_request, validate_response},
    validation::GLOBAL_USER_AGENT,
};

/// Result of a direct revocation attempt.
#[derive(Debug, Clone, Serialize)]
pub struct DirectRevocationResult {
    /// The rule ID that was used for revocation.
    pub rule_id: String,
    /// The rule name.
    pub rule_name: String,
    /// Whether the secret was revoked successfully.
    pub revoked: bool,
    /// HTTP status code from the revocation request (if applicable).
    pub status_code: Option<u16>,
    /// Response body or error message.
    pub message: String,
}

/// Find all rules matching an ID or prefix.
///
/// Returns all matching rules, or an error if no rules match.
fn find_rules_by_selector<'a>(
    selector: &str,
    rules: &'a BTreeMap<String, Rule>,
) -> Result<Vec<&'a Rule>> {
    let mut matches: Vec<&Rule> = Vec::new();

    let selectors_to_try: Vec<std::borrow::Cow<'_, str>> = if selector.starts_with("kingfisher.") {
        vec![std::borrow::Cow::Borrowed(selector)]
    } else {
        vec![
            std::borrow::Cow::Borrowed(selector),
            std::borrow::Cow::Owned(format!("kingfisher.{}", selector)),
        ]
    };

    for try_selector in &selectors_to_try {
        for (id, rule) in rules {
            if id == try_selector.as_ref()
                || (id.starts_with(try_selector.as_ref())
                    && id.as_bytes().get(try_selector.len()) == Some(&b'.'))
            {
                matches.push(rule);
            }
        }
        if !matches.is_empty() {
            break;
        }
    }

    if matches.is_empty() {
        bail!(
            "No rule found matching '{}'. Use `kingfisher rules list` to see available rules.",
            selector
        );
    }

    Ok(matches)
}

/// Extract Liquid template variable names from a string.
fn extract_template_vars(text: &str) -> BTreeSet<String> {
    let re = Regex::new(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\|[^}]*)?\}\}").unwrap();
    re.captures_iter(text).filter_map(|cap| cap.get(1).map(|m| m.as_str().to_uppercase())).collect()
}

/// Extract all template variables used in a revocation configuration.
fn extract_revocation_vars(revocation: &Revocation) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();

    match revocation {
        Revocation::Http(http) => {
            vars.extend(extract_template_vars(&http.request.url));
            for (key, value) in &http.request.headers {
                vars.extend(extract_template_vars(key));
                vars.extend(extract_template_vars(value));
            }
            if let Some(body) = &http.request.body {
                vars.extend(extract_template_vars(body));
            }
        }
    }

    vars
}

/// Build the globals object for Liquid template rendering.
fn build_globals(
    secret: &str,
    args: &[String],
    variables: &[String],
    template_vars: &BTreeSet<String>,
) -> Result<Object> {
    let mut globals = Object::new();
    globals.insert("TOKEN".into(), Value::scalar(secret.to_string()));

    let auto_assign_vars: Vec<&String> = template_vars.iter().filter(|v| *v != "TOKEN").collect();

    for (i, arg_value) in args.iter().enumerate() {
        if i < auto_assign_vars.len() {
            let var_name = auto_assign_vars[i];
            debug!("Auto-assigning --arg '{}' to variable '{}'", arg_value, var_name);
            globals.insert(var_name.clone().into(), Value::scalar(arg_value.clone()));
        }
    }

    for var in variables {
        let (name, value) = var
            .split_once('=')
            .ok_or_else(|| anyhow!("Invalid variable format '{}'. Expected NAME=VALUE", var))?;

        let name = name.trim().to_uppercase();
        let value = value.trim().to_string();

        if name.is_empty() {
            bail!("Variable name cannot be empty in '{}'", var);
        }

        globals.insert(name.into(), Value::scalar(value));
    }

    Ok(globals)
}

/// Read the secret value from the provided argument or stdin.
fn read_secret(secret_arg: Option<&str>) -> Result<String> {
    match secret_arg {
        Some("-") => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer).context("Failed to read secret from stdin")?;
            Ok(buffer.trim().to_string())
        }
        Some(s) => Ok(s.to_string()),
        None => {
            bail!("No secret provided. Pass a secret as an argument or use '-' to read from stdin.")
        }
    }
}

/// Render the revocation URL using Liquid templates.
async fn render_and_parse_url(
    parser: &liquid::Parser,
    globals: &Object,
    url_template: &str,
) -> Result<reqwest::Url> {
    let template =
        parser.parse(url_template).map_err(|e| anyhow!("Failed to parse URL template: {}", e))?;

    let rendered =
        template.render(globals).map_err(|e| anyhow!("Failed to render URL template: {}", e))?;

    reqwest::Url::parse(&rendered).map_err(|e| anyhow!("Invalid URL '{}': {}", rendered, e))
}

/// Execute HTTP revocation against the provided rule.
async fn execute_http_revocation(
    http_revocation: &HttpValidation,
    globals: &Object,
    client: &Client,
    parser: &liquid::Parser,
    timeout: Duration,
    retries: u32,
) -> Result<DirectRevocationResult> {
    let url = render_and_parse_url(parser, globals, &http_revocation.request.url).await?;

    debug!("Revoking against URL: {}", url);

    let request_builder = build_request_builder(
        client,
        &http_revocation.request.method,
        &url,
        &http_revocation.request.headers,
        &http_revocation.request.body,
        timeout,
        parser,
        globals,
    )
    .map_err(|e| anyhow!("Failed to build request: {}", e))?;

    let backoff_min = Duration::from_millis(100);
    let backoff_max = Duration::from_secs(2);

    let response = retry_request(request_builder, retries, backoff_min, backoff_max)
        .await
        .map_err(|e| anyhow!("Request failed: {}", e))?;

    let status = response.status();
    let headers = response.headers().clone();
    let body =
        response.text().await.unwrap_or_else(|e| format!("Failed to read response body: {}", e));

    let display_body = if body.len() > 500 { format!("{}...", &body[..500]) } else { body.clone() };

    let matchers = http_revocation
        .request
        .response_matcher
        .as_deref()
        .ok_or_else(|| anyhow!("Revocation response_matcher is required"))?;
    let html_allowed = http_revocation.request.response_is_html;
    let revoked = validate_response(matchers, &body, &status, &headers, html_allowed);

    Ok(DirectRevocationResult {
        rule_id: String::new(),
        rule_name: String::new(),
        revoked,
        status_code: Some(status.as_u16()),
        message: display_body,
    })
}

/// Run direct revocation of a secret against one or more rules.
pub async fn run_direct_revocation(
    args: &RevokeArgs,
    global_args: &GlobalArgs,
) -> Result<Vec<DirectRevocationResult>> {
    let secret = read_secret(args.secret.as_deref())?;

    if secret.is_empty() {
        bail!("Secret cannot be empty");
    }

    let loader = RuleLoader::new()
        .load_builtins(!args.no_builtins)
        .additional_rule_load_paths(&args.rules_path);

    let scan_args = crate::direct_validate::create_minimal_scan_args();
    let loaded = loader.load(&scan_args)?;

    let matching_rules = find_rules_by_selector(&args.rule, loaded.id_to_rule())?;
    let num_matching_rules = matching_rules.len();

    if num_matching_rules > 1 {
        debug!("Rule selector '{}' matches {} rules, trying all", args.rule, num_matching_rules);
    }

    let client = Client::builder()
        .danger_accept_invalid_certs(global_args.ignore_certs)
        .timeout(Duration::from_secs(args.timeout))
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .gzip(true)
        .deflate(true)
        .brotli(true)
        .build()
        .context("Failed to build HTTP client")?;

    let parser = register_all(liquid::ParserBuilder::with_stdlib()).build()?;
    let timeout = Duration::from_secs(args.timeout);

    let mut results = Vec::new();

    for rule in matching_rules {
        let rule_id = rule.id().to_string();
        let rule_name = rule.name().to_string();

        debug!("Trying rule: {} ({})", rule_name, rule_id);

        let revocation = match rule.syntax().revocation.as_ref() {
            Some(v) => v,
            None => {
                debug!("Rule '{}' has no revocation defined, skipping", rule_id);
                continue;
            }
        };

        let template_vars = extract_revocation_vars(revocation);
        let non_token_vars: Vec<&String> = template_vars.iter().filter(|v| *v != "TOKEN").collect();

        if args.args.len() > non_token_vars.len() {
            if num_matching_rules > 1 {
                debug!(
                    "Rule '{}' expects {} variable(s) but {} --arg value(s) provided, skipping",
                    rule_id,
                    non_token_vars.len(),
                    args.args.len()
                );
                continue;
            } else {
                let var_list = if non_token_vars.is_empty() {
                    "none".to_string()
                } else {
                    non_token_vars.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                };
                bail!(
                    "Too many --arg values provided. Rule '{}' expects {} additional variable(s): {}",
                    rule_id,
                    non_token_vars.len(),
                    var_list
                );
            }
        }

        let globals = build_globals(&secret, &args.args, &args.variables, &template_vars)?;

        if !non_token_vars.is_empty() && !args.args.is_empty() {
            debug!(
                "Rule '{}' uses variables: {:?}, auto-assigned from --arg: {:?}",
                rule_id, non_token_vars, args.args
            );
        }

        let mut result = match revocation {
            Revocation::Http(http_revocation) => {
                execute_http_revocation(
                    http_revocation,
                    &globals,
                    &client,
                    &parser,
                    timeout,
                    args.retries,
                )
                .await?
            }
        };

        result.rule_id = rule_id;
        result.rule_name = rule_name;
        results.push(result);
    }

    if results.is_empty() {
        bail!(
            "No rules with revocation found matching '{}'. \
             Use `kingfisher rules list` to see available rules.",
            args.rule
        );
    }

    Ok(results)
}

/// Print revocation results to stdout.
pub fn print_results(results: &[DirectRevocationResult], format: &str, use_color: bool) {
    match format {
        "json" => {
            if results.len() == 1 {
                println!("{}", serde_json::to_string_pretty(&results[0]).unwrap());
            } else {
                println!("{}", serde_json::to_string_pretty(results).unwrap());
            }
        }
        _ => {
            for (i, result) in results.iter().enumerate() {
                if i > 0 {
                    println!();
                }

                let revoked_str = if result.revoked {
                    if use_color {
                        "\x1b[32m✓ REVOKED\x1b[0m"
                    } else {
                        "REVOKED"
                    }
                } else if use_color {
                    "\x1b[31m✗ FAILED\x1b[0m"
                } else {
                    "FAILED"
                };

                println!("Rule:     {} ({})", result.rule_name, result.rule_id);
                println!("Result:   {}", revoked_str);
                if let Some(status) = result.status_code {
                    println!("Status:   {}", status);
                }
                if !result.message.is_empty() {
                    println!("Response: {}", result.message);
                }
            }
        }
    }
}

/// Check if any result was revoked.
pub fn any_revoked(results: &[DirectRevocationResult]) -> bool {
    results.iter().any(|r| r.revoked)
}
