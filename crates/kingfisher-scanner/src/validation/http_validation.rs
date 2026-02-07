use std::{collections::BTreeMap, future::Future, str::FromStr, time::Duration};

use anyhow::{anyhow, Error, Result};
use http::StatusCode;
use liquid::Object;
use quick_xml::de::from_str as xml_from_str;
use reqwest::{
    header,
    header::{HeaderMap, HeaderName, HeaderValue},
    Client, Method, RequestBuilder, Response, Url,
};
use serde::de::IgnoredAny;
use sha1::{Digest, Sha1};
use tokio::{net::lookup_host, time::sleep};
use tracing::debug;

use super::GLOBAL_USER_AGENT;
use kingfisher_rules::ResponseMatcher;

/// Build a deterministic cache key from the immutable parts of an HTTP request.
pub fn generate_http_cache_key_parts(
    method: &str,
    url: &Url,
    headers: &BTreeMap<String, String>,
    body: Option<&str>,
) -> String {
    let method = method.to_uppercase();
    let url = url.as_str();

    let mut hasher = Sha1::new();
    hasher.update(method.as_bytes());
    hasher.update(b"\0");
    hasher.update(url.as_bytes());
    hasher.update(b"\0");

    for (k, v) in headers {
        hasher.update(k.as_bytes());
        hasher.update(b":");
        hasher.update(v.as_bytes());
        hasher.update(b"\0");
    }

    if let Some(b) = body {
        hasher.update(b"BODY\0");
        hasher.update(b.as_bytes());
        hasher.update(b"\0");
    }

    format!("HTTP:{:x}", hasher.finalize())
}

/// Parse an HTTP method from a string.
pub fn parse_http_method(method_str: &str) -> Result<Method, String> {
    Method::from_str(method_str).map_err(|_| format!("Invalid HTTP method: {}", method_str))
}

/// Build a reqwest RequestBuilder using the provided parameters.
pub fn build_request_builder(
    client: &Client,
    method_str: &str,
    url: &Url,
    headers: &BTreeMap<String, String>,
    body: &Option<String>,
    timeout: Duration,
    parser: &liquid::Parser,
    globals: &liquid::Object,
) -> Result<RequestBuilder, String> {
    let method = parse_http_method(method_str).map_err(|err_msg| {
        debug!("{}", err_msg);
        err_msg
    })?;
    let mut request_builder = client.request(method, url.clone()).timeout(timeout);
    let custom_headers = process_headers(headers, parser, globals, url)
        .map_err(|e| format!("Error processing headers: {}", e))?;

    let user_agent = GLOBAL_USER_AGENT.as_str();
    let standard_headers = [
        (header::USER_AGENT, user_agent),
        (
            header::ACCEPT,
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        ),
        (header::ACCEPT_LANGUAGE, "en-US,en;q=0.5"),
        (header::ACCEPT_ENCODING, "gzip, deflate, br"),
        (header::CONNECTION, "keep-alive"),
    ];
    let mut combined_headers = HeaderMap::new();
    for (name, value) in &standard_headers {
        if let Ok(hv) = HeaderValue::from_str(value) {
            combined_headers.insert(name.clone(), hv);
        }
    }
    for (name, value) in custom_headers.iter() {
        combined_headers.insert(name.clone(), value.clone());
    }
    request_builder = request_builder.headers(combined_headers);

    if let Some(body_template) = body {
        let template = parser
            .parse(body_template)
            .map_err(|e| format!("Error parsing body template: {}", e))?;
        let rendered_body = template
            .render(globals)
            .map_err(|e| format!("Error rendering body template: {}", e))?;
        request_builder = request_builder.body(rendered_body);
    }

    Ok(request_builder)
}

/// Process headers from a BTreeMap, rendering any Liquid templates.
pub fn process_headers(
    headers: &BTreeMap<String, String>,
    parser: &liquid::Parser,
    globals: &Object,
    url: &Url,
) -> Result<HeaderMap> {
    let mut headers_map = HeaderMap::new();
    for (key, value) in headers {
        let template = match parser.parse(value) {
            Ok(t) => t,
            Err(e) => {
                debug!("Error parsing Liquid template for '{}': {}", key, e);
                continue;
            }
        };

        let header_value = match template.render(globals) {
            Ok(s) => s,
            Err(e) => {
                debug!(
                    "Failed to render header template. URL = <{}> | Key '{}': {}",
                    url.as_str(),
                    key,
                    e
                );
                continue;
            }
        };

        let cleaned_key = key.trim().replace(&['\n', '\r'][..], "");
        let cleaned_value = header_value.trim().replace(&['\n', '\r'][..], "");
        let name = match HeaderName::from_str(&cleaned_key) {
            Ok(n) => n,
            Err(e) => {
                debug!(
                    "Invalid header name. URL = <{}> | Key '{}': {}",
                    url.as_str(),
                    cleaned_key,
                    e
                );
                continue;
            }
        };
        let value = match HeaderValue::from_str(&cleaned_value) {
            Ok(v) => v,
            Err(e) => {
                debug!(
                    "Invalid header value. URL = <{}> | Value '{}': {}",
                    url.as_str(),
                    cleaned_value,
                    e
                );
                continue;
            }
        };
        headers_map.insert(name, value);
    }
    Ok(headers_map)
}

/// Exponential‐backoff retry helper that always returns `Result<T, anyhow::Error>`.
async fn retry_with_backoff<F, Fut, T>(
    mut operation: F,
    is_retryable: impl Fn(&Result<T, Error>, usize) -> bool,
    max_retries: usize,
    backoff_min: Duration,
    backoff_max: Duration,
) -> Result<T, Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, Error>>,
{
    let mut retries = 0;
    while retries <= max_retries {
        let result = operation().await;
        if !is_retryable(&result, retries) {
            return result;
        }
        retries += 1;
        if retries > max_retries {
            break;
        }
        let backoff = backoff_min.saturating_mul(2u32.pow(retries as u32)).min(backoff_max);
        sleep(backoff).await;
    }
    Err(anyhow!("Max retries reached"))
}

pub async fn retry_multipart_request<F, Fut>(
    mut build_request: F,
    max_retries: usize,
    backoff_min: Duration,
    backoff_max: Duration,
) -> Result<Response, Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = RequestBuilder>,
{
    retry_with_backoff(
        move || {
            let fut = build_request();
            async move {
                let rb = fut.await;
                rb.send().await.map_err(Error::from)
            }
        },
        |res: &Result<_, Error>, _attempt| match res {
            Ok(resp)
                if matches!(
                    resp.status(),
                    StatusCode::BAD_GATEWAY
                        | StatusCode::SERVICE_UNAVAILABLE
                        | StatusCode::GATEWAY_TIMEOUT
                ) =>
            {
                true
            }
            Err(_) => true,
            _ => false,
        },
        max_retries,
        backoff_min,
        backoff_max,
    )
    .await
}

pub async fn retry_request(
    request_builder: RequestBuilder,
    max_retries: u32,
    backoff_min: Duration,
    backoff_max: Duration,
) -> Result<Response, Error> {
    retry_with_backoff(
        move || {
            let rb =
                request_builder.try_clone().expect("retry_request: failed to clone RequestBuilder");
            async move { rb.send().await.map_err(Error::from) }
        },
        |res: &Result<_, Error>, _attempt| match res {
            Ok(resp)
                if matches!(
                    resp.status(),
                    StatusCode::BAD_GATEWAY
                        | StatusCode::SERVICE_UNAVAILABLE
                        | StatusCode::GATEWAY_TIMEOUT
                ) =>
            {
                true
            }
            Err(_) => true,
            _ => false,
        },
        max_retries as usize,
        backoff_min,
        backoff_max,
    )
    .await
}

/// Return `true` when the body is very likely HTML.
fn body_looks_like_html(body: &str, headers: &HeaderMap) -> bool {
    let header_says_html = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            let ct = ct.to_ascii_lowercase();
            ct.contains("text/html") || ct.contains("application/xhtml")
        })
        .unwrap_or(false);

    let mut end = 1024.min(body.len());
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    let probe = &body[..end];
    let trimmed = probe.trim_start_matches(|c: char| c.is_whitespace());
    let probe = trimmed.to_ascii_lowercase();
    let body_looks_htmlish = probe.starts_with('<') && probe.contains("<html");

    header_says_html && body_looks_htmlish
}

/// Validate the response by checking word and status matchers.
pub fn validate_response(
    matchers: &[ResponseMatcher],
    body: &str,
    status: &StatusCode,
    headers: &HeaderMap,
    html_allowed: bool,
) -> bool {
    let word_ok = matchers
        .iter()
        .filter_map(|m| {
            if let ResponseMatcher::WordMatch { words, match_all_words, negative, .. } = m {
                let raw = if *match_all_words {
                    words.iter().all(|w| body.contains(w))
                } else {
                    words.iter().any(|w| body.contains(w))
                };
                Some(if *negative { !raw } else { raw })
            } else {
                None
            }
        })
        .all(|b| b);

    let status_ok = matchers
        .iter()
        .filter_map(|m| {
            if let ResponseMatcher::StatusMatch {
                status: expected,
                match_all_status,
                negative,
                ..
            } = m
            {
                let raw = if *match_all_status {
                    expected.iter().all(|s| s.to_string() == status.as_str())
                } else {
                    expected.iter().any(|s| s.to_string() == status.as_str())
                };
                Some(if *negative { !raw } else { raw })
            } else {
                None
            }
        })
        .all(|b| b);

    let header_ok = matchers
        .iter()
        .filter_map(|m| {
            if let ResponseMatcher::HeaderMatch { header, expected, match_all_values, .. } = m {
                let val = headers
                    .get(header)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                Some(if *match_all_values {
                    expected.iter().all(|e| val.contains(&e.to_ascii_lowercase()))
                } else {
                    expected.iter().any(|e| val.contains(&e.to_ascii_lowercase()))
                })
            } else {
                None
            }
        })
        .all(|b| b);

    let json_ok = matchers
        .iter()
        .filter_map(|m| {
            if matches!(m, ResponseMatcher::JsonValid { .. }) {
                Some(serde_json::from_str::<serde_json::Value>(body).is_ok())
            } else {
                None
            }
        })
        .all(|b| b);

    let xml_ok = matchers
        .iter()
        .filter_map(|m| {
            if matches!(m, ResponseMatcher::XmlValid { .. }) {
                Some(xml_from_str::<IgnoredAny>(body).is_ok())
            } else {
                None
            }
        })
        .all(|b| b);

    let html_detected = body_looks_like_html(body, headers);
    let html_ok = html_allowed || !html_detected;

    word_ok && status_ok && header_ok && json_ok && xml_ok && html_ok
}

/// Check if a URL can be resolved via DNS.
pub async fn check_url_resolvable(url: &Url) -> Result<(), Box<dyn std::error::Error>> {
    let host = url.host_str().ok_or("No host in URL")?;
    let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let addr = format!("{}:{}", host, port);
    lookup_host(addr).await?.next().ok_or_else(|| "Failed to resolve URL".into()).map(|_| ())
}
