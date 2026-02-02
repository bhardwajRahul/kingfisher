# Kingfisher Library Crates

[← Back to README](../README.md)

Kingfisher's functionality is available as a set of Rust library crates that can be embedded into other applications. This guide covers how to use these crates for secret scanning in your own Rust projects.

## Crate Overview

| Crate | Description |
|-------|-------------|
| `kingfisher-core` | Core types: `Blob`, `BlobId`, `Location`, `Origin`, entropy calculation |
| `kingfisher-rules` | Rule definitions, YAML parsing, compiled rule database, builtin rules |
| `kingfisher-scanner` | High-level scanning API with `Scanner` and `Finding` types |

### Optional Features

The `kingfisher-scanner` crate supports optional validation features:

| Feature | Description |
|---------|-------------|
| `validation` | Core validation support (includes HTTP validation) |
| `validation-http` | HTTP-based validation for API tokens |
| `validation-aws` | AWS credential validation via STS GetCallerIdentity |
| `validation-all` | Enable all validation features |

## Quick Start

Add the crates to your `Cargo.toml`:

```toml
[dependencies]
kingfisher-core = { git = "https://github.com/mongodb/kingfisher" }
kingfisher-rules = { git = "https://github.com/mongodb/kingfisher" }
kingfisher-scanner = { git = "https://github.com/mongodb/kingfisher" }
```

### Basic File Scanning

```rust
use std::sync::Arc;
use kingfisher_core::Blob;
use kingfisher_rules::{get_builtin_rules, RulesDatabase, Rule};
use kingfisher_scanner::Scanner;

fn main() -> anyhow::Result<()> {
    // 1. Load the builtin rules
    let rules = get_builtin_rules(None)?;
    
    // 2. Convert to Rule objects and compile into a database
    let rule_vec: Vec<Rule> = rules.iter_rules()
        .map(|syntax| Rule::new(syntax.clone()))
        .collect();
    let rules_db = Arc::new(RulesDatabase::from_rules(rule_vec)?);
    
    // 3. Create a scanner
    let scanner = Scanner::new(rules_db);
    
    // 4. Scan a file
    let findings = scanner.scan_file("path/to/file.txt")?;
    
    for finding in findings {
        println!("Found {} at line {}", 
            finding.rule_name, 
            finding.location.start_line);
    }
    
    Ok(())
}
```

### Scanning In-Memory Content

```rust
use std::sync::Arc;
use kingfisher_rules::{get_builtin_rules, RulesDatabase, Rule};
use kingfisher_scanner::Scanner;

fn scan_content(content: &[u8]) -> anyhow::Result<()> {
    let rules = get_builtin_rules(None)?;
    let rule_vec: Vec<Rule> = rules.iter_rules()
        .map(|syntax| Rule::new(syntax.clone()))
        .collect();
    let rules_db = Arc::new(RulesDatabase::from_rules(rule_vec)?);
    
    let scanner = Scanner::new(rules_db);
    
    // Scan bytes directly - no file I/O needed
    let findings = scanner.scan_bytes(content);
    
    for finding in &findings {
        println!("Secret: {} ({})", finding.rule_name, finding.confidence);
    }
    
    Ok(())
}
```

---

## kingfisher-core

Core types and utilities for working with scannable content.

### Blob - Content Abstraction

`Blob` represents content that can be scanned. It supports:
- **File-backed content** with memory mapping for large files
- **In-memory content** for programmatic use
- **Borrowed content** for zero-copy scanning

```rust
use kingfisher_core::Blob;

// From a file (memory-mapped for efficiency)
let blob = Blob::from_file("secret.txt")?;

// From owned bytes
let blob = Blob::from_bytes(vec![0x41, 0x42, 0x43]);

// Access the content
let bytes: &[u8] = blob.bytes();
let id: BlobId = blob.id();  // SHA-1 based identifier
```

### BlobId - Content Identity

`BlobId` provides a unique identifier for content, computed using a SHA-1 hash (compatible with Git's blob IDs):

```rust
use kingfisher_core::BlobId;

let id = BlobId::new(b"hello world");
println!("Blob ID: {}", id.hex());  // 40-character hex string

// Parse from hex
let id = BlobId::from_hex("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")?;
```

### Location - Source Positions

Track positions within scanned content:

```rust
use kingfisher_core::{LocationMapping, SourceSpan};

let content = b"line1\nline2\nline3";
let mapping = LocationMapping::new(content);

// Convert byte offset to line/column
let point = mapping.get_source_point(7);  // Returns (line: 2, column: 2)

// Get a span
let span = mapping.get_source_span(6..11);  // "line2"
```

### Entropy Calculation

Calculate Shannon entropy to filter high-randomness content:

```rust
use kingfisher_core::calculate_shannon_entropy;

let entropy = calculate_shannon_entropy(b"AKIAIOSFODNN7EXAMPLE");
println!("Entropy: {:.2} bits", entropy);  // ~4.0 for random-looking strings
```

### Origin - Provenance Tracking

Track where content came from:

```rust
use kingfisher_core::{Origin, FileOrigin, GitRepoOrigin};
use std::path::PathBuf;

// File origin
let origin = Origin::File(FileOrigin {
    path: PathBuf::from("/path/to/file.txt"),
});

// Git repository origin
let origin = Origin::GitRepo(GitRepoOrigin {
    repo_path: PathBuf::from("/path/to/repo"),
    remote_url: Some("https://github.com/org/repo".into()),
});
```

---

## kingfisher-rules

Rule definitions, YAML parsing, and the compiled rule database.

### Loading Builtin Rules

Kingfisher comes with 400+ builtin rules for common secret types:

```rust
use kingfisher_rules::{get_builtin_rules, Confidence};

// Load all rules with Medium confidence or higher (default)
let rules = get_builtin_rules(None)?;

// Load only High confidence rules
let rules = get_builtin_rules(Some(Confidence::High))?;

println!("Loaded {} rules", rules.num_rules());
```

### Loading Custom Rules

Load rules from YAML files or directories:

```rust
use kingfisher_rules::{Rules, Confidence};

// From a single file
let rules = Rules::from_paths(&["my-rules.yml"], Confidence::Medium)?;

// From a directory (recursively finds .yml files)
let rules = Rules::from_paths(&["rules/"], Confidence::Medium)?;

// Merge multiple sources
let mut rules = Rules::new();
rules.update(Rules::from_paths(&["builtin/"], Confidence::Medium)?);
rules.update(Rules::from_paths(&["custom/"], Confidence::Medium)?);
```

### Rule Syntax YAML Format

```yaml
rules:
  - name: My Custom API Key
    id: custom.myapi.1
    pattern: |
      (?i)
      myapi[_-]?key\s*[:=]\s*
      ["']?([A-Za-z0-9]{32})["']?
    min_entropy: 3.5
    confidence: high
    examples:
      - 'MYAPI_KEY=abc123def456ghi789jkl012mno345pq'
    validation:
      type: Http
      content:
        request:
          method: GET
          url: https://api.example.com/validate
          headers:
            Authorization: Bearer {{ TOKEN }}
          response_matcher:
            - type: StatusMatch
              status: [200]
```

### Compiling Rules

The `RulesDatabase` compiles rules for efficient multi-pattern matching:

```rust
use std::sync::Arc;
use kingfisher_rules::{get_builtin_rules, RulesDatabase, Rule};

let rules = get_builtin_rules(None)?;

// Convert RuleSyntax to Rule objects
let rule_vec: Vec<Rule> = rules.iter_rules()
    .map(|syntax| Rule::new(syntax.clone()))
    .collect();

// Compile into a database (uses Vectorscan for fast matching)
let db = Arc::new(RulesDatabase::from_rules(rule_vec)?);

// Access compiled rules
println!("Compiled {} rules", db.num_rules());

// Look up rules by ID
if let Some(rule) = db.get_rule_by_text_id("kingfisher.aws.1") {
    println!("Found rule: {}", rule.name());
}
```

### Confidence Levels

Rules have confidence levels indicating detection accuracy:

```rust
use kingfisher_rules::Confidence;

// Available levels (in order)
// Confidence::Low    - May have false positives
// Confidence::Medium - Balanced (default)
// Confidence::High   - High accuracy

let conf = Confidence::High;
if conf.is_at_least(&Confidence::Medium) {
    println!("Confidence is medium or higher");
}
```

### Liquid Filters for Validation

The crate includes Liquid template filters for HTTP validation:

```rust
use kingfisher_rules::register_liquid_filters;
use liquid::ParserBuilder;

let parser = register_liquid_filters(ParserBuilder::with_stdlib())
    .build()?;

let template = parser.parse("{{ secret | sha256 }}")?;
```

Available filters:
- **Encoding**: `b64enc`, `b64dec`, `b64url_enc`, `url_encode`, `json_escape`
- **Hashing**: `sha256`, `crc32`, `crc32_dec`, `crc32_hex`
- **HMAC**: `hmac_sha256`, `hmac_sha384`, `hmac_sha1`
- **Encoding**: `base62`, `base36`
- **Strings**: `prefix`, `suffix`, `replace`, `lstrip_chars`, `random_string`
- **Time**: `unix_timestamp`, `iso_timestamp`, `iso_timestamp_no_frac`
- **Other**: `uuid`, `jwt_header`

---

## kingfisher-scanner

High-level scanning API that combines core types and rules.

### Scanner Configuration

```rust
use std::sync::Arc;
use kingfisher_rules::{get_builtin_rules, RulesDatabase, Rule};
use kingfisher_scanner::{Scanner, ScannerConfig};

let rules = get_builtin_rules(None)?;
let rule_vec: Vec<Rule> = rules.iter_rules()
    .map(|syntax| Rule::new(syntax.clone()))
    .collect();
let rules_db = Arc::new(RulesDatabase::from_rules(rule_vec)?);

// Default configuration
let scanner = Scanner::new(Arc::clone(&rules_db));

// Custom configuration
let config = ScannerConfig {
    enable_base64_decoding: true,   // Decode and scan base64 content
    enable_dedup: true,             // Skip duplicate blobs
    min_entropy_override: Some(3.0), // Override minimum entropy
    redact_secrets: false,          // Don't redact in findings
    max_base64_depth: 2,            // Max nested base64 decoding
};
let scanner = Scanner::with_config(Arc::clone(&rules_db), config);
```

### Scanning Methods

```rust
// Scan raw bytes
let findings = scanner.scan_bytes(b"AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE");

// Scan a file
let findings = scanner.scan_file("config.yml")?;

// Scan a Blob
use kingfisher_core::Blob;
let blob = Blob::from_file("secrets.env")?;
let findings = scanner.scan_blob(&blob)?;
```

### Working with Findings

```rust
use kingfisher_scanner::Finding;

for finding in findings {
    println!("Rule: {} ({})", finding.rule_name, finding.rule_id);
    println!("Secret: {}", finding.secret);
    println!("Location: line {} col {} - line {} col {}",
        finding.location.start_line,
        finding.location.start_column,
        finding.location.end_line,
        finding.location.end_column);
    println!("Entropy: {:.2}", finding.entropy);
    println!("Confidence: {:?}", finding.confidence);
    println!("Fingerprint: {}", finding.fingerprint);
    
    // Named captures from the regex
    for capture in &finding.captures {
        println!("  {}: {}", capture.name, capture.value);
    }
}
```

### Parallel Scanning

The scanner is thread-safe and uses a thread-local scanner pool:

```rust
use std::sync::Arc;
use rayon::prelude::*;

let scanner = Arc::new(Scanner::new(rules_db));

let files = vec!["file1.txt", "file2.txt", "file3.txt"];

let all_findings: Vec<_> = files.par_iter()
    .flat_map(|file| {
        scanner.scan_file(file).unwrap_or_default()
    })
    .collect();
```

---

## Complete Example

Here's a complete example that scans a directory for secrets:

```rust
use std::sync::Arc;
use std::path::Path;
use walkdir::WalkDir;
use kingfisher_core::Blob;
use kingfisher_rules::{get_builtin_rules, RulesDatabase, Rule, Confidence};
use kingfisher_scanner::{Scanner, ScannerConfig};

fn main() -> anyhow::Result<()> {
    // Load high-confidence rules only
    let rules = get_builtin_rules(Some(Confidence::High))?;
    println!("Loaded {} high-confidence rules", rules.num_rules());
    
    // Compile rules
    let rule_vec: Vec<Rule> = rules.iter_rules()
        .map(|syntax| Rule::new(syntax.clone()))
        .collect();
    let rules_db = Arc::new(RulesDatabase::from_rules(rule_vec)?);
    
    // Configure scanner
    let config = ScannerConfig {
        enable_base64_decoding: true,
        enable_dedup: true,
        redact_secrets: true,  // Redact secrets in output
        ..Default::default()
    };
    let scanner = Scanner::with_config(rules_db, config);
    
    // Scan directory
    let dir = Path::new("./src");
    let mut total_findings = 0;
    
    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        
        match scanner.scan_file(path) {
            Ok(findings) if !findings.is_empty() => {
                println!("\n{}", path.display());
                for finding in &findings {
                    println!("  [{}] {} at line {}",
                        finding.rule_id,
                        finding.rule_name,
                        finding.location.start_line);
                }
                total_findings += findings.len();
            }
            Err(e) => eprintln!("Error scanning {}: {}", path.display(), e),
            _ => {}
        }
    }
    
    println!("\nTotal findings: {}", total_findings);
    Ok(())
}
```

---

## Credential Validation (Optional)

The `kingfisher-scanner` crate includes optional credential validation support. This allows you to check if detected secrets are still active/valid.

### Enabling Validation

Add the validation feature to your `Cargo.toml`:

```toml
[dependencies]
kingfisher-scanner = { git = "https://github.com/mongodb/kingfisher", features = ["validation"] }
```

### Available Features

| Feature | Description |
|---------|-------------|
| `validation` | Core validation support with HTTP validation |
| `validation-http` | HTTP-based validation for API tokens |
| `validation-aws` | AWS credential validation via STS |
| `validation-all` | Enable all validation features |

### HTTP Validation Example

```rust
use kingfisher_scanner::validation::{
    build_request_builder, validate_response, CachedResponse,
    from_string, GLOBAL_USER_AGENT,
};
use kingfisher_rules::ResponseMatcher;
use reqwest::Client;
use std::collections::BTreeMap;
use std::time::Duration;

async fn validate_api_token(token: &str) -> bool {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    
    let parser = liquid::ParserBuilder::with_stdlib().build().unwrap();
    let mut globals = liquid::Object::new();
    globals.insert("TOKEN".into(), liquid_core::Value::scalar(token.to_string()));
    
    let url = reqwest::Url::parse("https://api.example.com/validate").unwrap();
    let mut headers = BTreeMap::new();
    headers.insert("Authorization".to_string(), "Bearer {{ TOKEN }}".to_string());
    
    let request = build_request_builder(
        &client,
        "GET",
        &url,
        &headers,
        &None,
        Duration::from_secs(10),
        &parser,
        &globals,
    ).unwrap();
    
    match request.send().await {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            
            // Define matchers for valid response
            let matchers = vec![
                ResponseMatcher::StatusMatch {
                    r#type: "status-match".to_string(),
                    status: vec![200],
                    match_all_status: false,
                    negative: false,
                },
            ];
            
            validate_response(&matchers, &body, &status, resp.headers(), false)
        }
        Err(_) => false,
    }
}
```

### AWS Credential Validation

Enable the `validation-aws` feature to validate AWS credentials:

```toml
[dependencies]
kingfisher-scanner = { git = "https://github.com/mongodb/kingfisher", features = ["validation-aws"] }
```

```rust
use kingfisher_scanner::validation::{
    validate_aws_credentials, validate_aws_credentials_input,
    aws_key_to_account_number, set_aws_skip_account_ids,
};

async fn check_aws_key(access_key_id: &str, secret_key: &str) {
    // Validate format first
    if let Err(e) = validate_aws_credentials_input(access_key_id, secret_key) {
        println!("Invalid format: {}", e);
        return;
    }
    
    // Extract account number from the key
    if let Ok(account) = aws_key_to_account_number(access_key_id) {
        println!("AWS Account: {}", account);
    }
    
    // Validate credentials via STS
    match validate_aws_credentials(access_key_id, secret_key).await {
        Ok((true, arn)) => println!("Valid! ARN: {}", arn),
        Ok((false, msg)) => println!("Invalid: {}", msg),
        Err(e) => println!("Error: {}", e),
    }
}

// Skip validation for known canary/honeypot accounts
fn setup_skip_list() {
    set_aws_skip_account_ids(vec![
        "111122223333",  // Test account
        "444455556666",  // Canary account
    ]);
}
```

### Validation Response Types

```rust
use kingfisher_scanner::validation::{
    CachedResponse, ValidationResponseBody,
    from_string, as_str, VALIDATION_CACHE_SECONDS,
};
use http::StatusCode;
use std::time::Duration;

// Create a validation response body
let body = from_string("Credential is valid");

// Create a cached response
let cached = CachedResponse::new(
    body,
    StatusCode::OK,
    true,  // is_valid
);

// Check if cache is still fresh
let cache_duration = Duration::from_secs(VALIDATION_CACHE_SECONDS);
if cached.is_still_valid(cache_duration) {
    println!("Using cached result: valid={}", cached.is_valid);
}
```

---

## API Stability

These crates are currently internal to Kingfisher. The API may change between versions. For stable integration, pin to a specific git commit or tag.

## See Also

- [Main README](../README.md) - CLI usage and installation
- [Rule Format](FINGERPRINT.md) - Rule definition details
- [Changelog](../CHANGELOG.md) - Version history
