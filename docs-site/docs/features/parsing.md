---
title: "Source Code Parsing"
description: "Language-aware secret detection using tree-sitter parsing for 13+ languages including Python, JavaScript, Go, Rust, and more."
---

# Kingfisher Source Code Parsing

Kingfisher leverages tree-sitter as an extra layer of analysis when scanning source files written in supported programming languages. In practice, after its initial regex-based scan (powered by Vectorscan/Hyperscan), Kingfisher can run a targeted verification pass for context-dependent rules.

If so, it creates a Checker (see below) that uses tree‐sitter to parse the file and run language‐specific queries. This additional pass refines the detection by capturing more structured patterns—such as secret-like tokens—that might be obscured or spread over code constructs.

## How It’s Called

In the scanning phase (in the Matcher's implementation), Kingfisher does the following:

- **Primary Regex Pass:** Kingfisher always scans the full blob with Vectorscan/Hyperscan first.
- **Candidate Selection:** Findings from rules classified as context-dependent become tree-sitter verification candidates.
- **Language Detection:** If a language string is provided (for example from metadata or extension), the code calls a helper (such as `get_language_and_queries`) to retrieve the corresponding tree-sitter language and queries.
- **Checker Creation:** With those values, a `Checker` is instantiated with the target language and query map.
- **Parsing and Querying:** The Checker retrieves a thread-local parser (to avoid recreating it on every call), sets language, parses source, and runs queries to extract structured snippets (for example `key = value` pairs).
- **Verification Decision:** Candidate findings are kept only if parser-extracted context verifies the matched secret. If tree-sitter is unavailable, fallback behavior is profile-driven (for strict generic keyword+token rules, findings are suppressed).
  *(See the implementation details in the parser module – for example, the `modify_regex` function in the Checker, and the conditional tree‐sitter call in Matcher::scan_blob)*

## Supported Languages

The design supports many common source code languages. The Language enum (defined in the parser module) includes variants for:

- **Scripting:** Bash, Python, Ruby, PHP  
- **Compiled languages:** C, C++, C#, Rust, Java  
- **Web-related languages:** CSS, HTML, JavaScript, TypeScript, YAML, Toml  
- **Others:** Go, and even a generic “Regex” mode  

Each variant maps to its corresponding tree‐sitter language through the `get_ts_language()` method.

## When Tree‐sitter Is Not Called

Tree‐sitter won’t be invoked in certain cases:

- **No Language Identified:** If the file isn’t recognized as belonging to one of the supported languages or no language hint is provided, the Checker isn’t even constructed.
- **Non-source Files:** Binary files or files that aren’t expected to contain code (or aren’t extracted from archives) bypass tree‐sitter parsing.
- **Fallback on Errors:** If tree‐sitter parsing fails (e.g. due to malformed code or other errors), Kingfisher will fall back on its regex/Vectorscan matches without the additional tree‐sitter insights.

## Summary

In essence, Kingfisher’s use of tree‐sitter is conditional and complementary. It is called only when the scanned file is a source code file written in a supported language, and its role is to enrich the scanning results by leveraging the syntax tree and language-specific queries. When files are non-source, binary, or if no language is provided, tree‐sitter is not invoked, and Kingfisher relies solely on its regex-based detection.

This layered approach helps improve the accuracy of secret detection while maintaining high performance.
