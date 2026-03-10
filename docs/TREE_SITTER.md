# Tree-sitter in Kingfisher Scanning

[← Back to README](../README.md)

This document explains how Tree-sitter is used during scanning, and when it is intentionally skipped.

## What Tree-sitter Is Used For

Kingfisher always starts with a fast regex pass (Vectorscan/Hyperscan). Tree-sitter is a secondary verification layer used only for context-dependent findings.

The goal is to confirm that a regex hit appears in a plausible code assignment/config context (for example `api_key = "..."`) before keeping the finding.

## Where It Runs in the Scan Pipeline

1. `BlobProcessor::run` decides whether to compute a language hint.
   - It skips language hinting in `fast_mode`.
   - It also skips when blob size is outside the Tree-sitter window.
2. `Matcher::scan_blob` performs the primary regex scan and other filtering.
3. `maybe_apply_tree_sitter_verification` runs near the end of `scan_blob`.
4. Only candidate matches are checked against Tree-sitter extracted text.
5. Matches that fail verification can be dropped, depending on rule profile and fallback policy.

## Size and Mode Gates

Tree-sitter is attempted only when all of these are true:

- Blob length is between `1 KiB` and `64 KiB` (`should_attempt_tree_sitter`).
- `fast_mode` is disabled.
- A language hint is available.
- The language maps to a supported Tree-sitter grammar + query set.

If any of these conditions fails, Tree-sitter verification is considered unavailable for that blob.

## Candidate Selection (Not Every Match)

Tree-sitter verification is only applied to matches that are:

- Classified as `ContextDependent` by rule profiling.
- Not base64-derived findings (`is_base64 == false`).

Classification and fallback policy come from rule profiles in `kingfisher-rules`:

- `SelfIdentifying`: usually keep raw regex result.
- `ContextDependent`: may require Tree-sitter confirmation.

## How Verification Works

When Tree-sitter is available:

1. `load_tree_sitter_results` builds a `Checker` with:
   - `Language` enum value
   - language-specific queries from `src/parser/queries.rs`
2. `Checker::check`:
   - Reuses a thread-local parser cache (`PARSER_CACHE`)
   - Parses source into a syntax tree
   - Runs language query patterns capturing `@key` and `@val`
   - Produces normalized strings like `key = value`
   - Attempts base64 decode of value and keeps decoded ASCII form when valid
3. For each candidate finding, Kingfisher re-runs that rule's anchored regex on each extracted Tree-sitter text fragment.
4. Verification succeeds only when the rule's secret capture equals the original matched secret bytes.

If no extracted fragment verifies the secret, that candidate finding is removed.

## Fallback Behavior When Tree-sitter Is Unavailable

If Tree-sitter cannot run (size/mode/language/parse errors), behavior is rule-driven:

- `KeepRawWhenUnavailable`: keep the regex finding.
- `SuppressWhenUnavailable`: drop the finding.

`SuppressWhenUnavailable` is used for stricter generic-context patterns where false positives are likely without syntax-aware confirmation.

## Supported Languages in This Path

Language mapping for verification currently includes:

- `bash`/`shell`
- `c`
- `c#`/`csharp`
- `c++`/`cpp`
- `css`
- `go`
- `html`
- `java`
- `javascript`/`js`
- `php`
- `python`/`py`/`starlark`
- `ruby`
- `rust`
- `toml`
- `typescript`/`ts`
- `yaml`

The Tree-sitter query definitions for these languages live in `src/parser/queries.rs`.

## Operational Summary

Tree-sitter in Kingfisher is a conditional verifier, not the primary detector:

- Regex finds candidates quickly.
- Rule profiling decides which candidates need context verification.
- Tree-sitter confirms contextual plausibility from parsed syntax.
- Fallback policy determines what to do when verification cannot run.

This keeps scanning fast while reducing noisy matches for context-dependent secret patterns.
