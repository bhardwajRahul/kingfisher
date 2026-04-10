# Parser-Based Context Verification

[← Back to README](../README.md)

Kingfisher starts with a fast regex pass powered by Vectorscan/Hyperscan. For rules classified as `ContextDependent`, it then runs a lightweight parser-based verification pass that extracts likely assignment-style snippets such as `api_key = secret`.

> **Why not a full AST parser?** Earlier implementations used statically linked
> grammar crates for this step. That added roughly 20 MB to the binary and
> required a full AST parse just to extract `key = value` pairs. The current
> approach — handwritten regex-based lexers with comment-aware stripping —
> produces the same (or better) extraction quality at a fraction of the binary
> and runtime cost.

## Where It Runs

1. `BlobProcessor::run` decides whether to compute a language hint.
2. `Matcher::scan_blob` performs the primary regex scan and other filtering.
3. `maybe_apply_context_verification` streams parser candidates near the end of `scan_blob`.
4. Only context-dependent, non-Base64 matches are checked.
5. Candidates that cannot be verified are removed.

## Gates

Context verification runs only when all of these are true:

- Blob length is between `0 KiB` and `2 MiB` (`should_attempt_context_verification`).
- Turbo mode is disabled.
- A supported language hint is available.

If any gate fails, context-dependent matches are suppressed rather than falling back to raw regex hits.

## Backends

Kingfisher uses lightweight language-specific extractors instead of a full AST layer:

- Handwritten lexers for Bash, C, C#, C++, Go, Java, JavaScript, PHP, Python, Ruby, Rust, TOML, TypeScript, and YAML
- `tl` for HTML attributes, element text, and embedded `<script>` / `<style>` blocks
- `cssparser` for CSS declarations and function-style values

Each lexer runs a comment-aware stripping pass (tracking string boundaries to avoid false comment detection) followed by a small set of regex patterns that extract assignment-style pairs.

## Verification Model

- Rule profiling decides which matches are `ContextDependent`.
- The parser streams candidate text snippets like `secret_key = abcd1234`.
- Kingfisher re-runs the rule's anchored regex against each candidate snippet.
- Verification succeeds only when the regex secret capture exactly matches the original hit.

This keeps the fast regex engine on the hot path while still filtering noisy generic keyword+token matches with language-aware context.
