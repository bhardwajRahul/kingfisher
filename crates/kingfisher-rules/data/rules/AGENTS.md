# AGENTS.md

Rule-authoring instructions for this directory.

## Scope
- Applies to `crates/kingfisher-rules/data/rules/` and all files under it.
- This file overrides broader AGENTS guidance for rule-writing tasks in this subtree.

## Goal
- Add or update YAML detection rules with high precision, low false positives, and safe remediation support.

## Rule File Conventions
- Keep provider rules in provider-named files (for example `github.yml`, `openai.yml`).
- Prefer lowercase filenames with `.yml`.
- Keep rule IDs stable and unique. Prefer `kingfisher.<provider>.<number>` unless a descriptive suffix is already established for that provider.
- Reuse nearby provider patterns/styles instead of inventing new structure.

## Required Rule Shape
Each rule entry should define:
- `name`
- `id`
- `pattern`
- `min_entropy` (default to 3.0)
- `confidence` (default to medium)
- `examples` (at least one realistic positive example)

Strongly recommended fields:
- `pattern_requirements` (for extra filtering)
- `references`

## Pattern Quality Rules
- Prefer specific anchors/prefixes and provider context over broad generic regex.
- Use `pattern_requirements` to enforce quality constraints (`min_digits`, `min_uppercase`, `min_lowercase`, `min_special_chars`, `ignore_if_contains`, `checksum`).
- Use checksum validation in `pattern_requirements.checksum` when token formats support it.
- Use `visible: false` for helper/non-secret captures used only by dependent rules.
- Use `depends_on_rule` for multi-part credential validation (for example ID + secret).

## Validation Policy (Important)
- Default: define validation logic in YAML under `validation:`.
- Do not move validation logic into Rust unless YAML cannot reliably express it.
- Code-backed validation types (for example AWS, GCP, Coinbase, MongoDB) are notable exceptions and should remain rare.
- For new rules, first attempt `Http`/`Grpc` YAML validation before considering exception paths.

## Revocation Policy
- If a rule has validation and the provider API safely supports revocation, add `revocation:` in the same YAML rule.
- Prefer explicit success criteria in `response_matcher`.
- Use `HttpMultiStep` revocation when API workflows require pre-fetch/extraction steps.
- If revocation is intentionally not supported, document why with an inline YAML comment.

## Authoring Workflow
1. Choose the target provider file (or add a new provider file if no suitable file exists).
2. Copy a structurally similar rule from this directory.
3. Implement/adjust `pattern`, `examples`, and filtering (`pattern_requirements`, `min_entropy`).
4. Add YAML `validation` (default path).
5. Add YAML `revocation` when supported.
6. Add `references` for token format/API behavior.
7. Verify locally (below).

## Local Verification Checklist
- Syntax/load checks:
  - `cargo test -p kingfisher-rules`
- Broader regression check:
  - `cargo test --workspace --all-targets`
- Behavioral check against sample content:
  - `kingfisher scan ./testdata --rule <rule-family-or-id> --rule-stats`
- Validation check (when validation is present):
  - `kingfisher validate --rule <rule-id> <token-or-secret>`

## Documentation
Read these before complex edits:
- `docs/RULES.md` (schema, pattern requirements, checksum, Liquid, validation/revocation)
- `docs/MULTI_STEP_REVOCATION.md`
- `docs/TOKEN_REVOCATION_SUPPORT.md`

## Change Discipline
- Keep changes scoped to the specific provider/rule request.
- Do not refactor unrelated rules in the same PR unless explicitly asked.
- Preserve existing YAML style and indentation conventions in this directory.
