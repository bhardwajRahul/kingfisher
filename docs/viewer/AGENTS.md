# AGENTS.md

Guidance for editing the local report viewer under `docs/viewer/`.

## Scope

- Applies to `docs/viewer/` and all files under it.
- This file overrides broader documentation guidance for this subtree.

## Current Architecture

- The shipped viewer is the single-file app in `index.html`.
- Treat `index.html` as the authoritative implementation for the UI, parsing, and rendering logic.
- `sample-report.json` is the canonical example payload for native Kingfisher viewer data.
- `app.js`, `viewer.js`, and `viewer.css` may exist as older or non-authoritative assets. Do not assume changes there affect the shipped viewer unless you also update how the app is loaded.

## Editing Expectations

- Prefer targeted edits over broad refactors. This file is large, so keep changes localized and easy to review.
- Keep new parsing or normalization logic grouped into small helper functions instead of scattering format-specific conditionals throughout the file.
- Preserve the distinction between native Kingfisher reports and imported third-party reports in both data handling and UI messaging.
- Do not imply feature parity for imported reports when native-only features such as `access_map`, validate commands, revoke commands, or blast-radius linking are unavailable.
- Prefer ASCII when editing text unless the file already relies on another character.

## Data Model Guidance

- Native viewer inputs should continue to normalize around the Kingfisher envelope shape: `findings`, optional `access_map`, and optional metadata.
- When supporting imported formats, map them into the viewer envelope instead of building parallel rendering paths.
- Keep fingerprint behavior stable and explicit. If imported reports need synthetic fingerprints, use a deterministic approach and document the fidelity limits in the UI or docs.
- Preserve graceful handling of both JSON and JSONL inputs.

## UI Guidance

- Keep imported-report limitations visible in the viewer when access-map data or command workflows are unavailable.
- Prefer small explanatory notices and empty states over hiding entire sections without explanation.
- Maintain client-side-only behavior. Do not add network calls from the viewer except for the existing local `GET /report` loading path used by `kingfisher view`.

## Validation

- After substantive edits to `index.html`, run a syntax check on the embedded JavaScript by extracting the `<script>` block and using `node --check`.
- For doc or sample changes, make sure examples still match the current viewer behavior and accepted report formats.
