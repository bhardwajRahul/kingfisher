---
title: "Report Viewer & Triager (Kingfisher, Gitleaks, TruffleHog)"
description: "Triage Kingfisher, Gitleaks, and TruffleHog JSON findings in one browser-based viewer. Use the bundled local viewer via `kingfisher view` or the hosted static viewer on GitHub Pages."
---

# Report Viewer & Triager

Kingfisher ships a browser-based **report viewer and triager** for three formats:

- **Kingfisher** JSON / JSONL — with full `access_map` blast-radius data when available
- **Gitleaks** JSON
- **TruffleHog** JSON / JSONL — verified findings are surfaced as active credentials

The same UI is available two ways:

- **Locally**, bundled into every Kingfisher binary: `kingfisher view ./report.json`
- **Hosted**, as a static upload-based copy on GitHub Pages: **[Open the hosted report viewer](../report-viewer/index.html)** ([https://mongodb.github.io/kingfisher/report-viewer/](https://mongodb.github.io/kingfisher/report-viewer/))

Both render reports entirely client-side. Nothing about the uploaded report leaves the browser.

## Why a visual viewer/triager matters

Gitleaks and TruffleHog are great at emitting candidate matches; Kingfisher goes further by live-validating and mapping blast radius. But all three produce JSON, and raw JSON is not how a human decides which finding to rotate first. The viewer turns that output into a triage workflow:

- **Skim at a glance** — findings are grouped by detector, rule, file, and repository with counts and validation state, instead of one JSON object per line in a terminal.
- **Cross-tool triage in one place** — import a Gitleaks scan, a TruffleHog scan, and a Kingfisher scan of the same codebase and look at them side-by-side with deduplication, rather than reconciling three different schemas by hand.
- **Rotate real secrets first** — validated Kingfisher findings and TruffleHog-verified findings are surfaced as active credentials; unverified/static matches are marked as not attempted.
- **Dedup automatically** — the same secret appearing across multiple reports, directories, or scan runs collapses to one entry by fingerprint / secret identity.
- **See blast radius** — when a Kingfisher report was generated with `--access-map`, the viewer renders the identity, permissions, and resources the credential can reach, so you can tell apart a dev token from a production admin key.
- **Share and archive** — export filtered subsets for tickets, rotation runbooks, or audit reviewers.

Tools like Gitleaks and TruffleHog surface candidates. Kingfisher's viewer helps you decide which ones matter — and it works with their output, not just its own.

## Using the local viewer via the `kingfisher` CLI

The local viewer is part of the `kingfisher` binary — no separate install, no network calls.

```bash
# Open a Kingfisher scan report
kingfisher view kingfisher.json

# Import a Gitleaks JSON report
kingfisher view gitleaks-report.json

# Import a TruffleHog JSON or JSONL report
kingfisher view trufflehog-report.jsonl

# Combine multiple reports — deduplicated by fingerprint / secret identity
kingfisher view kingfisher.json gitleaks.json trufflehog.jsonl

# Or load every JSON/JSONL report in a directory (non-recursive)
kingfisher view ./reports/
```

`kingfisher view` starts a tiny local web server on `127.0.0.1:7890` and opens the browser automatically. Use `--port` to pick another port and `--address 0.0.0.0` to expose the viewer from a container or remote host.

You can also chain scanning and viewing in a single step:

```bash
# Scan and open the report in the browser when it finishes
kingfisher scan /path/to/code --view-report

# Same, but bind to all interfaces and a specific port (useful in Docker)
kingfisher scan /path/to/code \
  --view-report \
  --view-report-address 0.0.0.0 \
  --view-report-port 7891
```

## Using the hosted viewer

The docs site publishes a static, upload-based copy of the viewer at:

**[https://mongodb.github.io/kingfisher/report-viewer/](https://mongodb.github.io/kingfisher/report-viewer/)**

Drag a Kingfisher, Gitleaks, or TruffleHog JSON report into the page (or use the file picker) to triage it in your browser. You can also merge multiple reports in one session by uploading them one after another — duplicates collapse automatically. It's useful when you want to:

- Hand a teammate a link rather than a binary
- Triage a report on a machine that doesn't have Kingfisher installed
- Show a finding with its blast-radius context without shipping the raw JSON around

## Sample data

You can test the hosted page with a bundled sample report:

- [Open sample report JSON](../report-viewer/sample-report.json)

## Local vs hosted — quick comparison

| Capability                                              | `kingfisher view` (local) | Hosted viewer |
|---------------------------------------------------------|:-------------------------:|:-------------:|
| Open Kingfisher JSON/JSONL reports                      | Yes                       | Yes           |
| Import Gitleaks JSON reports                            | Yes                       | Yes           |
| Import TruffleHog JSON/JSONL reports                    | Yes                       | Yes           |
| Merge multiple reports with deduplication               | Yes                       | Yes           |
| Render `access_map` blast-radius data                   | Yes                       | Yes           |
| Runs fully client-side (no report leaves your machine)  | Yes                       | Yes           |
| Auto-load a report from disk via CLI argument           | Yes                       | —             |
| Shareable URL you can send to a teammate                | —                         | Yes           |
| Requires Kingfisher installed                           | Yes                       | No            |

## Caveats for imported Gitleaks / TruffleHog reports

- Imported reports are display-oriented. They do not carry Kingfisher-native `access_map` data or drive `kingfisher validate` / `kingfisher revoke`.
- Fingerprints on imported findings use the importer's normalization, not Kingfisher's native fingerprinting.
- TruffleHog findings marked as verified are shown as active credentials; all other imported findings are treated as not attempted rather than inactive.
- For full validation and blast-radius mapping, re-scan the source with Kingfisher and (when authorized) add `--access-map`.
