---
title: "Hosted Report Viewer"
description: "Open the Kingfisher report viewer from the docs site and upload Kingfisher, Gitleaks, or TruffleHog JSON reports directly in your browser."
---

Kingfisher ships a browser-based report viewer that can also be hosted from the documentation site as a static page.

[Open the hosted report viewer](../access-map-viewer/index.html)

## What it supports

- Upload local `Kingfisher` JSON and JSONL reports
- Upload local `Gitleaks` JSON reports
- Upload local `TruffleHog` JSON and JSONL reports
- Merge multiple uploaded reports in one browser session
- Explore findings, detector breakdowns, and access-map data when present

## Hosted vs local viewer

The hosted docs-site version is upload-based. It does not use the CLI-only local `/report` endpoint that powers `kingfisher view`.

Use the hosted version when you want a shareable static viewer on GitHub Pages.

Use the local CLI viewer when you want Kingfisher to open a report directly from disk:

```bash
kingfisher view report.json
```

## Sample data

You can test the hosted page with a bundled sample report:

- [Open sample report JSON](../access-map-viewer/sample-report.json)

## Notes

- Everything runs client-side in the browser.
- Imported third-party reports are normalized for viewing and deduplicated by fingerprint logic in the viewer.
- Native-only CLI conveniences such as auto-loading `/report` remain part of the local `kingfisher view` workflow.
