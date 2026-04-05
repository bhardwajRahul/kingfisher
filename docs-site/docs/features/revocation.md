---
title: "Secret Revocation"
description: "Revoke compromised credentials directly from the CLI. Supports 20+ providers including GitHub, GitLab, Slack, AWS, and GCP."
---

# Revocation Support Matrix

Kingfisher supports direct secret revocation through rule-level `revocation:` blocks.

Current coverage in built-in rules:
- `23` provider families
- `39` revocation-enabled rules

Use `kingfisher revoke --rule <rule-id> <secret>` to invoke these flows. See [USAGE.md](../usage/basic-scanning.md#direct-secret-revocation-with-kingfisher-revoke) for command details.

## Supported Providers

| Provider | Revocation Rule Count | Rule IDs |
|---|---:|---|
| `aws` | 1 | `kingfisher.aws.2` |
| `browserstack` | 1 | `kingfisher.browserstack.1` |
| `buildkite` | 1 | `kingfisher.buildkite.1` |
| `cloudflare` | 1 | `kingfisher.cloudflare.1` |
| `confluent` | 2 | `kingfisher.confluent.2`, `kingfisher.confluent.3` |
| `deviantart` | 1 | `kingfisher.deviantart.1` |
| `doppler` | 6 | `kingfisher.doppler.1`, `kingfisher.doppler.2`, `kingfisher.doppler.3`, `kingfisher.doppler.4`, `kingfisher.doppler.5`, `kingfisher.doppler.6` |
| `gcp` | 1 | `kingfisher.gcp.1` |
| `github` | 3 | `kingfisher.github.1`, `kingfisher.github.2`, `kingfisher.github.5` |
| `gitlab` | 2 | `kingfisher.gitlab.1`, `kingfisher.gitlab.4` |
| `harness` | 1 | `kingfisher.harness.pat.1` |
| `mapbox` | 1 | `kingfisher.mapbox.2` |
| `mongodb` | 1 | `kingfisher.mongodb.1` |
| `npm` | 2 | `kingfisher.npm.1`, `kingfisher.npm.2` |
| `particle.io` | 2 | `kingfisher.particleio.1`, `kingfisher.particleio.2` |
| `sendgrid` | 1 | `kingfisher.sendgrid.1` |
| `slack` | 2 | `kingfisher.slack.1`, `kingfisher.slack.2` |
| `sumologic` | 1 | `kingfisher.sumologic.2` |
| `tailscale` | 1 | `kingfisher.tailscale.1` |
| `twilio` | 1 | `kingfisher.twilio.2` |
| `twitch` | 1 | `kingfisher.twitch.1` |
| `unkey` | 1 | `kingfisher.unkey.2` |
| `vercel` | 5 | `kingfisher.vercel.1`, `kingfisher.vercel.2`, `kingfisher.vercel.3`, `kingfisher.vercel.4`, `kingfisher.vercel.5` |

## Notes

- Coverage above is derived from built-in YAML rules under `crates/kingfisher-rules/data/rules/` that currently define a `revocation:` block.
- A provider may have additional detection/validation rules that do not yet support revocation.
