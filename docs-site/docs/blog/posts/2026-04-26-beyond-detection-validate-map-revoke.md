---
date: 2026-04-26
title: "Beyond Detection: Live Validation, Blast Radius, and One-Command Revocation"
description: >
  Detection alone is noise. Kingfisher answers the three questions that
  actually matter when a secret leaks — is it live, what does it reach,
  and can we revoke it now — across AWS, GCP, GitHub, GitLab, Slack,
  and dozens of other providers.
categories:
  - Features
tags:
  - validation
  - blast-radius
  - revocation
  - secret-scanning
---

# Beyond Detection: Live Validation, Blast Radius, and One-Command Revocation

A regex match on `AKIA[0-9A-Z]{16}` is the easy part. Every secret scanner
finds those. The hard part — and the part that decides whether your Tuesday
afternoon turns into an incident — is what happens **after** the match.

Kingfisher answers the three questions that actually matter:

1. **Is this credential alive right now?**
2. **What can it reach?**
3. **Can we kill it from here?**

<!-- more -->

## 1. Live validation, not just pattern matching

Out of Kingfisher's 820 standalone detectors, **484 include live validation
logic**. Every one of those calls the provider's own API and reports the
credential as `Active`, `Inactive`, or `NotAttempted` — so a 4,000-finding
scan collapses to the dozen findings that are actually live.

Validation runs automatically when you scan:

```bash
kingfisher scan github --organization my-org
```

Or you can run it standalone when you've already pulled a suspicious value
out of a paste, a log, or a customer ticket:

```bash
# Hit GitHub's user API to confirm the token works
kingfisher validate --rule github "$GITHUB_TOKEN"

# AWS needs both halves of the keypair
kingfisher validate --rule aws \
  --arg "$AWS_ACCESS_KEY_ID" \
  "$AWS_SECRET_ACCESS_KEY"

# A GCP service account JSON, straight from the file
kingfisher validate --rule gcp "$(cat service-account.json)"

# A Postgres connection URI — does it actually authenticate?
kingfisher validate --rule postgres "$POSTGRES_URI"
```

Validation logic lives in the rule YAML, not in compiled Rust, which is
why coverage is high and growing — every new detector ships with a
validation block whenever the provider exposes a safe check call.

## 2. Blast radius mapping — what does this token actually reach?

A leaked AWS key bound to a single read-only S3 bucket and a leaked AWS key
bound to organization-wide `AdministratorAccess` are not the same incident.
The first is a Friday afternoon ticket. The second is a war room.

Add `--access-map` to a scan and Kingfisher authenticates each live
credential, enumerates what it can do, and writes the result alongside
the finding:

```bash
kingfisher scan github --organization my-org \
  --access-map \
  --format json \
  --output findings.json
```

Each cloud finding gets an `access_map` block with the identity, the
permissions, and the concrete resources reachable. Today this is supported
for **AWS, GCP, Azure Storage, Azure DevOps, GitHub, GitLab, Slack, and
Microsoft Teams.**

You can also run it standalone — useful when triaging a single credential
you've fished out of a paste or a customer report:

```bash
# What does this AWS keypair actually own?
kingfisher access-map aws ./aws.json --json-out aws.access-map.json

# Same for a GitHub token
kingfisher access-map github ./github.token --json-out github.access-map.json

# Or a GCP service account
kingfisher access-map gcp ./service-account.json --json-out gcp.access-map.json
```

The HTML report viewer (`--format html`) renders the access map as a
clickable tree — identity at the root, then services, then individual
resources and permissions. It's the fastest way to get a non-engineer
stakeholder to grasp severity in five seconds rather than five minutes.

## 3. Revocation — kill the token from where you found it

Validation tells you a credential is live. Blast radius tells you why it's
urgent. Revocation tells you it's done.

For every rule whose provider exposes a safe revocation API, Kingfisher
ships the revocation call as part of the rule definition. One command,
no console:

```bash
# Revoke a GitHub PAT
kingfisher revoke --rule github "$GITHUB_TOKEN"

# Revoke a GitLab token
kingfisher revoke --rule gitlab "$GITLAB_TOKEN"

# Revoke a Slack bot token
kingfisher revoke --rule slack "$SLACK_TOKEN"

# Deactivate an AWS access key
kingfisher revoke --rule aws \
  --arg "$AWS_ACCESS_KEY_ID" \
  "$AWS_SECRET_ACCESS_KEY"

# Disable a GCP service account key
kingfisher revoke --rule gcp "$(cat service-account.json)"
```

The same Liquid templating that powers the validation request handles
revocation — including multi-step flows for providers that need a separate
key-id lookup before disabling. (See
[`docs/RULES.md`](https://github.com/mongodb/kingfisher/blob/main/docs/RULES.md#multi-step-revocation)
for the schema.)

This matters in two scenarios:

- **Mass revocation after a leak.** A laptop or a CI runner gets popped and
  you have a list of fingerprints. `kingfisher revoke` walks the list, no
  human pivoting between five provider consoles.
- **Automated response.** Wire `kingfisher revoke` into the same job that
  scanned and validated, gated by an allow-list of rule IDs you've decided
  are safe to auto-revoke (typically: short-lived CI tokens, dev-environment
  secrets). The credential is dead before the on-call gets paged.

## The combined workflow

In practice these three primitives chain into a single pipeline:

```bash
# 1. Scan + validate + map blast radius in one call
kingfisher scan github --organization my-org \
  --access-map \
  --format json \
  --output findings.json

# 2. Pull just the live, high-blast-radius findings
jq '[.[] | select(.validation.status == "Active")
        | select(.access_map.permissions
        | any(. == "*" or contains("Admin")))]' \
   findings.json > urgent.json

# 3. Triage in the HTML viewer (or revoke programmatically)
kingfisher view findings.json
```

Three commands, full incident workflow — find, prioritize, kill.

## Why this is the right shape

Most scanners stop at step one because going further is expensive: every
provider has its own auth flow, its own permission model, its own
revocation API. Kingfisher gets to a high-coverage version of all three by
keeping the logic in YAML rule files (the same place the detection regex
lives), reusing typed validators for the common families (AWS, GCP, JWT,
Postgres, MongoDB, MySQL, JDBC, Azure Storage, Coinbase), and letting rule
authors drop down to a `Raw` validator only for genuinely odd providers.

The upshot for users: when a new detector lands, you almost always get
validation, blast radius, and revocation along with it — not three
separate roadmaps.

## Next up

- **Catching secrets in pull requests with GitHub Actions** — pre-merge
  scanning so leaked credentials never reach `main`.
- **Top leaked credential types we see in the wild** — what validation
  telemetry says about the credential leak landscape.
- **Docker image scanning** — pulling and scanning every layer for
  embedded secrets.

Got a provider you'd love to see validation or revocation support for?
Open an issue at
[mongodb/kingfisher](https://github.com/mongodb/kingfisher/issues).
