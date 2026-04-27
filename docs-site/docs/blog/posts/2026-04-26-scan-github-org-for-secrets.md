---
date: 2026-04-26
title: "Scanning an Entire GitHub Organization for Leaked Secrets"
description: >
  Step-by-step guide to scanning every repository in a GitHub organization
  for leaked credentials with Kingfisher — including history, issues, wikis,
  and gists — and validating which secrets are still live.
categories:
  - Tutorials
tags:
  - github
  - secret-scanning
  - validation
  - tutorial
---

# Scanning an Entire GitHub Organization for Leaked Secrets

Most organizations have more GitHub surface area than they think: active
services, abandoned repositories, internal tooling, forks, experiments, and
projects inherited through acquisitions. A credential leaked in a five-year-old
archived repo can still be live today.

Kingfisher can enumerate every repository in a GitHub organization, scan the
full git history, and then **validate which credentials are still live** so
you can focus on what needs rotation first.

<!-- more -->

## What you need

- Kingfisher installed (`brew install mongodb/brew/kingfisher`, or grab a
  release from [GitHub](https://github.com/mongodb/kingfisher/releases)).
- A GitHub personal access token exported as `KF_GITHUB_TOKEN`. A classic
  token with `repo` and `read:org` scopes is enough for private repos; for
  public-only scans, even an unscoped token raises your rate limit and
  is strongly recommended.
- About 5 GB of free disk for clones (varies by org size — use
  `--git-clone-dir /path/to/big/disk` if your home volume is small).

## The one-liner

```bash
export KF_GITHUB_TOKEN=ghp_yourTokenHere
kingfisher scan github --organization my-org
```

That single command enumerates the org, clones each repository, scans working
tree content plus git history, and validates supported findings against
provider APIs.

## Tuning for real-world orgs

Real organizations have huge monorepos, archived junk, mirrored forks, and
repositories you already know are out of scope. Three flags handle most of
the tuning:

```bash
kingfisher scan github --organization my-org \
  --repo-clone-limit 500 \
  --github-exclude 'my-org/*-archive' \
  --github-exclude 'my-org/legacy-monorepo' \
  --git-clone-dir /var/tmp/kf-clones \
  --format sarif \
  --output kf-findings.sarif
```

- **`--repo-clone-limit`** caps the number of clones per scan. It is useful
  for staged rollouts or staying under a disk budget.
- **`--github-exclude`** accepts exact `OWNER/REPO` strings or gitignore-style
  globs (`my-org/*-archive`). Repeat the flag for each pattern. Matching is
  case-insensitive.
- **`--git-clone-dir`** moves clones off your home volume. Combine with
  `--keep-clones` if you want to re-scan later without re-cloning.

## Pulling in issues, wikis, and gists

Secrets don't only live in code. Issues and pull request descriptions are a
common leak source: someone pastes a stack trace with a JWT, or an
"on-call handoff" issue with a temporary token that never gets rotated. Add
`--repo-artifacts` to fetch these:

```bash
kingfisher scan github --organization my-org --repo-artifacts
```

This pulls each repo's issues, pull requests, wiki, and any **public** gists
owned by the repo owner, then scans that material as well. It does consume API
calls, so budget for that if the org is large or your token is already near a
rate limit.

## Following the people, not just the org

Developers also leak secrets in *personal* repositories: side projects,
dotfiles, and throwaway forks. If a contributor to your org has a public repo
containing a still-live credential that reaches company infrastructure, that is
still your incident.

Pass a single repo URL with `--include-contributors` and Kingfisher will
enumerate the contributors, then clone and scan **every public repo they own**:

```bash
kingfisher scan https://github.com/my-org/critical-service \
  --include-contributors \
  --repo-clone-limit 200
```

This is a noisy operation. Start with one or two critical repositories rather
than the entire organization. GitHub will also rate-limit aggressive
enumeration, so `KF_GITHUB_TOKEN` is effectively required.

## Reading the output

The default `pretty` output is fine for interactive terminal use. For
automation, pick a format that matches your downstream consumer:

```bash
# JSON for custom tooling
kingfisher scan github --organization my-org --format json --output findings.json

# SARIF for GitHub code scanning, GitLab, or any SARIF-aware UI
kingfisher scan github --organization my-org --format sarif --output findings.sarif

# TOON for piping to an LLM or agent
kingfisher scan github --organization my-org --format toon
```

The interactive HTML report is often the fastest way to triage a large scan.
You can filter by rule, validation status, or repository, then click through
to the exact commit and line:

```bash
kingfisher scan github --organization my-org --format html --output kf-report.html
```

## Triage by validation status

The single most important field in the output is **validation**. A live
credential should be triaged immediately; a value that never authenticated is
usually just cleanup work. Filter to live findings first:

```bash
jq '.findings[] | select(.validation.status == "Active")' findings.json
```

Then prioritize by blast radius. For AWS, GCP, GitHub, GitLab, and Slack
tokens, Kingfisher can already map what each credential can access. Look at
the `access_map` field in JSON output, or the **Blast Radius** panel in the
HTML report.

## Revoke from the CLI

For supported providers, you do not need to pivot into the provider console.
Kingfisher can revoke directly:

```bash
kingfisher revoke --rule kingfisher.aws.access_key.1 AKIAEXAMPLE...
```

Each rule that supports revocation declares the API call in its YAML. See
[`docs/RULES.md`](https://github.com/mongodb/kingfisher/blob/main/docs/RULES.md)
for the schema and the current approach.

## Wiring it into a recurring job

The first scan gives you a baseline. The real value comes from running the
same workflow continuously so new leaks are caught within hours instead of
months. A simple starting point is a nightly GitHub Action or scheduled CI
job that runs the org scan, diffs against yesterday's findings, and alerts on
net-new live credentials.

## What's next

- **Catching secrets in pull requests with GitHub Actions** — pre-merge
  scanning so leaks never reach `main`.
- **The most common credential types we see leaked in the wild** — what
  Kingfisher's validation telemetry says about the credential leak landscape.
- **Docker image scanning** — pulling images directly and scanning every
  layer for embedded secrets.

If there is a workflow you want us to cover, open an issue at
[mongodb/kingfisher](https://github.com/mongodb/kingfisher/issues).
