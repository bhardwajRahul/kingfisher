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

Most organizations have hundreds of repositories — some abandoned, some active,
plenty inherited from acquisitions. A leaked AWS key in a five-year-old archived
repo is just as dangerous as one in `main` today. Kingfisher can enumerate every
repo in a GitHub organization, scan the full git history, and then **validate
which credentials are still live** so you know what to rotate first.

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

That's it — Kingfisher enumerates every repo, clones each one, scans the full
commit history, runs all 942 detection rules, and validates findings against
provider APIs.

## Tuning for real-world orgs

Real orgs have huge monorepos, archived junk, and forks you don't care about.
Three flags do most of the work:

```bash
kingfisher scan github --organization my-org \
  --repo-clone-limit 500 \
  --github-exclude 'my-org/*-archive' \
  --github-exclude 'my-org/legacy-monorepo' \
  --git-clone-dir /var/tmp/kf-clones \
  --format sarif \
  --output kf-findings.sarif
```

- **`--repo-clone-limit`** caps the number of clones per scan. Useful for
  staged rollouts ("first 500 repos by stars") or to stay under disk budget.
- **`--github-exclude`** accepts exact `OWNER/REPO` strings or gitignore-style
  globs (`my-org/*-archive`). Repeat the flag for each pattern. Matching is
  case-insensitive.
- **`--git-clone-dir`** moves clones off your home volume. Combine with
  `--keep-clones` if you want to re-scan later without re-cloning.

## Pulling in issues, wikis, and gists

Secrets don't only live in code. Issues and pull request descriptions are a
common leak source — someone pastes a stack trace with a JWT, or an
"oncall handoff" issue with a temporary token that never got rotated. Add
`--repo-artifacts` to fetch these:

```bash
kingfisher scan github --organization my-org --repo-artifacts
```

This pulls each repo's issues (including PRs), wiki, and any **public** gists
owned by the repo owner, and scans them all. It does cost API calls, so plan
accordingly if you're near a rate limit.

## Following the people, not just the org

This is the trick that catches what every other scanner misses. Developers
leak secrets in *personal* repositories — side projects, dotfiles, throwaway
forks. If a contributor to your org has a public personal repo with an active
token that grants access to org infrastructure, that's a real incident.

Pass a single repo URL with `--include-contributors` and Kingfisher will
enumerate the contributors, then clone and scan **every public repo they own**:

```bash
kingfisher scan https://github.com/my-org/critical-service \
  --include-contributors \
  --repo-clone-limit 200
```

This is a noisy operation — start with one or two critical repos rather than
the whole org. GitHub will rate-limit aggressive enumeration, so a token
(`KF_GITHUB_TOKEN`) is required in practice.

## Reading the output

The default `pretty` output is human-friendly for terminals. For automation,
pick the format that matches your downstream tool:

```bash
# JSON for custom tooling
kingfisher scan github --organization my-org --format json --output findings.json

# SARIF for GitHub code scanning, GitLab, or any SARIF-aware UI
kingfisher scan github --organization my-org --format sarif --output findings.sarif

# TOON for piping to an LLM or agent
kingfisher scan github --organization my-org --format toon
```

The interactive HTML report is often the fastest way to triage a large scan —
filter by rule, by validation status, or by repository, and click through to
the exact commit and line:

```bash
kingfisher scan github --organization my-org --format html --output kf-report.html
```

## Triage by validation status

The single most important column in the output is **validation**. A live
credential is a fire — a never-was-valid one is noise. Filter to live findings
first:

```bash
jq '.[] | select(.validation.status == "Active")' findings.json
```

Then walk those credentials in order of blast radius. For AWS, GCP, GitHub,
GitLab, and Slack tokens, Kingfisher already maps what each one can access —
look at the `access_map` field in the JSON output, or the **Blast Radius**
panel in the HTML report.

## Revoke from the CLI

For supported providers, you don't need to log into a console — Kingfisher can
revoke directly:

```bash
kingfisher revoke --rule kingfisher.aws.access_key.1 AKIAEXAMPLE...
```

Each rule that supports revocation declares the API call in its YAML. Today
this works for AWS, GitHub, GitLab, Slack, and a growing list of SaaS
providers — see [`docs/RULES.md`](https://github.com/mongodb/kingfisher/blob/main/docs/RULES.md)
for the current list and how to add revocation to a custom rule.

## Wiring it into a recurring job

A first scan is the one-shot baseline. The real value is recurring scans
catching new leaks within hours, not months. The simplest pattern is a nightly
GitHub Action or scheduled CI job that runs the org scan, diffs against
yesterday's findings, and pages on net-new live credentials. We'll cover that
end-to-end in the next post.

## What's next

- **Catching secrets in pull requests with GitHub Actions** — pre-merge
  scanning so leaks never reach `main`.
- **The most common credential types we see leaked in the wild** — what
  Kingfisher's validation telemetry says about the credential leak landscape.
- **Docker image scanning** — pulling images directly and scanning every
  layer for embedded secrets.

If there's a workflow you'd like us to cover, open an issue at
[mongodb/kingfisher](https://github.com/mongodb/kingfisher/issues).
