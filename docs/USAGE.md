# Usage Guide

This guide covers all scan targets and usage patterns for Kingfisher.

## Table of Contents

- [Basic Examples](#basic-examples)
- [Scanning Platform-Specific Targets](#scanning-platform-specific-targets)
  - [AWS S3](#aws-s3)
  - [Google Cloud Storage](#google-cloud-storage)
  - [Docker Images](#docker-images)
  - [GitHub](#github)
  - [GitLab](#gitlab)
  - [Azure Repos](#azure-repos)
  - [Gitea](#gitea)
  - [Bitbucket](#bitbucket)
  - [Hugging Face](#hugging-face)
  - [Jira](#jira)
  - [Confluence](#confluence)
  - [Slack](#slack)
- [TLS Certificate Validation](#tls-certificate-validation)
- [Understanding the Scan Summary](#understanding-the-scan-summary)
- [Environment Variables](#environment-variables)
- [Exit Codes](#exit-codes)

---

## Basic Examples

> **Note:** `kingfisher scan` detects whether the input is a Git repository or a plain directory, no extra flags required.

### Scan with secret validation

```bash
kingfisher scan /path/to/code
## NOTE: This path can refer to:
# 1. a local git repo
# 2. a directory with many git repos
# 3. or just a folder with files and subdirectories

## To explicitly prevent scanning git commit history add:
#   `--git-history=none`
```

### Scan a directory containing multiple Git repositories

```bash
kingfisher scan /projects/mono‑repo‑dir
```

### Scan a Git repository without validation

```bash
kingfisher scan ~/src/myrepo --no-validate
```

### Display only secrets confirmed active by third‑party APIs

```bash
kingfisher scan /path/to/repo --only-valid
```

### Output JSON and capture to a file

```bash
kingfisher scan . --format json | tee kingfisher.json
```

### Output SARIF directly to disk

```bash
kingfisher scan /path/to/repo --format sarif --output findings.sarif
```

### Generate an auditor-friendly HTML report

```bash
kingfisher scan /path/to/repo --format html --output kingfisher-audit.html
```

The HTML audit report is standalone and includes scan metadata designed for evidence workflows, including scan timestamp, sanitized CLI arguments, version, and finding summary counts.

### Access map outputs and viewer

**Stop Guessing, Start Mapping: Understand Your True Blast Radius**

Finding a leaked credential is only the first step. The critical question isn't just "Is this a secret?"—it's "What can an attacker do with it?"

Kingfisher's `--access-map` feature transforms secret detection from a simple alert into a comprehensive threat assessment. Instead of leaving you with a cryptic API key, Kingfisher actively authenticates against your cloud provider (AWS, GCP, Azure Storage, Azure DevOps, GitHub, GitLab, or Slack) to map the full extent of the credential's power. 

* Instant Identity Resolution: Immediately identify who the key belongs to—whether it's a specific IAM user, an assumed role, or a service account.
* Visualize the Blast Radius: See exactly which resources (S3 buckets, EC2 instances, projects, storage containers) are exposed and at risk.
 

Add `--access-map` to enrich JSON, JSONL, BSON, pretty, and SARIF reports with an `access_map` containing the resources and the permissions that the key can access - for each resource (grouped when identical).
- If you validated cloud credentials without `--access-map`, Kingfisher will remind you on stderr to rerun with the flag so the access map appears in the output.
- Run `kingfisher view ./kingfisher.json` to explore a report locally in a local web UI (opens your browser automatically when a report is provided).
- Or use `kingfisher scan --view-report ...` to generate a JSON report, start the viewer at `http://127.0.0.1:7890`, and open it in your browser.

> **Use the access map functionality only when you are authorized to inspect the target account, as Kingfisher will issue additional network requests to determine what access the secret grants**

### View access-map reports locally

```bash
kingfisher view kingfisher.json
```

The `view` subcommand starts a local-only server (default port `7890`) that bundles the HTML, CSS, and JavaScript for the access-map viewer directly into the Kingfisher binary. Provide a JSON or JSONL report to load it automatically and Kingfisher will open your browser, or open the page and upload a report in the browser. If port 7890 is already in use, Kingfisher will exit and tell you to re-run with `--port <PORT>`.

### Pipe any text directly into Kingfisher by passing `-`

```bash
cat /path/to/file.py | kingfisher scan -
```

### Direct secret validation with `kingfisher validate`

When you already know a secret's type and have the raw value, use `kingfisher validate` to check if it's still active—without needing the surrounding context that detection rules require.

This is useful for:
- Re-validating a known secret from a previous scan
- Checking if a credential is still active before rotation
- Validating secrets from external sources (password managers, ticketing systems, etc.)

> **Note:** The `kingfisher.` prefix is optional for built-in rules. You can use `--rule aws` instead of `--rule kingfisher.aws`.

To reduce API pressure during validation, you can limit request rate:

- `--validation-rps <RPS>` applies a global rate limit to network validators.
- `--validation-rps-rule <RULE_SELECTOR=RPS>` applies a rule-scoped override and can be repeated.

Rule selectors use the same prefix behavior as `--rule`: `github=2` targets `kingfisher.github.*`.

```bash
# Global limit for all validation requests
kingfisher scan ./repo --validation-rps 5

# Per-rule overrides (prefix match, kingfisher. prefix optional)
kingfisher scan ./repo \
  --validation-rps 10 \
  --validation-rps-rule github=2 \
  --validation-rps-rule pypi=0.5

# Direct validation can use the same limiter options
kingfisher validate --rule github "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  --validation-rps-rule github=1
```

```bash
# Validate an OpsGenie API key (using rule prefix matching)
kingfisher validate --rule opsgenie "12345678-9abc-def0-1234-56789abcdef0"

# Validate from stdin
echo "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" | kingfisher validate --rule github -

# JSON output for scripting
kingfisher validate --rule slack "xoxb-..." --format json

# AWS credentials - use --arg to auto-assign additional values
kingfisher validate --rule aws --arg AKIAIOSFODNN7EXAMPLE \
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Or use --var if you know the variable name (explicit rule ID still works)
kingfisher validate --rule kingfisher.aws.2 --var AKID=AKIAIOSFODNN7EXAMPLE \
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GCP service account (pass JSON as secret)
kingfisher validate --rule gcp "$(cat service-account.json)"

# MongoDB connection string
kingfisher validate --rule mongodb.3 \
  "mongodb+srv://user:password@cluster.mongodb.net/db"

# PostgreSQL connection
kingfisher validate --rule postgres \
  "postgres://admin:password@db.example.com:5432/mydb"

# JWT token
kingfisher validate --rule jwt \
  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Supported validators:** HTTP, Grpc, AWS, GCP, MongoDB, MySQL, Postgres, JDBC, JWT, Azure Storage, and Coinbase.

**Exit codes:** Returns `0` if any matching rule validates the secret as valid, `1` if all are invalid or an error occurred.

**Passing additional values (`--arg` and `--var`):**

Some validators need more than just the secret. For example, AWS needs both an access key ID and the secret key (see the rule for `dependent_rule` section):

- `--arg VALUE` — Auto-assigns values to template variables (in alphabetical order). Use when you don't know the exact variable name.
- `--var NAME=VALUE` — Explicitly sets a variable. Use when you know the exact name, or to override `--arg`.

```bash
# --arg auto-assigns to AKID (the only non-TOKEN variable for AWS)
kingfisher validate --rule aws --arg AKIAEXAMPLE "secret_key"

# --var for explicit assignment
kingfisher validate --rule aws --var AKID=AKIAEXAMPLE "secret_key"
```

**Rule prefix matching:** Use partial rule IDs like `opsgenie` instead of the full `kingfisher.opsgenie.1`. If the prefix matches multiple rules, **all matching rules with compatible variables are tried**:

```bash
$ kingfisher validate --rule aws --arg AKIAEXAMPLE "secret_key"
Rule:     AWS Secret Access Key (kingfisher.aws.2)
Result:   ✓ VALID
Response: arn:aws:iam::123456789012:user/example
```

### Direct secret revocation with `kingfisher revoke`

When you need to invalidate a known token immediately, use `kingfisher revoke` to call the rule's `revocation` configuration without scanning files. Revocation requests use the same Liquid templating and response matchers as `validation`.

This is useful for:
- Responding to a leaked credential quickly
- Revoking tokens discovered during incident response
- Automating cleanup after rotation

```bash
# Revoke a Slack token
kingfisher revoke --rule slack "xoxb-..."

# Revoke a GitHub PAT
kingfisher revoke --rule github "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Revoke a GitLab personal access token (self revoke)
kingfisher revoke --rule gitlab "glpat-xxxxxxxxxxxxxxxxxxxx"

# Revoke an Atlassian API token (requires account_id, tokenId, admin access token)
kingfisher revoke --rule atlassian --arg "<account_id>" --arg "<token_id>" "<admin_access_token>"

# Revoke AWS credentials (sets access key to Inactive)
kingfisher revoke --rule aws --arg "AKIAIOSFODNN7EXAMPLE" "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Revoke a GCP service account key (JSON key file)
kingfisher revoke --rule gcp '{"type":"service_account","project_id":"example","private_key_id":"abcd1234","private_key":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n","client_email":"example@project.iam.gserviceaccount.com","token_uri":"https://oauth2.googleapis.com/token"}'

kingfisher revoke --rule gcp "$(cat service-account.json)"

# JSON output for scripting
kingfisher revoke --rule slack "xoxb-..." --format json
```

**Exit codes:** Returns `0` if any matching rule reports a successful revocation, `1` if all are failures or an error occurred.

**Passing additional values (`--arg` and `--var`):** Works the same as `kingfisher validate` when a revocation request requires extra variables.

### Limit maximum file size scanned (`--max-file-size`)

By default, Kingfisher skips files larger than **256 MB**. You can raise or lower this cap per run with `--max-file-size`, which takes a value in **megabytes**.

```bash
# Scan files up to 500 mb in size
kingfisher scan /some/file --max-file-size 500
```

### Scan using a rule _family_ with one flag

_(prefix matching: `--rule kingfisher.aws` loads `kingfisher.aws.*`)_

```bash
# Only apply AWS-related rules (kingfisher.aws.1 + kingfisher.aws.2)
kingfisher scan /path/to/repo --rule kingfisher.aws
```

### Display rule performance statistics

```bash
kingfisher scan /path/to/repo --rule-stats
```

### Scan while ignoring likely test files

`--exclude` skips any file or directory whose path matches this glob pattern (repeatable, uses gitignore-style syntax, case sensitive)

```bash
# Scan source but skip likely unit / integration tests
kingfisher scan ./my-project \
  --exclude='[Tt]est' \
  --exclude='spec' \
  --exclude='[Ff]ixture' \
  --exclude='example' \
  --exclude='sample'
```

### Exclude specific paths

```bash
# Skip all Python files and any directory named tests
kingfisher scan ./my-project \
  --exclude '*.py' \
  --exclude '[Tt]ests'
```

### Scan changes in CI pipelines

Limit scanning to the delta between your default branch and a pull request branch by combining `--since-commit` with `--branch` (defaults to `HEAD`). This only scans files that differ between the two references, which keeps CI runs fast while still blocking new secrets.

Use `--branch-root-commit` alongside `--branch` when you need to include a specific commit (and everything after it) in a diff-focused scan without re-examining earlier history. Provide the branch tip (or other comparison ref) via `--branch`, and pass the commit or merge-base you want to include with `--branch-root-commit`. If you omit `--branch-root-commit`, you can still enable `--branch-root` to fall back to treating the `--branch` ref itself as the inclusive root for backwards compatibility. This is especially useful in long-lived branches where you want to resume scanning from a previous review point or from the commit where a hotfix forked.

> **How is this different from `--since-commit`?**   
> `--since-commit` computes a diff between the branch tip and another ref, so it only inspects files that changed between those two points in history. `--branch-root-commit` rewinds to the parent of the commit you provide and then scans everything introduced from that commit forward, even if the files are unchanged relative to another baseline. Reach for `--since-commit` to keep CI scans fast by checking only the latest delta, and use `--branch-root-commit` when you want to re-audit the full contents of a branch starting at a specific commit.

```bash
kingfisher scan . \
  --since-commit origin/main \
  --branch "$CI_BRANCH"
```

Another example:

```bash
cd /tmp
git clone https://github.com/micksmix/SecretsTest.git

cd /tmp/SecretsTest
git checkout feature-1
#
# scan diff between main and feature-1 branch
kingfisher scan /tmp/SecretsTest --branch feature-1 \
  --since-commit=$(git -C /tmp/SecretsTest merge-base main feature-1)
#
# scan only a specific commit
kingfisher scan /tmp/SecretsTest \
  --branch baba6ccb453963d3f6136d1ace843e48d7007c3f
#
# scan feature-1 starting at a specific commit (inclusive)
kingfisher scan /tmp/SecretsTest --branch feature-1 \
  --branch-root-commit baba6ccb453963d3f6136d1ace843e48d7007c3f
#
# scan feature-1 starting from the commit where the branch diverged from main
kingfisher scan /tmp/SecretsTest --branch feature-1 \
  --branch-root-commit $(git -C /tmp/SecretsTest merge-base main feature-1)
#
# scan from a hotfix commit that should be re-checked before merging
HOTFIX_COMMIT=$(git -C /tmp/SecretsTest rev-parse hotfix~1)
kingfisher scan /tmp/SecretsTest --branch hotfix \
  --branch-root-commit "$HOTFIX_COMMIT"
```

When the branch under test is already checked out, `--branch HEAD` or omitting `--branch` entirely is sufficient. Kingfisher exits with `200` when any findings are discovered and `205` when validated secrets are present, allowing CI jobs to fail automatically if new credentials slip in.

> **Tip:** You can point Kingfisher at a local working tree and scan another branch or commit without changing checkouts. The CLI now resolves repositories from their worktree roots, so commands like the following work without needing to pass the `.git` directory explicitly:

```bash
kingfisher scan /path/to/local/repo --branch <ref>
kingfisher scan C:\\src\\repo --branch <commit-hash>
```

The same diff-focused workflow works when cloning repositories on the fly with `--git-url`. Kingfisher automatically tries remote-tracking names like `origin/main` and `origin/feature-1`, so you can target the branches involved in a pull request without performing a local checkout first.

```bash
kingfisher scan \
  --git-url https://github.com/org/repo.git \
  --since-commit main \
  --branch development
```

When `--since-commit` is omitted, specifying `--branch` scans the requested ref directly. This makes it easy to analyze a feature branch without checking it out locally.

```bash
# Scan a branch from an existing checkout
kingfisher scan ~/tmp/repo --branch feature-123

# Or scan a branch when cloning on the fly
kingfisher scan \
  --git-url https://github.com/org/repo.git \
  --branch origin/feature-123
```

In CI systems that expose the base and head commits explicitly, you can pass those SHAs directly while still using `--git-url`:

```bash
kingfisher scan \
  --git-url git@github.com:org/repo.git \
  --since-commit "$BASE_COMMIT" \
  --branch "$PR_HEAD_COMMIT"
```

If you want to know which files are being skipped, enable verbose debugging (-v) when scanning, which will report any files being skipped by the baseline file (or via --exclude):

```bash
# Skip all Python files and any directory named tests, and report to stderr any skipped files
kingfisher scan ./my-project \
  --exclude '*.py' \
  --exclude tests \
  -v
```

---

## Scanning Platform-Specific Targets

> **Deprecated**
> Legacy scan flags such as `--github-user`, `--gitlab-group`,
> `--bitbucket-workspace`, `--azure-organization`, `--huggingface-user`,
> `--slack-query`, `--jira-url`, `--confluence-url`, `--s3-bucket`,
> `--gcs-bucket`, and `--docker-image` still work for now, but they trigger a
> warning and will be removed in a future release. Migrate to the
> `kingfisher scan <provider>` subcommands below to future-proof your automations.

---

## AWS S3

You can scan S3 objects directly:

```bash
kingfisher scan s3 bucket-name [--prefix path/]
```

Credential resolution happens in this order:

1. `KF_AWS_KEY` and `KF_AWS_SECRET` environment variables (optionally `KF_AWS_SESSION_TOKEN` for temporary credentials)
2. `--profile` pointing to a profile in `~/.aws/config` (works with AWS SSO)
3. anonymous access for public buckets

If `--role-arn` is supplied, the credentials from steps 1–2 are used to assume that role.

**Examples:**

```bash
# using explicit keys
export KF_AWS_KEY=AKIA...
export KF_AWS_SECRET=g5nYW...
kingfisher scan s3 some-example-bucket

# Above can also be run as:
KF_AWS_KEY=AKIA... KF_AWS_SECRET=g5nYW... kingfisher scan s3 some-example-bucket

# using a local profile (e.g., SSO) that exists in your AWS profile (~/.aws/config)
kingfisher scan s3 some-example-bucket --profile default

# anonymous scan of a bucket, while providing an object prefix to only scan subset of the s3 bucket
kingfisher scan s3 awsglue-datasets \
  --prefix examples/us-legislators/all

# assuming a role when scanning
kingfisher scan s3 some-example-bucket \
  --role-arn arn:aws:iam::123456789012:role/MyRole

# anonymous scan of a public bucket
kingfisher scan s3 some-example-bucket
```

**Docker example:**

```bash
docker run --rm \
  -e KF_AWS_KEY=AKIA... \
  -e KF_AWS_SECRET=g5nYW... \
  ghcr.io/mongodb/kingfisher:latest \
    scan s3 bucket-name
```

---

## Google Cloud Storage

Use the `gcs` scan subcommand to stream objects directly from Google Cloud Storage. Authentication uses Application Default Credentials, so you can provide a service-account JSON file via the `GOOGLE_APPLICATION_CREDENTIALS` environment variable or by passing `--service-account`. Public buckets work without credentials.

```bash
kingfisher scan gcs bucket-name

# scan a sub-tree inside the bucket
kingfisher scan gcs bucket-name --prefix path/to/data/

# supply a service-account key explicitly
kingfisher scan gcs bucket-name --service-account /path/to/key.json
```

**Functional example:**

```bash
kingfisher scan gcs cloud-samples-data --prefix "storage/"
```

---

## Docker Images

Kingfisher will first try to use any locally available image, then fall back to pulling via OCI.  

Authentication happens *in this order*:

1. **`KF_DOCKER_TOKEN`** env var  
   - If it contains `user:pass`, it's used as Basic auth
   - Otherwise it's sent as a Bearer token
2. **Docker CLI credentials**  
   - Checks `credHelpers` (per-registry) and `credsStore` in `~/.docker/config.json`.  
   - Falls back to the legacy `auths` → `auth` (base64) entries.  
3. **Anonymous** (no credentials)

```bash
# 1) Scan public or already-pulled image
kingfisher scan docker ghcr.io/owasp/wrongsecrets/wrongsecrets-master:latest-master

# 2) For private registries, explicitly set KF_DOCKER_TOKEN:
#    - Basic auth:     "user:pass"
#    - Bearer only:    "TOKEN"
export KF_DOCKER_TOKEN="AWS:$(aws ecr get-login-password --region us-east-1)"
kingfisher scan docker some-private-registry.dkr.ecr.us-east-1.amazonaws.com/base/amazonlinux2023:latest

# 3) Or rely on your Docker CLI login/keychain:
#    (e.g. aws ecr get-login-password … | docker login …)
kingfisher scan docker private.registry.example.com/my-image:tag
```

---

## GitHub

### Scan GitHub organization (requires `KF_GITHUB_TOKEN`)

```bash
kingfisher scan github --organization my-org
kingfisher scan github --organization my-org --repo-clone-limit 500
```

### Skip specific GitHub repositories during enumeration

Repeat `--github-exclude` for every repository you want to ignore when scanning users or organizations. You can provide exact repositories like `OWNER/REPO` or gitignore-style glob patterns such as `owner/*-archive` (matching is case-insensitive).

```bash
kingfisher scan github --organization my-org \
  --github-exclude my-org/huge-repo \
  --github-exclude my-org/*-archive
```

### Scan remote GitHub repository

`--git-url` clones the repository and scans its files and history. When the URL targets GitHub and you pass `--include-contributors`, Kingfisher enumerates repository contributors and attempts to clone **all public repos owned by those contributors**—a common offensive and blue-team pivot when developers leak secrets in personal or side projects. Use `--repo-clone-limit` to cap how many repositories are cloned during this enumeration.

**NOTE**: This may cause you to be temporarily rate-limited by GitHub. Providing a token (`KF_GITHUB_TOKEN`) will provide a higher rate limit.

To inspect related server-side data, supply `--repo-artifacts`. This flag pulls down the repository's issues (including pull requests), wiki, and any public gists owned by the repository owner and scans them for secrets. Fetching these extras counts against API rate limits and private artifacts require a `KF_GITHUB_TOKEN`.

Use `--git-clone-dir` to choose where cloned repositories land and `--keep-clones` to preserve them for follow-on analysis.

> **Why does `--git-url` sometimes report fewer findings than scanning a local checkout?**. 
> 
> Remote clones created via `--git-url` default to `--mirror`/bare mode so Kingfisher only reads the Git history. When you point Kingfisher at an existing working tree (for example `kingfisher scan ./repo`), it enumerates both the filesystem contents *and* the Git history. Any secrets that are present in the checked-out files therefore appear twice: once from the working tree path and once from the commit where the secret entered the history. To replicate the remote behavior locally, either scan a bare clone or disable history scanning with `--git-history none` when targeting a working tree.

```bash
# Scan the repository only
kingfisher scan --git-url https://github.com/org/repo.git

# Scan the repository plus contributor repos, but cap the crawl
kingfisher scan --git-url https://github.com/org/repo.git \
  --include-contributors \
  --repo-clone-limit 250

# Keep clones for later manual inspection
kingfisher scan --git-url https://github.com/org/repo.git \
  --git-clone-dir ./kingfisher-clones \
  --keep-clones

# Include issues, wiki, and owner gists
kingfisher scan --git-url https://github.com/org/repo.git --repo-artifacts

# Private repositories or artifacts
KF_GITHUB_TOKEN="ghp_…" kingfisher scan --git-url https://github.com/org/private_repo.git --repo-artifacts
```

---

## GitLab

### Scan GitLab group (requires `KF_GITLAB_TOKEN`)

```bash
kingfisher scan gitlab --group my-group
# include repositories from all nested subgroups
kingfisher scan gitlab --group my-group --include-subgroups
kingfisher scan gitlab --group my-group --repo-clone-limit 500
```

### Scan GitLab user

```bash
kingfisher scan gitlab --user johndoe
```

### Skip specific GitLab projects during enumeration

Repeat `--gitlab-exclude` for every project path you want to ignore when scanning users or groups. Specify project paths as `group/project` (case-insensitive) or use gitignore-style glob patterns like `group/**/archive-*` to drop families of projects across nested subgroups.

```bash
kingfisher scan gitlab --group my-group \
  --gitlab-exclude my-group/huge-project \
  --gitlab-exclude my-group/**/archive-*
```

### Scan remote GitLab repository by URL

`--git-url` by itself clones the project repository. When the URL targets GitLab and you pass `--include-contributors`, Kingfisher enumerates contributors and tries to clone **their other public projects** to catch secrets that escape the main repo. Apply `--repo-clone-limit` to cap the total repos cloned during this pivot.

**NOTE**: This may cause you to be temporarily rate-limited by GitLab. Providing a token (`KF_GITLAB_TOKEN`) will provide a higher rate limit.

To include server-side artifacts owned by the project, add `--repo-artifacts`. Kingfisher will retrieve the project's issues, wiki, and snippets and scan them for secrets. These extra requests may take longer and require a `KF_GITLAB_TOKEN` for private projects.

Use `--git-clone-dir` to choose where cloned projects land and `--keep-clones` to preserve them for later review.

```bash
# Scan the repository only
kingfisher scan --git-url https://gitlab.com/group/project.git

# Scan the repository plus contributor projects, but cap the crawl
kingfisher scan --git-url https://gitlab.com/group/project.git \
  --include-contributors \
  --repo-clone-limit 250

# Keep clones for later manual inspection
kingfisher scan --git-url https://gitlab.com/group/project.git \
  --git-clone-dir ./kingfisher-clones \
  --keep-clones

# Include issues, wiki, and snippets
kingfisher scan --git-url https://gitlab.com/group/project.git --repo-artifacts

# Private projects or artifacts
KF_GITLAB_TOKEN="glpat-…" kingfisher scan --git-url https://gitlab.com/group/private_project.git --repo-artifacts
```

### List GitLab repositories

```bash
kingfisher scan gitlab --group my-group --list-only
# include repositories from all nested subgroups
kingfisher scan gitlab --group my-group --include-subgroups --list-only
# skip specific projects when listing or scanning (supports glob patterns)
kingfisher scan gitlab --group my-group --gitlab-exclude my-group/**/legacy-* --list-only
```

---

## Azure Repos

### Scan Azure Repos organization or collection (requires `KF_AZURE_TOKEN` or `KF_AZURE_PAT`)

```bash
kingfisher scan azure --organization my-org

# Azure Repos Server example
KF_AZURE_PAT="pat" kingfisher scan azure --organization DefaultCollection --azure-base-url https://ado.internal.example/tfs/
```

### Scan specific Azure Repos projects

Projects are specified as `ORGANIZATION/PROJECT`. Repeat the flag for multiple projects.

```bash
kingfisher scan azure --project my-org/payments \
  --project my-org/core-platform
```

### Skip specific Azure repositories during enumeration

Repeat `--azure-exclude` to ignore repositories when scanning organizations or projects. Use identifiers like `ORGANIZATION/PROJECT/REPOSITORY`. Repositories that share the same name as their project can be excluded with `ORGANIZATION/PROJECT`, and gitignore-style patterns such as `my-org/*/archive-*` are also supported.

```bash
kingfisher scan azure --organization my-org \
  --azure-exclude my-org/payments/legacy-service \
  --azure-exclude my-org/**/archive-*
```

### List Azure repositories

```bash
kingfisher scan azure --organization my-org --list-only
# list repositories for specific projects
kingfisher scan azure --project my-org/app --project my-org/api --list-only
# skip specific repositories while listing (supports glob patterns)
kingfisher scan azure --organization my-org --azure-exclude my-org/**/experimental-* --list-only
```

---

## Gitea

### Scan Gitea organization (requires `KF_GITEA_TOKEN`)

```bash
kingfisher scan gitea --organization my-org
# self-hosted example
KF_GITEA_TOKEN="gtoken" kingfisher scan gitea --organization platform --gitea-api-url https://gitea.internal.example/api/v1/
```

### Scan Gitea user

```bash
kingfisher scan gitea --user johndoe
```

### Skip specific Gitea repositories during enumeration

Repeat `--gitea-exclude` for each repository you want to ignore when scanning users or organizations. Accepts `owner/repo` identifiers or gitignore-style glob patterns like `team/**/archive-*`.

```bash
kingfisher scan gitea --organization my-org \
  --gitea-exclude my-org/legacy-repo \
  --gitea-exclude my-org/**/archive-*
```

### Scan remote Gitea repository by URL

`--git-url` clones the repository and scans its history. Adding `--repo-artifacts` also clones the repository wiki if one exists. Private repositories and wikis require `KF_GITEA_TOKEN` (and `KF_GITEA_USERNAME` when cloning via HTTPS).

```bash
# Scan the repository only
kingfisher scan --git-url https://gitea.com/org/repo.git

# Include the repository wiki (if present)
KF_GITEA_TOKEN="gtoken" KF_GITEA_USERNAME="org" \
  kingfisher scan --git-url https://gitea.com/org/repo.git --repo-artifacts
```

### List Gitea repositories

```bash
kingfisher scan gitea --organization my-org --list-only
# enumerate every organization visible to the authenticated user
KF_GITEA_TOKEN="gtoken" kingfisher scan gitea --all-gitea-organizations --list-only
# self-hosted example
KF_GITEA_TOKEN="gtoken" kingfisher scan gitea --user johndoe --gitea-api-url https://gitea.internal.example/api/v1/ --list-only
```

---

## Bitbucket

### Scan Bitbucket workspace

```bash
kingfisher scan bitbucket --workspace my-team
# include Bitbucket Cloud repositories from every accessible workspace
KF_BITBUCKET_TOKEN="$BITBUCKET_TOKEN" \
  kingfisher scan bitbucket --all-workspaces
```

### Scan Bitbucket user

```bash
kingfisher scan bitbucket --user johndoe
```

### Skip specific Bitbucket repositories during enumeration

Use `--bitbucket-exclude` to ignore repositories while scanning users, workspaces, or projects. Patterns accept either `owner/repo` (case-insensitive) or gitignore-style globs such as `workspace/**/archive-*`.

```bash
kingfisher scan bitbucket --workspace my-team \
  --bitbucket-exclude my-team/legacy-repo \
  --bitbucket-exclude my-team/**/archive-*
```

### Scan remote Bitbucket repository by URL

`--git-url` clones the repository and scans its files and history. To inspect Bitbucket artifacts such as issues, add `--repo-artifacts`. Private artifacts require credentials (see [Authenticate to Bitbucket](#authenticate-to-bitbucket)).

```bash
# Scan the repository only
kingfisher scan --git-url https://bitbucket.org/hashashash/secretstest.git

# Include repository issues
KF_BITBUCKET_TOKEN="$BITBUCKET_TOKEN" \
  kingfisher scan --git-url https://bitbucket.org/workspace/project.git --repo-artifacts
```

### List Bitbucket repositories

```bash
kingfisher scan bitbucket --workspace my-team --list-only
# enumerate all accessible workspaces or projects
KF_BITBUCKET_TOKEN="$BITBUCKET_TOKEN" \
  kingfisher scan bitbucket --all-workspaces --list-only
# filter out repositories using glob patterns
kingfisher scan bitbucket --workspace my-team --bitbucket-exclude my-team/**/experimental-* --list-only
```

### Authenticate to Bitbucket

Kingfisher supports Bitbucket Cloud and Bitbucket Server credentials:

- **Workspace API token (Cloud)** – set `KF_BITBUCKET_TOKEN`. Kingfisher automatically uses the token for Bitbucket REST APIs and authenticates git operations as `x-token-auth`.
- **Bitbucket Server token** – set `KF_BITBUCKET_USERNAME` and either `KF_BITBUCKET_TOKEN` or `KF_BITBUCKET_PASSWORD`.
- **Legacy app password (Cloud)** – set `KF_BITBUCKET_USERNAME` and `KF_BITBUCKET_APP_PASSWORD`.
- **OAuth/PAT token** – set `KF_BITBUCKET_OAUTH_TOKEN`.

These credentials match the options described in the [ghorg setup guide](https://github.com/gabrie30/ghorg/blob/master/README.md#bitbucket-setup).

Bitbucket no longer supports App Tokens as of September 9, 2025: https://support.atlassian.com/bitbucket-cloud/docs/api-tokens/

> As of September 9, 2025, app passwords can no longer be created. Use API tokens with scopes instead. All existing app passwords will be disabled on June 9, 2026. Migrate any integrations before then to avoid disruptions.

### Self-hosted Bitbucket Server

Use `--bitbucket-api-url` to point Kingfisher at your server's REST endpoint, for example `https://bitbucket.example.com/rest/api/1.0/`. Provide credentials with `KF_BITBUCKET_USERNAME` plus either `KF_BITBUCKET_TOKEN` or `KF_BITBUCKET_PASSWORD`, and pass `--tls-mode=off` (or the legacy `--ignore-certs`) when connecting to HTTP or otherwise insecure instances.

---

## Hugging Face

Hugging Face hosts git repositories for models, datasets, and Spaces. Kingfisher can enumerate and scan all three resource types.

### Scan Hugging Face user

```bash
kingfisher scan huggingface --user <username>
```

### Scan Hugging Face organization

```bash
kingfisher scan huggingface --organization <orgname>
```

### Scan specific Hugging Face resources

Scan individual repositories by ID (owner/name) or by passing the full HTTPS URL:

```bash
kingfisher scan huggingface --model <owner/model>
kingfisher scan huggingface --dataset https://huggingface.co/datasets/<owner>/<dataset>
kingfisher scan huggingface --space <owner/space>
```

Use `--huggingface-exclude` to omit results returned by user or organization enumeration. Prefix values with `model:`, `dataset:`, or `space:` when you only want to skip a specific resource type.

### List Hugging Face repositories

```bash
kingfisher scan huggingface --user <username> --list-only
```

### Authenticate to Hugging Face

Private repositories require an access token provided through the `KF_HUGGINGFACE_TOKEN` environment variable. For git authentication the helper also honours `KF_HUGGINGFACE_USERNAME` (default `hf_user`).

---

## Jira

### Scan Jira issues matching a JQL query

```bash
KF_JIRA_TOKEN="token" kingfisher scan jira --url https://jira.company.com \
    --jql "project = TEST AND status = Open" \
    --max-results 500
```

### Scan the last 1,000 Jira issues

```bash
KF_JIRA_TOKEN="token" kingfisher scan jira --url https://jira.mongodb.org \
  --jql 'ORDER BY created DESC' \
  --max-results 1000
```

---

## Confluence

### Scan Confluence pages matching a CQL query

```bash
# Bearer token
KF_CONFLUENCE_TOKEN="token" kingfisher scan confluence --url https://confluence.company.com \
    --cql "label = secret" \
    --max-results 500

# Basic auth with username and token
KF_CONFLUENCE_USER="user@example.com" KF_CONFLUENCE_TOKEN="token" \
  kingfisher scan confluence --url https://confluence.company.com \
    --cql "text ~ 'password'" \
    --max-results 500
```

Use the base URL of your Confluence site for `--confluence-url`. Kingfisher automatically adds `/rest/api` to the end, so `https://example.com/wiki` and `https://example.com` both work depending on your server configuration.

Generate a personal access token and set it in the `KF_CONFLUENCE_TOKEN` environment variable. By default, Kingfisher sends the token as a bearer token in the `Authorization` header.

To use basic authentication instead, also set `KF_CONFLUENCE_USER` to your Confluence email address; Kingfisher will then send the username and `KF_CONFLUENCE_TOKEN` as a Basic auth header. If the server responds with a redirect to a login page, the credentials are invalid or lack the required permissions.

---

## Slack

### Scan Slack messages matching a search query

```bash
KF_SLACK_TOKEN="xoxp-1234..." kingfisher scan slack "from:username has:link" \
    --max-results 1000

KF_SLACK_TOKEN="xoxp-1234..." kingfisher scan slack "akia" \
    --max-results 1000
```

*The Slack token must be a user token with the `search:read` scope. Bot tokens (those beginning with `xoxb-`) cannot call the Slack search API.*

---

## TLS Certificate Validation

Kingfisher validates TLS certificates when connecting to endpoints during secret validation (database connections, API calls, JWKS fetching, etc.). The `--tls-mode` flag controls this behavior:

| Mode | Description |
| ---- | ----------- |
| `strict` | **Default.** Full WebPKI certificate validation: trusted CA chain, hostname match, certificate not expired. |
| `lax` | Accept self-signed or unknown CA certificates for rules that opt into it. Still enforces TLS 1.2+. Useful for database connections using self-signed certs or private CAs (e.g., Amazon RDS). |
| `off` | Disable all certificate validation. Use with extreme caution. |

### When to use `--tls-mode=lax`

The `lax` mode is designed for environments where:

- **Database connections** use self-signed certificates (common for PostgreSQL, MySQL, MongoDB)
- **Private CAs** are used (e.g., Amazon RDS uses an Amazon-issued CA that may not be in your system trust store)
- **Internal services** have certificates not signed by public CAs

Rules must opt into lax TLS by declaring `tls_mode: lax` in their definition. When you pass `--tls-mode=lax`, only rules with this declaration will use relaxed certificate validation. SaaS API validators (GitHub, Slack, AWS, etc.) always use strict validation regardless of this flag.

### Examples

```bash
# Default: strict TLS everywhere
kingfisher scan ./repo

# Lax TLS for database connection rules (Postgres, MySQL, MongoDB, JDBC, JWT)
kingfisher scan --tls-mode=lax ./repo

# Disable all TLS validation (not recommended)
kingfisher scan --tls-mode=off ./repo
```

The legacy `--ignore-certs` flag is still supported as an alias for `--tls-mode=off`.

---

## Understanding the Scan Summary

After each scan, Kingfisher displays a summary with validation statistics:

```
==========================================
Scan Summary:
==========================================
 |Findings....................: 15
 |__Successful Validations....: 3
 |__Failed Validations........: 5
 |__Skipped Validations.......: 2
 |Rules Applied...............: 120
 |__Blobs Scanned.............: 1,234
 |Bytes Scanned...............: 45.2 MB
 |Scan Duration...............: 12s 345ms
 ...
```

### Validation Counters

| Counter | Description |
| ------- | ----------- |
| **Successful Validations** | Credentials confirmed as active by the provider (e.g., API returned valid response) |
| **Failed Validations** | Validations that were attempted but failed (HTTP errors, connection timeouts, invalid credentials) |
| **Skipped Validations** | Validations that could not be attempted due to missing preconditions (e.g., missing dependent rules) |

### Why Validations Are Skipped

Validations are marked as "skipped" when:

- **Missing dependent rules**: Some rules require values from other rules to validate. For example, an AWS Secret Key rule needs the Access Key ID from the AWS Access Key rule. If the dependent rule wasn't matched, validation cannot proceed.
- **Preconditions not met**: The validation endpoint requires additional context that wasn't available in the scan.

When a validation is skipped, the finding will show:

```
 |Validation....: Inactive Credential
 |__Response....: Validation skipped - missing dependent rules: helper-rule-id
```

This distinction helps you understand validation coverage: **Failed Validations** represent actual validation attempts, while **Skipped Validations** indicate opportunities to improve rule coverage or provide additional context.

---

## Environment Variables

| Variable          | Purpose                      |
| ----------------- | ---------------------------- |
| `KF_GITHUB_TOKEN` | GitHub Personal Access Token |
| `KF_GITLAB_TOKEN` | GitLab Personal Access Token |
| `KF_GITEA_TOKEN` | Gitea Personal Access Token |
| `KF_GITEA_USERNAME` | Username for private Gitea clones (used with `KF_GITEA_TOKEN`) |
| `KF_AZURE_TOKEN` / `KF_AZURE_PAT` | Azure Repos Personal Access Token |
| `KF_AZURE_USERNAME` | Username to use with Azure Repos PATs (defaults to `pat` when unset) |
| `KF_BITBUCKET_TOKEN` | Bitbucket Cloud workspace API token or Bitbucket Server PAT |
| `KF_BITBUCKET_USERNAME` | Optional Bitbucket username for legacy app passwords or server tokens |
| `KF_BITBUCKET_APP_PASSWORD` | Legacy Bitbucket app password (deprecated September 9, 2025; disabled June 9, 2026) |
| `KF_BITBUCKET_OAUTH_TOKEN` | Bitbucket OAuth or PAT token |
| `KF_HUGGINGFACE_TOKEN` | Hugging Face access token for API enumeration and git cloning |
| `KF_HUGGINGFACE_USERNAME` | Optional username for Hugging Face git operations (defaults to `hf_user`) |
| `KF_JIRA_TOKEN`   | Jira API token               |
| `KF_CONFLUENCE_TOKEN` | Confluence API token      |
| `KF_SLACK_TOKEN`  | Slack API token              |
| `KF_DOCKER_TOKEN` | Docker registry token (`user:pass` or bearer token). If unset, credentials from the Docker keychain are used |
| `KF_AWS_KEY`, `KF_AWS_SECRET`, and `KF_AWS_SESSION_TOKEN` | AWS credentials for S3 bucket scanning. Session token is optional, for temporary credentials |

Set them temporarily per command:

```bash
KF_GITLAB_TOKEN="glpat-…" kingfisher scan gitlab --group my-group
```

Or export for the session:

```bash
export KF_GITLAB_TOKEN="glpat-…"
```

To authenticate Jira requests:

```bash
export KF_JIRA_TOKEN="token"
```

To authenticate Confluence requests:

```bash
export KF_CONFLUENCE_TOKEN="token"
```

_If no token is provided Kingfisher still works for public repositories._

---

## Exit Codes

| Code | Meaning                       |
| ---- | ----------------------------- |
| 0    | No findings                   |
| 200  | Findings discovered           |
| 205  | Validated findings discovered |
