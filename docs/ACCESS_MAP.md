# Access Map: supported tokens & credential formats

Kingfisher’s **access map** determines the *effective identity* and *blast radius* of a credential by authenticating to the target provider and enumerating accessible resources and permissions.

There are two ways to produce access maps:

- **During scanning**: `kingfisher scan ... --access-map`  
  Kingfisher validates detected secrets and automatically generates access-map entries for supported credential types.
- **Standalone**: `kingfisher access-map <provider> [credential_file]`  
  This reads a credential artifact from disk and maps it directly.

> Access mapping runs additional network requests. Only use it when you are authorized to inspect the target account/workspace.

## What “supported tokens” means

Access map only runs for credential types Kingfisher knows how to authenticate with and enumerate. In the codebase, these map to `AccessMapRequest` variants recorded from validated findings (see `src/scanner/validation.rs`).

## Providers and supported credential formats

### GitHub (`github`)

- **Credential**: a single GitHub token string (read from a file for `kingfisher access-map github <FILE>`).
- **Token types supported**: any token accepted by GitHub’s REST API `Authorization` scheme used by Kingfisher (`Authorization: token <TOKEN>`), including:
  - Classic PATs (commonly `ghp_...`)
  - Fine-grained PATs (commonly `github_pat_...`)
  - OAuth / user tokens (various prefixes; GitHub controls these)
  - GitHub App tokens (Kingfisher detects `ghu_...` and `ghs_...` and uses the installations APIs for richer mapping)

#### Standalone example (GitHub)

```bash
printf '%s' 'ghp_example...' > ./github.token
kingfisher access-map github ./github.token --json-out github.access-map.json
```

#### Notes (GitHub)

- Access map currently uses `https://api.github.com` as the API base.

### GitLab (`gitlab`)

- **Credential**: a single GitLab token string (read from a file for `kingfisher access-map gitlab <FILE>`).
- **Token types supported**: any token accepted by GitLab’s `PRIVATE-TOKEN` header (PATs like `glpat-...`, plus other GitLab token types that work with that header).  
  When available, Kingfisher also queries the token-self endpoint for metadata; some token types may not expose token details there.

#### Standalone example (GitLab)

```bash
printf '%s' 'glpat-example...' > ./gitlab.token
kingfisher access-map gitlab ./gitlab.token --json-out gitlab.access-map.json
```

#### Notes (GitLab)

- Access map currently uses `https://gitlab.com/api/v4/` as the API base.

### Slack (`slack`)

- **Credential**: a single Slack token string (read from a file for `kingfisher access-map slack <FILE>`).
- **Token types supported**: tokens accepted by Slack Web API with `Authorization: Bearer <TOKEN>` (for example `xoxp-...`, `xoxb-...`, etc.).  
  Kingfisher derives scopes from the `x-oauth-scopes` response header when Slack returns it.

#### Standalone example (Slack)

```bash
printf '%s' 'xoxp-example...' > ./slack.token
kingfisher access-map slack ./slack.token --json-out slack.access-map.json
```

### AWS (`aws`)

- **Credential**: AWS access key credentials.
- **Supported formats for `kingfisher access-map aws <FILE>`**:
  - **JSON object** with case-insensitive support for the following keys:
    - `access_key_id` / `accessKeyId` / `aws_access_key_id` / `AccessKeyId`
    - `secret_access_key` / `secretAccessKey` / `aws_secret_access_key` / `SecretAccessKey`
    - optional `session_token` / `sessionToken` / `aws_session_token` / `SessionToken`
  - **Key/value file** containing `KEY=VALUE` lines (comments allowed with `#`), supporting:
    - `aws_access_key_id` or `access_key_id`
    - `aws_secret_access_key` or `secret_access_key`
    - optional `aws_session_token` or `session_token`

#### Standalone examples (AWS)

```bash
cat > ./aws.json <<'EOF'
{
  "access_key_id": "AKIA....",
  "secret_access_key": "....",
  "session_token": "...."
}
EOF

kingfisher access-map aws ./aws.json --json-out aws.access-map.json
```

```bash
cat > ./aws.env <<'EOF'
aws_access_key_id=AKIA....
aws_secret_access_key=....
aws_session_token=....
EOF

kingfisher access-map aws ./aws.env --json-out aws.access-map.json
```

### GCP (`gcp`)

- **Credential**: a Google Cloud **service account key JSON** file.

#### Standalone example (GCP)

```bash
kingfisher access-map gcp ./service-account.json --json-out gcp.access-map.json
```

### Azure Storage (`azure`)

- **Credential**: a JSON file containing:
  - `storage_account` (string)
  - `storage_key` (string, base64-encoded account key as provided by Azure)

#### Standalone example (Azure Storage)

```bash
cat > ./azure-storage.json <<'EOF'
{
  "storage_account": "mystorageacct",
  "storage_key": "base64=="
}
EOF

kingfisher access-map azure ./azure-storage.json --json-out azure.access-map.json
```

### Azure DevOps (scan `--access-map` only)

Azure DevOps access mapping is supported when a **validated Azure DevOps PAT** is discovered during scanning (the access-map record includes both the PAT and the organization). At the moment, there is **no standalone** `kingfisher access-map azure-devops ...` provider flag.

### PostgreSQL (`postgres`)

- **Credential**: a single Postgres connection URI string (read from a file).

#### Standalone example (Postgres)

```bash
printf '%s' 'postgres://user:pass@db.example.com:5432/mydb' > ./postgres.uri
kingfisher access-map postgres ./postgres.uri --json-out postgres.access-map.json
```

### MongoDB (`mongodb` / `mongo`)

- **Credential**: a single MongoDB connection URI string (read from a file), including `mongodb+srv://...` URIs.

#### Standalone example (MongoDB)

```bash
printf '%s' 'mongodb+srv://user:pass@cluster.example.net/?retryWrites=true&w=majority' > ./mongodb.uri
kingfisher access-map mongodb ./mongodb.uri --json-out mongodb.access-map.json
```

### Hugging Face (`huggingface` / `hf`)

- **Credential**: a single Hugging Face token string (read from a file for `kingfisher access-map huggingface <FILE>`).
- **Token types supported**: tokens accepted by the Hugging Face API with `Authorization: Bearer <TOKEN>`, including:
  - User access tokens (commonly `hf_...`)
  - Organization API tokens (commonly `api_org_...`)

Kingfisher queries the `/api/whoami-v2` endpoint to resolve the token identity, role, and organization memberships. It also enumerates models authored by the user to assess the blast radius.

#### Standalone example (Hugging Face)

```bash
printf '%s' 'hf_example...' > ./huggingface.token
kingfisher access-map huggingface ./huggingface.token --json-out huggingface.access-map.json
```

#### Notes (Hugging Face)

- Access map uses `https://huggingface.co/api` as the API base.
- Token role (read, write, admin, fineGrained) is derived from the `auth` section of the whoami response when available.

### Gitea (`gitea`)

- **Credential**: a single Gitea token string (read from a file for `kingfisher access-map gitea <FILE>`).
- **Token types supported**: any token accepted by Gitea's `Authorization: token <TOKEN>` header (personal access tokens).

Kingfisher queries `/api/v1/user` for identity, enumerates organizations via `/api/v1/user/orgs`, and lists accessible repositories via `/api/v1/user/repos`. Repository-level permissions (admin, push, pull) are used to classify risk.

#### Standalone example (Gitea)

```bash
printf '%s' 'your_gitea_pat...' > ./gitea.token
kingfisher access-map gitea ./gitea.token --json-out gitea.access-map.json
```

#### Notes (Gitea)

- Access map currently uses `https://gitea.com/api/v1/` as the default API base.
- If the token belongs to a site administrator, severity is classified as Critical.

### Bitbucket (`bitbucket`)

- **Credential**: a single Bitbucket token string (read from a file for `kingfisher access-map bitbucket <FILE>`).
- **Token types supported**: tokens accepted by Bitbucket Cloud's `Authorization: Bearer <TOKEN>` header (OAuth access tokens, app passwords, repository access tokens).

Kingfisher queries `/2.0/user` for identity, enumerates workspace memberships and permissions via `/2.0/user/permissions/workspaces`, and lists accessible repositories via `/2.0/repositories?role=member`. Workspace ownership and private repository access are used to classify risk.

#### Standalone example (Bitbucket)

```bash
printf '%s' 'your_bitbucket_token...' > ./bitbucket.token
kingfisher access-map bitbucket ./bitbucket.token --json-out bitbucket.access-map.json
```

#### Notes (Bitbucket)

- Access map uses `https://api.bitbucket.org/2.0` as the API base.
- Workspace owners are classified as High severity.

### Buildkite (`buildkite`)

- **Credential**: a single Buildkite API token string (read from a file for `kingfisher access-map buildkite <FILE>`).
- **Token types supported**: tokens accepted by Buildkite's REST API with `Authorization: Bearer <TOKEN>` (API access tokens, commonly `bkua_...`).

Kingfisher queries `/v2/access-token` for token metadata and scopes, `/v2/user` for identity, `/v2/organizations` for organization memberships, and `/v2/organizations/{org}/pipelines` for pipeline enumeration. Token scopes and organization access are used to classify risk.

#### Standalone example (Buildkite)

```bash
printf '%s' 'bkua_example...' > ./buildkite.token
kingfisher access-map buildkite ./buildkite.token --json-out buildkite.access-map.json
```

#### Notes (Buildkite)

- Access map uses `https://api.buildkite.com/v2` as the API base.
- Tokens with `write_organizations` or `write_teams` scopes are classified as High severity.

### Harness (`harness`)

- **Credential**: a single Harness API key / personal access token (PAT) string (read from a file for `kingfisher access-map harness <FILE>`).
- **Auth header**: Harness APIs authenticate via `x-api-key: <TOKEN>` (see the Harness API docs).

Kingfisher performs best-effort, read-only enumeration:

- Queries the API key aggregate endpoint for basic token metadata (when available).
- Enumerates organizations via `GET https://app.harness.io/v1/orgs` and projects via `GET https://app.harness.io/v1/orgs/{org}/projects` when the key has permission.

If organizations/projects are not enumerable (scope-limited keys), Kingfisher still produces an access-map record with a conservative severity and a note explaining the limitation.

#### Standalone example (Harness)

```bash
printf '%s' 'pat.example...' > ./harness.token
kingfisher access-map harness ./harness.token --json-out harness.access-map.json
```

#### Notes (Harness)

- Access map uses `https://app.harness.io` as the API base.

### OpenAI (`openai`)

- **Credential**: a single OpenAI API key string (read from a file for `kingfisher access-map openai <FILE>`).
- **Token types supported**: OpenAI keys accepted by `Authorization: Bearer <TOKEN>` (for example `sk-...`, `sk-proj-...`, `sk-svcacct-...`).

Kingfisher performs read-only scope probing via:

- `GET https://api.openai.com/v1/models` to verify Models API read access and infer organization ownership (it does not enumerate or emit individual model resources in the access map).
- `GET https://api.openai.com/v1/me` for token identity metadata when available.
- `GET https://api.openai.com/v1/organization/projects` for project visibility when the key has permission (best-effort).

#### Standalone example (OpenAI)

```bash
printf '%s' 'sk-example...' > ./openai.token
kingfisher access-map openai ./openai.token --json-out openai.access-map.json
```

#### Notes (OpenAI)

- Access map uses `https://api.openai.com/v1` as the API base.

### Salesforce (`salesforce`)

- **Credential**: Salesforce access token plus instance domain.
- **Supported standalone formats** for `kingfisher access-map salesforce <FILE>`:
  - JSON:
    - `token` (or `access_token`)
    - `instance_url` (or `instance`), such as `https://mydomain.my.salesforce.com`
  - Free-form text containing both:
    - a Salesforce access token (`00...!...`)
    - an instance host (`<instance>.my.salesforce.com`)

Kingfisher performs read-only enumeration via:

- `GET /services/data/v60.0/limits` to confirm API access and gather account-level API context.
- `GET /services/oauth2/userinfo` for identity metadata when available.
- `GET /services/data/v60.0/sobjects` for visible object metadata (best-effort).

#### Standalone example (Salesforce)

```bash
cat > ./salesforce.json <<'EOF'
{
  "token": "00DE0X0A0M0PeLE!AQcAQH0dMHEXAMPLE...",
  "instance_url": "https://mydomain.my.salesforce.com"
}
EOF

kingfisher access-map salesforce ./salesforce.json --json-out salesforce.access-map.json
```

#### Notes (Salesforce)

- Access map currently targets `https://<instance>.my.salesforce.com` and API version `v60.0`.

### Weights & Biases (`weightsandbiases` / `wandb`)

- **Credential**: a single Weights & Biases API key string (read from a file for `kingfisher access-map weightsandbiases <FILE>`).
- **Token types supported**:
  - Legacy 40-character hex API keys
  - New v1 keys (`wandb_v1_...`)

Kingfisher performs read-only identity resolution via:

- `POST https://api.wandb.ai/graphql` with a GraphQL `viewer` query.

#### Standalone example (Weights & Biases)

```bash
printf '%s' 'wandb_v1_example...' > ./wandb.token
kingfisher access-map weightsandbiases ./wandb.token --json-out wandb.access-map.json
```

#### Notes (Weights & Biases)

- Access map uses `https://api.wandb.ai/graphql` as the API endpoint.
- W&B key introspection does not currently expose fine-grained scopes in this workflow, so risk is reported conservatively.

## Notes on access-map generation during `scan --access-map`

- Access-map entries are only recorded for **validated** findings.
- Some providers require extra context that Kingfisher infers from the finding context or validation response (for example, Azure DevOps organization name).
- Validated Hugging Face, Gitea, Bitbucket, Buildkite, Harness, OpenAI, Anthropic, Salesforce, and Weights & Biases credentials discovered during scans with `--access-map` are automatically collected and mapped, matching the existing behavior for other platforms.
