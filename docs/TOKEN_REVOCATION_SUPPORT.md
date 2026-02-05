# Token Revocation Support

This document provides an overview of the revocation support added to Kingfisher for various service tokens.

## Overview

Revocation support has been added for **6 services** that provide verified, documented programmatic API endpoints to delete or revoke access tokens/keys. Most implementations use the **HttpMultiStep** revocation type because they require a two-step process:

1. **Step 1 (Lookup)**: Query the API to retrieve an internal ID or token identifier
2. **Step 2 (Delete)**: Use the extracted ID to perform the actual revocation

**Important**: All implementations have been verified against official API documentation to ensure correctness.

## Services with Revocation Support

### 1. SendGrid (`sendgrid.yml`)
- **Rule ID**: `kingfisher.sendgrid.1`
- **Revocation Type**: HttpMultiStep (2-step)
- **Endpoint**: `DELETE /v3/api_keys/{api_key_id}`
- **Process**:
  1. List all API keys to find the current key's ID
  2. Delete the API key using its ID
- **Note**: SendGrid only shows partial keys in the list, so the first key is extracted

### 2. Tailscale (`tailscale.yml`)
- **Rule ID**: `kingfisher.tailscale.1`
- **Revocation Type**: HttpMultiStep (2-step)
- **Endpoint**: `DELETE /api/v2/tailnet/{tailnet}/keys/{keyId}`
- **Process**:
  1. List all keys to find the current key's ID
  2. Delete the key using its ID (using `-` as tailnet for authenticated user's tailnet)

### 3. MongoDB Atlas (`mongodb.yml`)
- **Rule ID**: `kingfisher.mongodb.1`
- **Revocation Type**: HttpMultiStep (2-step)
- **Endpoint**: `DELETE /api/atlas/v2/orgs/{ORG_ID}/apiKeys/{API_KEY_ID}`
- **Process**:
  1. List all organizations to get the first ORG_ID
  2. Delete the API key using the public key as the API_KEY_ID
- **Authentication**: Uses HTTP Digest authentication
- **Note**: The Public Key serves as the API_KEY_ID needed for deletion

### 4. Sumo Logic (`sumologic.yml`)
- **Rule ID**: `kingfisher.sumologic.2`
- **Revocation Type**: Http (single-step)
- **Endpoint**: `DELETE /api/v1/accessKeys/{id}`
- **Process**: Direct deletion using the Access ID
- **Authentication**: Basic Auth (Access ID as username, Access Key as password)
- **Note**: The Access ID is the ID needed for deletion (captured from `kingfisher.sumologic.1`)

### 5. Twilio (`twilio.yml`)
- **Rule ID**: `kingfisher.twilio.2`
- **Revocation Type**: HttpMultiStep (2-step)
- **Endpoint**: `DELETE /2010-04-01/Accounts/{Account_SID}/Keys/{Key_SID}.json`
- **Process**:
  1. List accounts to get the Account SID
  2. Delete the API key using both Account SID and Key SID
- **Note**: Assumes TWILIOID is an API Key SID (starts with `SK`)

### 6. NPM (`npm.yml`)
- **Rule IDs**: `kingfisher.npm.1`, `kingfisher.npm.2`
- **Revocation Type**: HttpMultiStep (2-step)
- **Endpoint**: `DELETE /-/npm/v1/tokens/token/{token_key}`
- **Process**:
  1. List all tokens to find the current token's key ID
  2. Revoke the token using its key
- **Alternative**: Can also use `npm token revoke <id>` CLI command


## Testing Revocation

To test revocation for a detected token:

```bash
# Revoke a token using the rule ID
kingfisher revoke --rule <rule_id> <token>

# With debug logging to see step-by-step execution
RUST_LOG=debug kingfisher revoke --rule <rule_id> <token>

# With additional variables if needed (e.g., for services with depends_on_rule)
kingfisher revoke --rule <rule_id> --var EXTRA_VAR=value <token>
```

### Example: Revoking a SendGrid API Key

```bash
# Revoke a SendGrid API key
kingfisher revoke --rule kingfisher.sendgrid.1 "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"
```

### Example: Revoking a MongoDB API Key

```bash
# Revoke a MongoDB Atlas API key (requires both public and private key)
kingfisher revoke --rule kingfisher.mongodb.1 \
  --var PUBKEY=qj4Zrh8e6A \
  "4b18315e-6b7d-4337-b449-5d38f5a189ec"
```

## Implementation Details

### Multi-Step Revocation Pattern

All multi-step revocations follow this general pattern:

```yaml
revocation:
  type: HttpMultiStep
  content:
    steps:
      # Step 1: Lookup
      - name: lookup_id
        request:
          method: GET
          url: https://api.service.com/endpoint
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - type: StatusMatch
              status: [200]
            - type: JsonValid
        extract:
          ID_VARIABLE:
            type: JsonPath
            path: "$.path.to.id"
      
      # Step 2: Delete
      - name: delete
        request:
          method: DELETE
          url: https://api.service.com/endpoint/{{ ID_VARIABLE }}
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - report_response: true
            - type: StatusMatch
              status: [200, 204]
```

### Variable Extraction Methods

The following extraction methods are used across different services:

| Method | Description | Example Services |
|--------|-------------|------------------|
| **JsonPath** | Extract from JSON response using JSONPath syntax | SendGrid, Netlify, Tailscale, ElevenLabs, NPM, MongoDB |
| **Regex** | Extract using regex with a capture group | (Not used in current implementations) |
| **Header** | Extract an HTTP response header value | (Not used in current implementations) |
| **Body** | Use the entire response body | (Not used in current implementations) |

### Common JSONPath Patterns

- `$.result[0].api_key_id` - SendGrid: Extract first API key ID from result array
- `$.keys[0].id` - Tailscale: Extract first key ID from keys object
- `$.results[0].id` - MongoDB: Extract first organization ID from results
- `$.objects[0].token.key` - NPM: Extract token key from objects array
- `$.accounts[0].sid` - Twilio: Extract account SID from accounts array

## Security Considerations

### Token Identification

Some services (like SendGrid, NPM, and Tailscale) list all tokens but don't include the full token value in the response. The current implementations extract the **first** token from the list, which assumes:

1. The user has only one active token, OR
2. The token being revoked is the first one in the list

**Important**: If multiple tokens exist, the wrong token might be revoked. In production, consider:
- Adding user prompts to confirm which token to revoke
- Matching tokens by creation date, name, or other metadata
- Displaying a list of tokens for user selection

### Digest Authentication

MongoDB Atlas uses HTTP Digest authentication, which is properly handled by the Kingfisher HTTP client via the `digest` field in the request configuration.


## Limitations

1. **Maximum 2 steps**: The HttpMultiStep implementation supports only 1-2 steps
2. **Sequential execution**: Steps execute in order; no parallel execution
3. **Token identification**: Services that don't return full token values may revoke the wrong token if multiple exist
4. **Requires API access**: All revocations require the token to have sufficient permissions to list and delete itself

## Future Enhancements

Potential improvements for revocation support:

1. **Interactive mode**: Prompt user to select which token to revoke when multiple exist
2. **Dry-run mode**: Show what would be revoked without actually revoking
3. **Batch revocation**: Revoke multiple tokens at once
4. **Revocation history**: Track what was revoked and when
5. **Rollback support**: For services that support token restoration
6. **Service-specific CLI support**: For services like NPM that have CLI commands

## References

- [Multi-Step Revocation Implementation](MULTI_STEP_REVOCATION.md)
- [Writing Custom Rules](RULES.md)
- [Kingfisher Rules Schema](../crates/kingfisher-rules/src/rule.rs)
