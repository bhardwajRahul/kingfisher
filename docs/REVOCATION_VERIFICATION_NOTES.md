# Revocation Implementation Verification Notes

## Services with Verified Revocation Support

The following services have been verified against their official API documentation to have working programmatic revocation endpoints:

### 1. SendGrid ✅
- **Endpoint**: `DELETE /v3/api_keys/{api_key_id}`
- **Response**: 204 No Content
- **Method**: Multi-step (list keys → delete by ID)
- **Documentation**: https://www.twilio.com/docs/sendgrid/api-reference/api-keys/delete-api-keys

### 2. Tailscale ✅
- **Endpoint**: `DELETE /api/v2/tailnet/{tailnet}/keys/{keyId}`
- **Response**: 200 OK
- **Method**: Multi-step (list keys → delete by ID)
- **Note**: Uses `-` as tailnet for authenticated user's network
- **Documentation**: https://tailscale.com/api

### 3. MongoDB Atlas ✅
- **Endpoint**: `DELETE /orgs/{ORG-ID}/apiKeys/{API-KEY-ID}`
- **Response**: 204 No Content (empty response body)
- **Method**: Multi-step (list orgs → delete by public key)
- **Authentication**: HTTP Digest
- **Documentation**: https://www.mongodb.com/docs/cloud-manager/reference/api/api-keys/org/delete-one-api-key/

### 4. Twilio ✅
- **Endpoint**: `DELETE /2010-04-01/Accounts/{AccountSid}/Keys/{Sid}.json`
- **Response**: 204 No Content
- **Method**: Multi-step (list accounts → delete key)
- **Documentation**: https://www.twilio.com/docs/iam/api-keys/key-resource-v2010

### 5. NPM ✅
- **Endpoint**: `DELETE /-/npm/v1/tokens/token/{token}`
- **Response**: 204 No Content
- **Method**: Multi-step (list tokens → revoke by key)
- **Authentication**: Bearer token (npmSessionToken required)
- **Documentation**: https://api-docs.npmjs.com/

### 6. Sumo Logic ✅
- **Endpoint**: `DELETE /api/v1/accessKeys/{id}`
- **Response**: 204 No Content
- **Method**: Single-step (direct deletion using Access ID)
- **Authentication**: Basic Auth (Access ID:Access Key)
- **Documentation**: https://help.sumologic.com/docs/api/access-keys/

## Services WITHOUT Programmatic Revocation Support

The following services were initially implemented but removed because they do not support programmatic token revocation via their APIs:

### Netlify ❌
- **Issue**: No API endpoint exists for deleting/revoking personal access tokens
- **Available**: Only UI-based revocation through Netlify dashboard
- **Documentation**: https://docs.netlify.com/api-and-cli-guides/api-guides/get-started-with-api
- **Note**: OpenAPI spec (https://open-api.netlify.com/) does not include token deletion endpoints

### ElevenLabs ❌
- **Issue**: No API key deletion endpoint documented
- **Available**: Only workspace secrets deletion, not API keys themselves
- **Documentation**: https://elevenlabs.io/docs/api-reference/authentication
- **Note**: Service Accounts feature mentions "rotating API keys" but no programmatic deletion endpoint exists

### Sourcegraph ❌
- **Issue**: No `deleteAccessToken` GraphQL mutation documented
- **Available**: Tokens can only be revoked through UI (Settings > Access tokens)
- **Documentation**: https://sourcegraph.com/docs/api/graphql
- **Note**: `deleteUser` mutation removes all tokens but no individual token deletion mutation exists

## Common Patterns

### Multi-Step Revocation Pattern
Most services require a 2-step process:
1. **Step 1**: List resources (keys/tokens) to extract the internal ID
2. **Step 2**: Delete using the extracted ID

**Reason**: Services don't accept the token string itself for deletion; they require an internal ID/key identifier.

### Authentication Methods
- **Bearer Token**: SendGrid, Tailscale, NPM (most common)
- **Basic Auth**: Sumo Logic, Twilio
- **HTTP Digest**: MongoDB Atlas (unique)

### Response Codes
- **204 No Content**: Most common success response (SendGrid, MongoDB, Twilio, NPM, Sumo Logic, Tailscale for some endpoints)
- **200 OK**: Tailscale (documented), some services with response bodies

## Verification Process

Each service was verified by:
1. Searching official API documentation
2. Checking OpenAPI/Swagger specs where available
3. Verifying endpoint paths, HTTP methods, and response codes
4. Confirming authentication requirements
5. Testing JSONPath extraction patterns against documented response formats

## Future Considerations

### Services to Monitor
- **Netlify**: May add programmatic token management in future API versions
- **ElevenLabs**: May extend Service Accounts API to include key deletion
- **Sourcegraph**: May add GraphQL mutation for individual token deletion

### Potential Issues
1. **Multiple Tokens**: Current implementations extract the "first" token from lists, which may not be correct if multiple active tokens exist
2. **Rate Limiting**: No rate limiting handling implemented in revocation flows
3. **Partial Success**: If Step 1 succeeds but Step 2 fails, the system doesn't retry
4. **Token Identification**: Services that don't return full token values in lists make it hard to identify the correct token

## Recommendations

1. **Before Using**: Always verify you have only one active token for the service
2. **Test in Development**: Use non-production tokens to test revocation flows
3. **Monitor API Changes**: Service APIs may change; periodically verify endpoints still work
4. **Check Documentation**: Always consult the latest service documentation before revoking critical tokens
5. **Consider Dry-Run**: Implement a dry-run mode that shows what would be revoked without actually revoking

## References

- [Multi-Step Revocation Implementation](MULTI_STEP_REVOCATION.md)
- [Token Revocation Support Documentation](TOKEN_REVOCATION_SUPPORT.md)
- [Rules Documentation](RULES.md)
