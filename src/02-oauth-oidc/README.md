# OAuth 2.1 / OIDC

`Authorization: Bearer <JWT>` -- MCP's path today. The MCP server is the OAuth **resource
server**, so with no gateway it validates tokens and publishes its own
[`metadata.json`](metadata.json) (RFC 9728) itself.

## What the MCP server learns
- **Client:** `client_id` / `azp` -- which app.
- **User:** `sub`, plus `name` / `email`, when a human ran the PKCE + consent flow.

A `client_credentials` token has **no user** -- the example includes one, and it is denied the
user-scoped tools exactly like an API key.

## Validation performed
1. signature (here HMAC; in production fetch the AS JWKS and match `kid`)
2. `iss` -- the AS we trust
3. **`aud` -- that the token was minted for THIS server.** The classic MCP mistake: skip it and
   any sibling service sharing the AS can replay its tokens here (confused deputy).
4. `exp`

## The ceiling
The token is a **bearer**. The server proves the token was validly *issued*, never that the
caller *possesses* anything. Copy the header, replay it anywhere. That is why `proof` is `None`
and non-repudiation is only partial -- a user can plausibly deny a call made with their stolen
token. DPoP or mTLS binding is what raises this; `05-aauth` does it at the message level.
