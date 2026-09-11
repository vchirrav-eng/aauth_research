# OAuth 2.1 + DPoP (RFC 9449)

The same OAuth deployment as [`02-oauth-oidc`](../02-oauth-oidc/), with the bearer weakness
removed. **Only the credential check differs** — flow, scopes, consent and claims are unchanged.
That is the appeal: it is an upgrade you can apply to OAuth you already run, with no new
infrastructure.

Real Ed25519 verification (`pip install cryptography`), so every ALLOW/DENY is genuine.

## Two headers instead of one

```
Authorization: DPoP <access_token>     <- NOT "Bearer"
DPoP: <proof JWT, typ "dpop+jwt">
```

The client generates a key pair and **never sends the private key**. The AS pins the access token
to it with `cnf.jkt` (the RFC 7638 SHA-256 thumbprint of the public key). Each request carries a
fresh proof JWT whose `jwk` header holds that public key, signed by the private one.

## The binding check

```python
if not hmac.compare_digest(_jkt(jwk), bound_jkt):   # proof key vs. token's cnf.jkt
    raise AuthenticationError(...)
```

One comparison is what makes the token non-transferable. The demo steals a valid token, signs
with a different key, and watches it fail.

## What the server validates

| Check | Stops |
|---|---|
| `cnf.jkt` == thumbprint(`jwk`) | using a **stolen token** |
| proof signature | forging a proof for someone else's key |
| `htm` / `htu` | replaying a proof at **another endpoint** |
| `iat` freshness | using **captured** proofs later |
| `ath` | pairing a proof with a **different token** |
| `jti` unseen | **replaying** the same proof |
| `typ` = `dpop+jwt`, `alg` asymmetric | proof confusion, `alg: none` forgery |
| `Bearer` scheme refused | **downgrading** a bound token back to a bearer |

## The limit — and why it matters for MCP

The proof covers method, URI, timestamp and token hash. It does **not cover the request body**.

Every MCP `tools/call` goes to the same method and URI, so within the freshness window one proof
is valid for *any tool name*. The demo swaps `read_inbox` → `send_payment` leaving the proof
untouched, and the proof still verifies — the call is stopped only by the authorization step,
because that user lacked `payments:write`. Had they held it, the tampered request would have
succeeded.

Mitigations: short `iat` windows, a server-issued `DPoP-Nonce`, and TLS so bodies cannot be
tampered with in flight. [`05-aauth`](../05-aauth/) closes it directly by covering a
`content-digest` in the signature.

## DPoP vs. AAuth

Both bind at the **message** level (unlike mTLS, which binds the channel). They differ in reach:

- **DPoP** — identity still comes from an AS you registered with in advance. Right answer when
  you already run OAuth.
- **AAuth** — the agent publishes its own key, so no pre-registration is needed, and agent vs.
  person identity stay separate (`act`), keeping delegation legible across organizations.
