# AAuth

Per-request **RFC 9421 HTTP message signatures**. Every call carries `Signature`,
`Signature-Input` and `Signature-Key`; the agent proves key possession *on each request* instead
of handing over a reusable token.

This example does **real Ed25519 verification** (`pip install cryptography`): it verifies both
the request signature and each issuer-signed JWT against that issuer's JWKS selected by `kid`.
The executable demo injects ephemeral public keys; a deployment resolves the published JWKS URLs.

## What the MCP server learns
- **Client:** the agent, from the `aa-agent+jwt` in `Signature-Key` (`iss` = its published
  identity, `sub` = the agent id).
- **User:** `sub`, `name`, `email`, `tenant` -- from the `aa-auth+jwt` a **person server** issued
  after the human consented.

## The check that changes everything
Both token types carry `cnf.jwk`, naming an ephemeral public key. The server verifies the request
signature **with that key**, after verifying the JWT's own issuer signature. So the JWT is useless to whoever steals it -- the demo replays a
valid auth token signed with an attacker's key and it fails. That single check is the whole
bearer-vs-bound difference.

## The ceremony (no gateway -- this server drives it)
Following [`walkthrough-2.jsonl`](../../~/.aauth/fetch/logs/walkthrough-2.jsonl) step for step:

```
agent signs with aa-agent+jwt      -> 401 AAuth-Requirement: requirement=auth-token;
                                            resource-token="<aa-resource+jwt>"
  (agent POSTs it to the PS token_endpoint; 202 + code; person consents; long-poll returns)
agent signs with aa-auth+jwt       -> 200, server now knows agent AND person
```

The server **mints the resource token itself** (`mint_resource_token`), audience = the agent's own
`ps`, with `agent_jkt` pinning the agent's ephemeral key so the PS binds its auth token to the
same key.

## Modes implemented
- **Identity-Based** -- agent token alone authorizes non-user work (`list_reports`).
- **PS-asserted** -- three-party; the resource trusts `sub`/`email` asserted by a person server in
  `TRUSTED_PERSON_SERVERS`.

## Attacks shown, all genuinely rejected
forged or unsigned JWT, stolen token + attacker's key (`cnf` binding), byte-identical replay (signature cache), signature
captured for `/mcp` replayed at `/admin` (`@path` covered), body swapped `read_inbox` ->
`send_payment` (`content-digest` covered), stale `created`, and an uncovered `signature-key`.

## Non-repudiation
`proof` is the signature itself -- a durable artifact, re-verifiable later against the agent's
published JWKS. The sample uses an expiring in-process cache for readability; a multi-instance
deployment must replace it with shared TTL storage such as Redis. This is the only mechanism in
`src/` where the audit log holds evidence rather than an assertion.

## Delegation cannot escalate
After a person consents, the **agent's own ceiling still applies** (`AGENT_POLICY`). The effective
permission is the *intersection* of what the agent may do and what the person granted -- never the
union.
