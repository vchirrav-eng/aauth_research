# MCP server-side implementations — authentication + authorization

Runnable companions to the comparison table in the [root README](../README.md). Each folder is
one **MCP server** enforcing, for every `tools/call`, `resources/read`, and `prompts/get`:

1. **Authentication** — who is the MCP **client**, and who is the **user** (if the mechanism can
   even express one)?
2. **Authorization** — may *that pair* touch *this specific* tool / resource / prompt?

**There is no MCP gateway in any of these examples.** Nothing upstream has validated anything, so
the MCP server itself is the policy enforcement point and must re-derive the caller on every
request. That is the realistic shape for a standalone MCP server, and it is why each folder has
to do its own token validation, audience checking, and challenge emission.

```
src/
├── _common/          policy.py (shared authz) + mcp_server.py (shared MCP core)
├── 01-api-keys/      shared secret          — client only, no user
├── 02-oauth-oidc/    bearer access token    — client + user, but stealable
├── 06-oauth-dpop/    DPoP-bound token       — same OAuth, no longer stealable
├── 03-mtls/          client certificate     — strong, machine only, channel-scoped
├── 04-spiffe-spire/  X.509-SVID / JWT-SVID  — attested workload, still no user
└── 05-aauth/         RFC 9421 signature     — agent + person, bound, non-repudiable
```

## Run them

Python 3.9+. `05-aauth` and `06-oauth-dpop` need one dependency (`pip install cryptography`) because they
perform **real Ed25519 verification** rather than faking it.

```bash
python src/01-api-keys/server.py
python src/02-oauth-oidc/server.py
python src/06-oauth-dpop/server.py
python src/03-mtls/server.py
python src/04-spiffe-spire/server.py
python src/05-aauth/server.py

python src/run_all.py        # all six, back to back
```

Each prints a labelled ALLOW/DENY trace for success cases *and* attack cases (stolen token,
wrong audience, replay, tampered body).

## Why the authorization code is shared

`_common/policy.py` holds one policy table and one `authorize()` used by all six servers, so the
**only** thing that differs between the folders is the `authenticate()` function. That is the
whole point: authorization is largely a solved, mechanism-independent problem — what actually
separates these six is *what the server is able to learn about the caller*, and *how hard that
claim is to forge*.

The same three primitives are exposed everywhere:

| Primitive | Kind | Needs a user? |
|---|---|---|
| `ping` | tool | no |
| `list_reports` | tool | no — client scope `reports:read` |
| `read_inbox` | tool | **yes** — `inbox:read` |
| `send_payment` | tool | **yes** — `payments:write` |
| `file:///public/handbook.md` | resource | no |
| `file:///users/me/notes.md` | resource | **yes** — `notes:read` |
| `summarize_report` | prompt | no |
| `draft_reply` | prompt | **yes** — `inbox:read` |

## What each mechanism can actually prove

| | Client identity | User identity | Proof is | Stolen credential works? | Artifact per request |
|---|---|---|---|---|---|
| **API keys** | account, coarse | **none** | a shared secret | yes, until rotated | no |
| **OAuth 2.1 / OIDC** | `client_id` | `sub` + consent | issuance, not possession | **yes** — bearer | no |
| **OAuth + DPoP** | `client_id` | `sub` + consent | **possession, per request** | **no** — `cnf.jkt`-bound | yes — but not over the body |
| **mTLS** | cert subject | **none** | key possession, at handshake | no (needs the key) | no — channel only |
| **SPIFFE / SPIRE** | SPIFFE ID, attested | **none** | X.509 possession *or* bearer JWT | X.509 no / JWT-SVID yes | no |
| **AAuth** | agent, from published key | `sub` via person server | **possession, per request** | **no** — `cnf`-bound | **yes — a signature** |

Three of the six cannot carry a user at all. In those servers every user-scoped primitive is
denied — and `tools/list` doesn't even advertise them, since showing an agent a tool it can never
call only invites it to plan around a guaranteed failure.

### The two independent axes

The root README's point that **"is it a JWT" is unrelated to strength** is visible in the code:

- `01-api-keys` uses no JWT and is the weakest.
- `05-aauth` uses JWTs throughout and is the strongest.
- `04-spiffe-spire` implements **both** SVID types side by side, and the **X.509-SVID (not a
  JWT) is stronger than the JWT-SVID (a JWT)** — the bearer form is replayable for its lifetime.

What actually moves the needle is **bearer vs. bound**, and it shows up as one specific check in
two different folders:

```python
# 06-oauth-dpop: proof key thumbprint must equal the token's cnf.jkt
if not hmac.compare_digest(_jkt(jwk), bound_jkt): ...

# 05-aauth: the request signature must verify against the key in cnf
verify_key.verify(presented, base)
```

Both demos steal a valid token, present it with an attacker's key, and watch it fail.

### What the proof covers is the next question

Once two mechanisms are bound, "bound or not" stops being the interesting axis — **what the
signature covers** takes over:

| | Covers method + URI | Covers the token | Covers the **body** |
|---|---|---|---|
| **DPoP** | yes (`htm` / `htu`) | yes (`ath`) | **no** |
| **AAuth** | yes (`@method` / `@authority` / `@path`) | yes (`signature-key` covered) | **yes**, via `content-digest` |

That gap is concrete for MCP, where every `tools/call` shares one method and URI.
`06-oauth-dpop` demonstrates it: the body is swapped `read_inbox` → `send_payment` with the proof
untouched, and **the proof still verifies** — the call is stopped only by the authorization step,
because that user happened to lack `payments:write`. `05-aauth` rejects the same tampering at the
authentication step, because the digest is signed.

## Where the checks live in a real MCP server

`_common/mcp_server.py` is a dependency-free teaching model, not a framework. With the official
MCP Python SDK the two enforcement points land in exactly the same places:

```python
@server.call_tool()
async def call_tool(name: str, arguments: dict):
    principal = authenticate(current_request())   # 1. who is calling (every request)
    authorize(principal, "tool", name)            # 2. may they use THIS tool
    return await run(name, arguments)
```

Both must run on **every** request. MCP connections are long-lived, and tokens expire or get
revoked mid-connection, so authenticating once at initialize and trusting it afterwards is a bug.

## Notes on the AAuth example

`05-aauth/server.py` follows the wire format in
[`~/.aauth/fetch/logs/walkthrough-2.jsonl`](../~/.aauth/fetch/logs/walkthrough-2.jsonl) — the
authoritative protocol log in this repo. Header names (`Signature`, `Signature-Input`,
`Signature-Key`, `AAuth-Requirement`), token `typ` values (`aa-agent+jwt`, `aa-resource+jwt`,
`aa-auth+jwt`), and claim shapes (`cnf`, `agent_jkt`, `act`, `ps`) match it.

It implements two of the four access modes from the root README:

- **Identity-Based** (agent + resource) — the agent token alone authorizes non-user work.
- **PS-asserted** (three-party) — a user-scoped call gets `401` + an `aa-resource+jwt` in
  `AAuth-Requirement`, which the agent takes to the person server; after the human consents it
  returns with an `aa-auth+jwt` carrying `sub`, `email`, and `name`.

The server mints that resource token itself (`mint_resource_token`) — with no gateway, driving
the consent ceremony is the MCP server's own job.
