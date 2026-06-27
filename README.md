# aauth_research

## Agent auth mechanisms — when to use what

Building up an agent's access to a protected resource (e.g. an MCP server) across four
properties — **identity** (who are you), **authentication** (prove it), **authorization**
(what may you do), and **non-repudiation** (you can't deny you did it, and the server
can't fake that you did) — and where each mechanism lands.

| Mechanism | Identity | Authentication | Authorization | Non-repudiation | Token is a JWT? | Reach for it when |
|---|---|---|---|---|---|---|
| **API keys** | String maps to an account (coarse) | Weak — possession of a *shared* secret, easily stolen | Coarse, server-side scopes tied to the key | **None** — not a signature; logs only | **No** — opaque random string, no structure | Internal/first-party, low-stakes, you own both ends, prototypes |
| **OAuth 2.1 / OIDC** | OIDC ID token = which user; `client_id` = which app | AS mints tokens after a PKCE flow; access token still **bearer** | **Strong & standard** — scopes, consent, revocable, short-lived | Partial (bearer ceiling; DPoP/mTLS adds binding) | **Yes** — ID token always a JWT; access token usually | Human delegates access to a third-party app; **MCP's path today** |
| **mTLS / client certs** | Certificate subject / SAN | Strong — handshake proves private-key possession | Usually external (cert → roles) | Channel-level only, not per-message | **No** — identity is an X.509 certificate (a different signed format) | Service-to-service inside infra you operate |
| **SPIFFE / SPIRE** | SPIFFE ID via workload attestation | SVID — X.509 or JWT | External policy engine | Limited (mTLS / bearer-JWT ceiling) | **Either** — X.509-SVID (no) or JWT-SVID (yes) | Workload identity in a cluster/mesh |
| **AAuth** | Agent identity from a published key + optional person identity via PS | **Per-request RFC 9421 signature** — proves key possession every call; not a bearer | Built-in modes + human consent ceremony; claims like `sub`/`email`/`scope` | **Strong** — each request a detached signature, a durable artifact | **Yes** — agent/resource/auth tokens are all JWTs (`aa-agent+jwt`, etc.) | Cross-org autonomous agents needing non-repudiation + native delegation |

**The "Token is a JWT?" column is independent of how strong the security is.** API keys (no
JWT) and AAuth (all JWTs) sit at opposite ends of the non-repudiation scale, and OAuth and
AAuth both use JWTs yet land in very different places. "Uses JWTs" describes the **encoding**,
not the **strength**.

**What moves the needle is bearer vs. bound.** A stealable **bearer** token (API key,
OAuth/OIDC, JWT-SVID) means possession = use. A token **bound to a key the caller proves
possession of** — mTLS at the channel level, AAuth at the message level — removes that
weakness. AAuth uses the same JWT format as OAuth but stops handing it over as a bearer;
that's the whole difference.

## Workflows — agent to MCP / API server

How the agent reaches a protected MCP / API server under each mechanism, step by step.

### API keys

![Agent to MCP / API server with API keys](img/01-api-keys.png)

### OAuth 2.1 / OIDC

![Agent to MCP / API server with OAuth / OIDC](img/02-oauth-oidc.png)

### mTLS

![Agent to MCP / API server with mTLS](img/03-mtls.png)

### SPIFFE / SPIRE

![Agent to MCP / API server with SPIFFE / SPIRE](img/04-spiffe-spire.png)

### AAuth

![Agent to MCP / API server with AAuth](img/05-aauth.png)

## AAuth access modes

AAuth defines four resource-access modes, from simple identity verification to full
four-party federation. The wire protocol is the same throughout — the difference is what
the resource returns in its `401`/`202` challenge and which party mints the eventual auth
token. Each mode is independently deployable. Source: <https://explorer.aauth.dev/access/compare>

| Mode | Parties | Tokens | Infrastructure | Best for |
|---|---|---|---|---|
| **Identity-Based** | Agent + Resource | `aa-agent+jwt` | None — just the agent and resource | Replacing API keys with cryptographic identity |
| **Resource-Managed** | Two-party | `aa-agent+jwt`, `AAuth-Access` (opaque) | Resource handles auth itself (interaction, OAuth/OIDC, internal policy) | Resource manages authorization without an external PS or AS |
| **PS-Asserted** | Three-party | `aa-agent+jwt`, `aa-resource+jwt`, `aa-auth+jwt` (from PS) | Person Server (no Access Server) | Resource accepts identity claims (`sub`, `email`, `tenant`, groups, roles) from any PS |
| **Federated** | Four-party | `aa-agent+jwt`, `aa-resource+jwt`, `aa-auth+jwt` (from AS) | Person Server + Access Server, PS–AS trust (pre-established or dynamic) | Cross-domain access with the resource's AS enforcing policy |

### 1. Identity-Based — Agent + Resource ([live demo](https://explorer.aauth.dev/access/identity-based))

1. **Agent → Resource** — HTTPSig w/ agent token
2. **Resource → Agent** — 200 OK (access decision by agent identity)

### 2. Resource-Managed — Two-Party ([live demo](https://explorer.aauth.dev/access/resource-managed))

1. **Agent → Resource** — HTTPSig w/ agent token
2. **Resource → Agent** — 202 + `AAuth-Requirement: interaction`
3. **User → Resource** — completes interaction at resource's own page
4. **Agent → Resource** — poll → 200 + `AAuth-Access` (opaque token)
5. **Agent → Resource** — subsequent calls: `Authorization: AAuth <token>`

### 3. PS-Asserted — Three-Party ([live demo](https://explorer.aauth.dev/access/ps-asserted))

1. **Agent → Resource** — HTTPSig → 401 + resource token (`aud=PS`)
2. **Agent → PS** — POST `/token` w/ resource token
3. **PS → Agent** — auth token (`iss=PS`, `dwk=aauth-person.json`)
4. **Agent → Resource** — present auth token → 200

### 4. Federated — Four-Party ([live demo](https://explorer.aauth.dev/access/federated))

1. **Agent → Resource** — HTTPSig → 401 + resource token (`aud=AS`)
2. **Agent → PS** — POST `/token` w/ resource token
3. **PS → AS** — PS federates: POST `/token` (signed)
4. **AS → PS → Agent** — auth token (`iss=AS`, `dwk=aauth-access.json`)
5. **Agent → Resource** — present auth token → 200
