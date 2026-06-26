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
