# mTLS / client certificates

The TLS handshake proves the peer holds the private key for its certificate. Application code
only *reads the result* -- `ssl.SSLContext(verify_mode=ssl.CERT_REQUIRED)` plus a CA bundle, then
`getpeercert()`.

## What the MCP server learns
- **Client:** the certificate subject / SAN -- a **workload**.
- **User:** *nothing.* A certificate is not a person and nobody consented to anything.

## Authentication is strong, but
1. **No user.** User-scoped primitives denied -- same outcome as API keys, completely different
   strength.
2. **Channel-scoped, not per-message.** The handshake happened once, before any MCP request; every
   later request on that connection inherits it. The server can prove *this connection belonged to
   cert X*, never *this particular `tools/call` was made*. Anything that can write to the socket
   afterwards -- a proxy, a sidecar, a compromised co-process -- is indistinguishable from the
   client.

So `proof` is recorded as `tls-channel:<id>`, explicitly *not* per-request evidence.

## Failure modes shown
no cert, untrusted CA, expired, revoked (CRL/OCSP), valid cert without the role, valid cert
reaching for user data.

## Behind a proxy
If nginx terminates TLS, the identity arrives as `ssl_client_verify` / `ssl_client_s_dn` headers.
Trust those **only** if the proxy is the sole ingress *and* it strips client-supplied copies.
