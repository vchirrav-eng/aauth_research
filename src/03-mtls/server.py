"""MCP server authenticated by MUTUAL TLS (client certificates).

  Identity        : the certificate subject / SAN
  Authentication  : strong -- the TLS handshake proves private-key possession
  Authorization   : usually external -- map cert -> roles
  Non-repudiation : CHANNEL-level only, never per-message

WHAT THE SERVER CAN AND CANNOT KNOW
-----------------------------------
mTLS is strong authentication of a MACHINE. The handshake proves the peer holds
the private key for the presented cert -- nothing is stealable the way an API
key or bearer token is. But that strength stops at the connection.

Two consequences the code below makes explicit:

 1. NO USER. A certificate identifies a workload, not a person. Nobody consented
    to anything. So user-scoped primitives are denied, exactly as with API keys
    -- for a completely different reason, at a completely different strength.

 2. CHANNEL, NOT MESSAGE. The handshake happened once, before any MCP request.
    Every later request on that connection inherits the identity; no individual
    `tools/call` is signed. So the server can prove "this connection belonged to
    the holder of cert X" but cannot later produce evidence that THIS PARTICULAR
    request was made. Anything that can write to the socket after the handshake
    -- a proxy, a sidecar, a compromised process sharing the connection -- is
    indistinguishable from the client. Hence `proof` is channel-scoped only.

WHERE THE VALUES COME FROM
--------------------------
The TLS layer verifies the chain, not application code. Under a plain Python
server that is `ssl.SSLContext(verify_mode=ssl.CERT_REQUIRED)` plus a CA
bundle, then `connection.getpeercert()`. Behind nginx it arrives as
`ssl_client_verify` / `ssl_client_s_dn` headers -- which you may trust ONLY if
the proxy is the sole way in and it strips client-supplied copies of them.
"""

import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_common"))

from mcp_server import MCPServer, demo
from policy import Principal, AuthenticationError

TRUSTED_CA = "CN=Corp Internal CA,O=Example"

# Cert subject -> what that workload may do. Authorization is EXTERNAL to the
# certificate: the cert says who, this table says what.
CERT_ROLES = {
    "CN=reporting-agent,OU=agents,O=Example": {"reports:read"},
    "CN=status-agent,OU=agents,O=Example": set(),
}


def authenticate(request) -> Principal:
    """Read the verified peer certificate. The TLS stack did the hard part.

    `request["tls"]` models what `getpeercert()` hands back AFTER the stack has
    already validated the chain and the private-key proof.
    """
    tls = request.get("tls")
    if not tls:
        # No client cert offered: the handshake would have failed outright.
        raise AuthenticationError(
            "no client certificate presented -- TLS handshake requires one "
            "(ssl.CERT_REQUIRED)")

    if not tls.get("verified"):
        raise AuthenticationError("client certificate failed chain validation")

    if tls.get("issuer") != TRUSTED_CA:
        raise AuthenticationError(
            f"certificate issued by {tls.get('issuer')}, not our trusted CA")

    # Expiry and revocation are the operational weak point of mTLS: certs are
    # long-lived, so a stolen key is usable until CRL/OCSP catches up.
    if tls.get("not_after", 0) < time.time():
        raise AuthenticationError("client certificate expired")
    if tls.get("revoked"):
        raise AuthenticationError("client certificate revoked (CRL/OCSP)")

    subject = tls["subject"]
    if subject not in CERT_ROLES:
        raise AuthenticationError(f"valid cert, but {subject} is not authorized to connect")

    return Principal(
        client=subject.split(",")[0].replace("CN=", ""),
        client_scopes=CERT_ROLES[subject],
        # A certificate is a workload identity. There is no person here.
        user=None,
        auth_method="mTLS client certificate",
        # Channel-scoped: ties to the CONNECTION, not to this request.
        proof=f"tls-channel:{tls.get('connection_id')} (handshake only, "
              f"not per-request)",
    )


server = MCPServer("03 - mTLS  (strong machine auth, channel-scoped, no user)", authenticate)

if __name__ == "__main__":
    future = time.time() + 86400

    good = {"verified": True, "issuer": TRUSTED_CA, "not_after": future,
            "subject": "CN=reporting-agent,OU=agents,O=Example",
            "connection_id": "conn-7f3a"}

    demo(server, [
        ("no client certificate",
         {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
          "params": {"name": "ping"}, "tls": None}),

        ("cert from an untrusted CA  (DENY)",
         {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "ping"},
          "tls": dict(good, issuer="CN=Someone Else CA")}),

        ("expired certificate  (DENY)",
         {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "ping"},
          "tls": dict(good, not_after=time.time() - 10)}),

        ("revoked certificate  (DENY)",
         {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "ping"},
          "tls": dict(good, revoked=True)}),

        ("valid cert -> org tool in scope  (ALLOW)",
         {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
          "params": {"name": "list_reports"}, "tls": good}),

        ("valid cert, workload lacks the role  (DENY - client scope)",
         {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "list_reports"},
          "tls": dict(good, subject="CN=status-agent,OU=agents,O=Example")}),

        ("valid cert -> user-scoped tool  (DENY - a cert is not a person)",
         {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
          "params": {"name": "read_inbox"}, "tls": good}),

        ("valid cert -> user's notes  (DENY - a cert is not a person)",
         {"jsonrpc": "2.0", "id": 8, "method": "resources/read",
          "params": {"uri": "file:///users/me/notes.md"}, "tls": good}),
    ])
    print("\nNOTE: authentication here is genuinely strong -- but it authenticates a\n"
          "      MACHINE, once per connection. No user consent, and no per-request\n"
          "      artifact to show later.")
