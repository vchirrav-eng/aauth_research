"""MCP server authenticated by SPIFFE / SPIRE workload identity.

  Identity        : a SPIFFE ID, issued after workload ATTESTATION
  Authentication  : an SVID -- X.509-SVID (mTLS) or JWT-SVID (bearer)
  Authorization   : external policy engine, keyed by SPIFFE ID
  Non-repudiation : limited -- mTLS channel ceiling, or JWT-SVID bearer ceiling

WHAT SPIFFE ADDS OVER PLAIN mTLS
--------------------------------
Not a different proof -- a different ISSUANCE story. With plain mTLS somebody
manually provisioned a cert and hoped the private key stayed put. SPIRE attests
the workload first (which kernel PID, which container image, which k8s service
account) and only then issues a short-lived SVID, rotated every few minutes.
So the identity is automatic, and a leaked credential expires almost at once.

What SPIFFE does NOT add: a user. A SPIFFE ID names a WORKLOAD. There is no
person, no consent, nothing to delegate. User-scoped primitives are denied here
for the same reason as API keys and mTLS.

THE TWO SVID TYPES SIT AT DIFFERENT STRENGTHS -- both are handled below:

  X.509-SVID : presented via mTLS. Key possession proven at handshake.
               Channel-scoped, like 03-mtls. NOT a JWT.
  JWT-SVID   : a bearer JWT. Convenient across L7 proxies, but stealable and
               replayable for its (short) lifetime. IS a JWT -- and is weaker
               than the X.509 form, which is exactly the README's point that
               "is it a JWT" says nothing about strength.

`aud` checking on a JWT-SVID is mandatory: without it, any service that can
obtain a JWT-SVID for its own use can replay it against this MCP server.
"""

import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_common"))

from mcp_server import MCPServer, demo
from policy import Principal, AuthenticationError

TRUST_DOMAIN = "spiffe://example.org"
THIS_SERVER_SPIFFE_ID = "spiffe://example.org/ns/prod/sa/mcp-server"

# The external policy engine, keyed by SPIFFE ID (OPA / SPIRE registration
# entries in production). The SVID says WHO; this table says WHAT.
POLICY = {
    "spiffe://example.org/ns/prod/sa/reporting-agent": {"reports:read"},
    "spiffe://example.org/ns/prod/sa/status-agent": set(),
    # Same workload name, different namespace -- a distinct identity.
    "spiffe://example.org/ns/staging/sa/reporting-agent": set(),
}


def authenticate(request) -> Principal:
    """Accept either SVID form and normalize both to one Principal."""
    svid = request.get("svid")
    if not svid:
        raise AuthenticationError(
            "no SVID presented -- expected an X.509-SVID via mTLS or a "
            "JWT-SVID bearer token")

    svid_type = svid.get("type")
    spiffe_id = svid.get("spiffe_id", "")

    # Common to both forms: the ID must come from the trust domain we federate
    # with. A SPIFFE ID from another trust domain is a different organization.
    if not spiffe_id.startswith(TRUST_DOMAIN + "/"):
        raise AuthenticationError(
            f"SPIFFE ID {spiffe_id} is outside trust domain {TRUST_DOMAIN}")

    if svid.get("expires_at", 0) < time.time():
        # SVIDs are short-lived by design -- minutes, not months.
        raise AuthenticationError("SVID expired (SPIRE rotates these continuously)")

    if svid_type == "x509":
        # Verified by the TLS stack against the SPIRE trust bundle.
        if not svid.get("chain_verified"):
            raise AuthenticationError("X.509-SVID failed validation against the trust bundle")
        auth_method = "SPIFFE X.509-SVID (mTLS, not a JWT)"
        proof = (f"tls-channel:{svid.get('connection_id')} "
                 f"(handshake only, not per-request)")

    elif svid_type == "jwt":
        # Verified against the SPIRE JWKS bundle.
        if not svid.get("signature_valid"):
            raise AuthenticationError("JWT-SVID signature invalid")
        # MANDATORY: a JWT-SVID is a bearer token. Without an audience check any
        # holder of any JWT-SVID in the trust domain can replay it here.
        audience = svid.get("aud") or []
        if THIS_SERVER_SPIFFE_ID not in audience:
            raise AuthenticationError(
                f"JWT-SVID audience {audience} does not include this server "
                f"-- refusing a token minted for another service")
        auth_method = "SPIFFE JWT-SVID (bearer JWT)"
        proof = None   # bearer: stealable for its lifetime, no durable artifact

    else:
        raise AuthenticationError(f"unknown SVID type: {svid_type}")

    if spiffe_id not in POLICY:
        raise AuthenticationError(
            f"attested workload {spiffe_id} has no policy entry on this server")

    return Principal(
        client=spiffe_id.rsplit("/", 1)[-1],
        client_scopes=POLICY[spiffe_id],
        # A workload identity. No human anywhere in this flow.
        user=None,
        auth_method=auth_method,
        proof=proof,
    )


server = MCPServer("04 - SPIFFE / SPIRE  (attested workload identity, no user)", authenticate)

if __name__ == "__main__":
    later = time.time() + 300

    x509 = {"type": "x509", "spiffe_id": "spiffe://example.org/ns/prod/sa/reporting-agent",
            "chain_verified": True, "expires_at": later, "connection_id": "conn-11c9"}

    jwt = {"type": "jwt", "spiffe_id": "spiffe://example.org/ns/prod/sa/reporting-agent",
           "signature_valid": True, "expires_at": later,
           "aud": [THIS_SERVER_SPIFFE_ID]}

    demo(server, [
        ("no SVID",
         {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
          "params": {"name": "ping"}, "svid": None}),

        ("SVID from a foreign trust domain  (DENY)",
         {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "ping"},
          "svid": dict(x509, spiffe_id="spiffe://evil.org/ns/prod/sa/reporting-agent")}),

        ("expired SVID  (DENY)",
         {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "ping"},
          "svid": dict(x509, expires_at=time.time() - 1)}),

        ("X.509-SVID -> org tool in scope  (ALLOW)",
         {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
          "params": {"name": "list_reports"}, "svid": x509}),

        ("same name, staging namespace -> different identity  (DENY - scope)",
         {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "list_reports"},
          "svid": dict(x509, spiffe_id="spiffe://example.org/ns/staging/sa/reporting-agent")}),

        ("JWT-SVID with correct audience  (ALLOW)",
         {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
          "params": {"name": "list_reports"}, "svid": jwt}),

        ("JWT-SVID minted for another service  (DENY - audience replay)",
         {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "list_reports"},
          "svid": dict(jwt, aud=["spiffe://example.org/ns/prod/sa/billing"])}),

        ("X.509-SVID -> user-scoped tool  (DENY - a workload is not a person)",
         {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
          "params": {"name": "read_inbox"}, "svid": x509}),

        ("resources/list -- no user, so no user resources are even visible",
         {"jsonrpc": "2.0", "id": 9, "method": "resources/list",
          "params": {}, "svid": x509}),
    ])
    print("\nNOTE: the X.509-SVID (not a JWT) is STRONGER than the JWT-SVID (a JWT).\n"
          "      'Is it a JWT' describes the encoding, not the security.")
