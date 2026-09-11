"""MCP server authenticated by OAUTH 2.1 / OIDC -- MCP's path today.

  Identity        : `client_id` = which app; OIDC `sub` = which user
  Authentication  : the AS minted the token after a PKCE + consent flow
  Authorization   : strong and standard -- scopes, consent, revocable, short exp
  Non-repudiation : partial -- the access token is still a BEARER token

WHAT THE SERVER CAN AND CANNOT KNOW
-----------------------------------
This is the first mechanism that carries BOTH identities in one credential: the
access token's `client_id`/`azp` names the app, and `sub` names the human who
sat through the consent screen. So user-scoped tools become possible.

The ceiling is that the token is a bearer: the server verifies the token was
validly *issued*, never that the caller *possesses* any key. A copied token
replays perfectly. That is why `proof` stays None -- the audit log can only say
"a valid token for sub=... arrived", which the real user can plausibly deny.
(DPoP or mTLS binding raises this ceiling; see 03-mtls and 05-aauth.)

As an MCP server with NO gateway, this server is also the OAuth *resource
server*: it must publish RFC 9728 protected-resource metadata and answer an
unauthorized call with a `WWW-Authenticate` challenge pointing at its AS.
"""

import sys, os, json, time, base64, hashlib, hmac
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_common"))

from mcp_server import MCPServer, demo
from policy import Principal, AuthenticationError

ISSUER = "https://as.example.com"
THIS_MCP_SERVER = "https://mcp.example.com"   # our own `aud` -- must be checked

# RFC 9728: how an MCP client discovers where to get a token. Served at
# /.well-known/oauth-protected-resource. See metadata.json in this folder.
PROTECTED_RESOURCE_METADATA = {
    "resource": THIS_MCP_SERVER,
    "authorization_servers": [ISSUER],
    "scopes_supported": ["reports:read", "inbox:read", "notes:read", "payments:write"],
    "bearer_methods_supported": ["header"],
}

# Demo only: a shared HMAC stands in for fetching the AS's JWKS and verifying
# RS256/EdDSA. Verification is otherwise identical in shape.
_AS_KEY = b"demo-authorization-server-signing-key"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mint_access_token(claims: dict) -> str:
    """Stands in for the Authorization Server after a PKCE + consent flow."""
    header = _b64u(json.dumps({"alg": "HS256", "typ": "at+jwt"}).encode())
    payload = _b64u(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = _b64u(hmac.new(_AS_KEY, signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def authenticate(request) -> Principal:
    """Validate the bearer access token and split it into client + user identity."""
    auth = (request.get("headers") or {}).get("authorization", "")
    if not auth.startswith("Bearer "):
        # RFC 9728 challenge: tells the client WHERE to authenticate. Without a
        # gateway, emitting this correctly is the MCP server's own job.
        raise AuthenticationError(
            f'missing bearer token -- WWW-Authenticate: Bearer '
            f'resource_metadata="{THIS_MCP_SERVER}/.well-known/oauth-protected-resource"')

    token = auth[len("Bearer "):]
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise AuthenticationError("malformed JWT")

    # 1. Signature -- in production: fetch the AS JWKS, match `kid`, verify.
    expected = _b64u(hmac.new(_AS_KEY, f"{header_b64}.{payload_b64}".encode(),
                              hashlib.sha256).digest())
    if not hmac.compare_digest(expected, sig_b64):
        raise AuthenticationError("bad signature -- not issued by our AS")

    claims = json.loads(_unb64u(payload_b64))

    # 2. Issuer -- must be the AS we actually trust.
    if claims.get("iss") != ISSUER:
        raise AuthenticationError(f"untrusted issuer {claims.get('iss')}")

    # 3. Audience -- THE classic MCP mistake. A token minted for a different
    #    resource must be rejected, or any service sharing the AS can replay
    #    its tokens here (the "confused deputy" problem).
    aud = claims.get("aud")
    aud = aud if isinstance(aud, list) else [aud]
    if THIS_MCP_SERVER not in aud:
        raise AuthenticationError(
            f"token audience {aud} is not this server -- refusing a token minted elsewhere")

    # 4. Expiry -- bearer tokens must be short-lived precisely because they
    #    are stealable.
    if claims.get("exp", 0) < time.time():
        raise AuthenticationError("token expired")

    granted = set((claims.get("scope") or "").split())

    # The user is present only if a human actually authenticated at the AS.
    # client_credentials grants have no `sub` -> machine-to-machine, no user.
    sub = claims.get("sub")
    is_user_flow = sub is not None and sub != claims.get("client_id")

    return Principal(
        client=claims.get("client_id") or claims.get("azp", "unknown-client"),
        client_scopes=granted,
        user=sub if is_user_flow else None,
        user_claims={k: claims[k] for k in ("name", "email", "email_verified")
                     if k in claims},
        # With OAuth the consented scopes are one set covering both parties;
        # the user's grant IS the token's scope.
        user_scopes=granted if is_user_flow else set(),
        auth_method="oauth2.1 bearer access token",
        proof=None,   # bearer -- possession is not proven, so no durable artifact
    )


server = MCPServer("02 - OAUTH 2.1 / OIDC  (client + user, but bearer)", authenticate)

if __name__ == "__main__":
    now = int(time.time())
    base = dict(iss=ISSUER, aud=THIS_MCP_SERVER, client_id="calendar-agent",
                iat=now, exp=now + 300)

    user_token = mint_access_token(dict(base,
        sub="user_8871", name="Vis Chirravuri", email="vis@example.com",
        email_verified=True, scope="reports:read inbox:read notes:read"))

    # A client_credentials token: app only, no human behind it.
    machine_token = mint_access_token(dict(base, scope="reports:read"))

    # Same AS, different resource -- must NOT be accepted here.
    wrong_aud = mint_access_token(dict(base, aud="https://other-api.example.com",
                                       sub="user_8871", scope="inbox:read"))

    expired = mint_access_token(dict(base, sub="user_8871",
                                     exp=now - 60, scope="inbox:read"))

    H = lambda t: {"authorization": f"Bearer {t}"}
    demo(server, [
        ("no token -> RFC 9728 challenge",
         {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
          "params": {"name": "ping"}, "headers": {}}),

        ("token minted for another resource  (DENY - audience)",
         {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
          "params": {"name": "read_inbox"}, "headers": H(wrong_aud)}),

        ("expired token  (DENY)",
         {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
          "params": {"name": "read_inbox"}, "headers": H(expired)}),

        ("user token -> user-scoped tool  (ALLOW - consented)",
         {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
          "params": {"name": "read_inbox"}, "headers": H(user_token)}),

        ("user token -> user's private notes  (ALLOW)",
         {"jsonrpc": "2.0", "id": 5, "method": "resources/read",
          "params": {"uri": "file:///users/me/notes.md"}, "headers": H(user_token)}),

        ("user token -> prompt needing inbox:read  (ALLOW)",
         {"jsonrpc": "2.0", "id": 6, "method": "prompts/get",
          "params": {"name": "draft_reply"}, "headers": H(user_token)}),

        ("user token -> payment  (DENY - scope never consented)",
         {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
          "params": {"name": "send_payment"}, "headers": H(user_token)}),

        ("client_credentials token -> user tool  (DENY - no user)",
         {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
          "params": {"name": "read_inbox"}, "headers": H(machine_token)}),

        ("client_credentials token -> org tool  (ALLOW)",
         {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
          "params": {"name": "list_reports"}, "headers": H(machine_token)}),
    ])
    print("\nNOTE: every token above is a BEARER token. Copy the header value and "
          "it works\n      from anywhere -- nothing binds it to this caller.")
