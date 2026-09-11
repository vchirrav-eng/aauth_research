"""MCP server authenticated by AAUTH -- per-request RFC 9421 signatures.

  Identity        : agent identity from a published key; person identity via PS
  Authentication  : PER-REQUEST RFC 9421 signature -- proves key possession
                    on every call. NOT a bearer token.
  Authorization   : built-in modes + a human consent ceremony
  Non-repudiation : STRONG -- every request leaves a detached signature

WHAT MAKES THIS DIFFERENT FROM 01-04
------------------------------------
In the four previous servers the credential IS the secret: whoever holds it can
use it. Here the credential is a signature computed over THIS request, with a
private key the server never sees. There is nothing in the request worth
stealing -- replaying it reproduces only the same method, authority and path,
and only until `created` ages out.

That gives the server two things at once:

  * the AGENT identity, from the `aa-agent+jwt` in `Signature-Key`, and
  * the USER identity, once the person has consented, from the `aa-auth+jwt`
    the person server issued -- carrying `sub`, `email`, `name`, `scope`.

...and a durable artifact: the signature bytes, re-verifiable later against the
agent's published JWKS. That is the non-repudiation column.

THE TWO-CALL SHAPE (no gateway -- this server drives the ceremony itself)
------------------------------------------------------------------------
Wire details below follow ~/.aauth/fetch/logs/walkthrough-2.jsonl exactly.

  call 1: agent signs with its `aa-agent+jwt`
          -> 401 + `AAuth-Requirement: requirement=auth-token; resource-token="..."`
             (this server MINTS that `aa-resource+jwt`, aud = the agent's `ps`)
  ...     agent POSTs it to the PS `token_endpoint`; person consents; PS returns
          an `aa-auth+jwt` bound via `cnf` to the agent's ephemeral key
  call 2: agent signs with the `aa-auth+jwt` in `Signature-Key`
          -> 200, and the server now knows agent AND user

CRITICAL CHECK -- `cnf` BINDING
-------------------------------
The auth token names an ephemeral public key in `cnf.jwk`. The server verifies
the request signature WITH THAT KEY. So the token is useless to anyone who does
not hold the matching private key: stealing the JWT gets an attacker nothing.
This is the single line that turns a JWT from a bearer into a bound credential.
"""

import sys, os, json, time, base64, hashlib, secrets
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_common"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.exceptions import InvalidSignature

from mcp_server import MCPServer, demo
from policy import Principal, AuthenticationError

THIS_RESOURCE = "https://mcp.example.com"
MAX_SIGNATURE_AGE = 300          # seconds; bounds replay of a captured request

# Person servers whose identity assertions this resource accepts. In PS-asserted
# mode this list IS the trust decision: we believe `sub`/`email` because we
# chose to trust this PS.
TRUSTED_PERSON_SERVERS = {"https://person.hello.coop"}

# Agent issuers we will talk to, and what the AGENT itself may do. The agent's
# ceiling applies even after a person consents -- delegation cannot escalate.
AGENT_POLICY = {
    "https://vchirrav-eng.github.io/aauth_research": {
        "reports:read", "inbox:read", "notes:read"},
}

_seen_jti = set()               # replay cache; Redis with a TTL in production


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jwt_parts(token: str):
    h, p, s = token.split(".")
    return json.loads(_unb64u(h)), json.loads(_unb64u(p)), (f"{h}.{p}".encode(), _unb64u(s))


def _jwk_to_key(jwk: dict) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise AuthenticationError(f"unsupported key type {jwk.get('kty')}/{jwk.get('crv')}")
    return Ed25519PublicKey.from_public_bytes(_unb64u(jwk["x"]))


def _jkt(jwk: dict) -> str:
    """RFC 7638 thumbprint -- how `agent_jkt` in the resource token is formed."""
    canonical = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
                           separators=(",", ":"), sort_keys=True)
    return _b64u(hashlib.sha256(canonical.encode()).digest())


def _signature_base(request, covered, created) -> bytes:
    """Reconstruct the RFC 9421 signature base the client signed.

    Derived components come from the request itself -- so a signature made for
    GET /a cannot be replayed onto POST /b. The base is rebuilt server-side and
    never taken from the caller.
    """
    headers = request.get("headers", {})
    lines = []
    for item in covered:
        if item == "@method":
            lines.append(f'"@method": {request["method_http"]}')
        elif item == "@authority":
            lines.append(f'"@authority": {request["authority"]}')
        elif item == "@path":
            lines.append(f'"@path": {request["path"]}')
        else:
            lines.append(f'"{item}": {headers.get(item, "")}')
    params = f'({" ".join(chr(34) + c + chr(34) for c in covered)});created={created}'
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines).encode()


def mint_resource_token(agent_claims: dict, agent_jwk: dict, scope: str) -> str:
    """Mint the `aa-resource+jwt` returned in the 401 `AAuth-Requirement`.

    Audience is the agent's OWN person server (`ps`), because the agent is about
    to present this token there. `agent_jkt` pins the agent's ephemeral key, so
    the PS issues an auth token bound to the same key -- that is what stops the
    agent from swapping in someone else's key mid-ceremony.
    """
    header = {"alg": "EdDSA", "typ": "aa-resource+jwt", "kid": "mcp-server-2026-06"}
    now = int(time.time())
    payload = {
        "iss": THIS_RESOURCE,
        "dwk": "aauth-resource.json",
        "aud": agent_claims["ps"],
        "jti": secrets.token_urlsafe(16),
        "agent": agent_claims["sub"],
        "agent_jkt": _jkt(agent_jwk),
        "scope": scope,
        "iat": now,
        "exp": now + 300,
    }
    # Signed with the resource's own key (omitted here: the agent never
    # verifies it -- the PS does, via our published aauth-resource.json).
    return f"{_b64u(json.dumps(payload).encode())}.{_b64u(json.dumps(header).encode())}.demo"


class AAuthRequired(AuthenticationError):
    """401 carrying the resource token -- starts the three-party ceremony."""


def authenticate(request) -> Principal:
    """Verify the RFC 9421 signature, then read identity from the bound JWT."""
    headers = request.get("headers") or {}
    for h in ("signature", "signature-input", "signature-key"):
        if h not in headers:
            raise AuthenticationError(f"missing {h} header -- AAuth signs every request")

    # --- 1. Parse Signature-Input: which components, and when ---------------
    sig_input = headers["signature-input"]
    covered = [c.strip('"') for c in
               sig_input.split("(", 1)[1].split(")", 1)[0].split()]
    created = int(sig_input.split("created=")[1].split(";")[0].strip())

    # Freshness. A captured request is replayable only inside this window --
    # and only as the identical method+authority+path.
    age = time.time() - created
    if age > MAX_SIGNATURE_AGE:
        raise AuthenticationError(f"signature too old ({int(age)}s) -- replay window exceeded")
    if age < -60:
        raise AuthenticationError("signature `created` is in the future -- clock skew or forgery")

    # `signature-key` MUST be covered, or the JWT could be swapped for another
    # while keeping a valid signature over the rest of the request.
    if "signature-key" not in covered:
        raise AuthenticationError(
            "`signature-key` is not in the covered components -- the token could be swapped")

    # --- 2. Extract the JWT from Signature-Key ------------------------------
    raw = headers["signature-key"]
    token = raw.split('jwt="', 1)[1].rsplit('"', 1)[0]
    header_j, claims, (signing_input, sig_bytes) = _jwt_parts(token)
    typ = header_j.get("typ")

    # --- 3. The cnf binding: which key must have signed this request? -------
    # Both token types carry `cnf.jwk`. THIS is the bound-vs-bearer line.
    cnf_jwk = (claims.get("cnf") or {}).get("jwk")
    if not cnf_jwk:
        raise AuthenticationError("token has no `cnf` binding -- refusing to treat it as a bearer")
    verify_key = _jwk_to_key(cnf_jwk)

    # --- 4. Verify the per-request signature --------------------------------
    # RFC 9421 wraps the signature in colons as a byte-sequence literal,
    # standard-base64 encoded (not base64url).
    sig_hdr = headers["signature"]
    presented = base64.b64decode(sig_hdr.split(":", 1)[1].rsplit(":", 1)[0])
    base = _signature_base(request, covered, created)
    try:
        verify_key.verify(presented, base)
    except InvalidSignature:
        raise AuthenticationError(
            "RFC 9421 signature does not verify against the key in `cnf` -- "
            "the caller does not possess the bound private key")

    # Replay cache. Keyed on the SIGNATURE, not the token's `jti`: one token is
    # reused across many legitimate requests, but each request signs a distinct
    # base, so identical signature bytes mean a genuine replay. Entries need
    # only live as long as MAX_SIGNATURE_AGE -- after that, freshness rejects
    # the request anyway.
    # If a content-digest was signed, it must match the body we actually got.
    # The signature covers the DIGEST header; only recomputing it over the real
    # payload ties the signature to this request's content.
    if "content-digest" in covered:
        body = {k: request[k] for k in ("jsonrpc", "id", "method", "params")
                if k in request}
        raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
        want = base64.b64encode(hashlib.sha256(raw).digest()).decode()
        got = headers.get("content-digest", "")
        if f"sha-256=:{want}:" != got:
            raise AuthenticationError(
                "content-digest does not match the request body -- payload altered in flight")

    marker = hashlib.sha256(presented).hexdigest()
    if marker in _seen_jti:
        raise AuthenticationError(
            f"replayed request -- this exact signature was already used "
            f"(jti={claims.get('jti')}, created={created})")
    _seen_jti.add(marker)

    if claims.get("exp", 0) < time.time():
        raise AuthenticationError("token expired")

    # --- 5. Branch on token type -------------------------------------------
    if typ == "aa-agent+jwt":
        # Agent identity only. The person has not consented yet.
        issuer = claims.get("iss")
        if issuer not in AGENT_POLICY:
            raise AuthenticationError(f"unknown agent issuer {issuer}")

        ps = claims.get("ps")
        if ps not in TRUSTED_PERSON_SERVERS:
            raise AuthenticationError(
                f"agent's person server {ps} is not trusted by this resource")

        # Identity-Based mode: the agent alone is enough for non-user work.
        # For anything user-scoped we answer 401 + resource-token, which is
        # what starts the three-party flow. (Raised by the wrapper below.)
        return Principal(
            client=claims["sub"],
            client_scopes=AGENT_POLICY[issuer],
            user=None,
            auth_method="AAuth agent token (aa-agent+jwt) + RFC 9421 signature",
            proof=f"rfc9421-sig over {covered} created={created} "
                  f"key={_jkt(cnf_jwk)[:16]}...",
        )

    if typ == "aa-auth+jwt":
        # PS-asserted mode: a person consented, and the PS vouches for them.
        iss = claims.get("iss")
        if iss not in TRUSTED_PERSON_SERVERS:
            raise AuthenticationError(f"auth token issued by untrusted person server {iss}")

        # Audience: this token was minted for US. Without this a token consented
        # for another resource replays here.
        if claims.get("aud") != THIS_RESOURCE:
            raise AuthenticationError(
                f"auth token audience {claims.get('aud')} is not this resource")

        # `agent` / `act.agent` record WHICH agent the person authorized. The
        # agent's own ceiling still applies -- consent cannot grant the agent
        # more than the agent was ever allowed.
        agent_id = claims.get("agent") or (claims.get("act") or {}).get("agent")
        agent_issuer = "https://" + agent_id.split("@", 1)[1] + "/aauth_research" \
            if agent_id and "@" in agent_id else None
        agent_ceiling = AGENT_POLICY.get(agent_issuer, set())

        granted = set((claims.get("scope") or "").split())
        # Map AAuth scopes onto this server's primitive scopes.
        SCOPE_MAP = {"whoami": set(), "openid": set(), "profile": set(),
                     "inbox": {"inbox:read"}, "notes": {"notes:read"},
                     "reports": {"reports:read"}}
        user_scopes = set()
        for s in granted:
            user_scopes |= SCOPE_MAP.get(s, {s})

        return Principal(
            client=agent_id or "unknown-agent",
            client_scopes=agent_ceiling,
            user=claims["sub"],
            user_claims={k: claims[k] for k in
                         ("name", "email", "email_verified", "tenant", "picture")
                         if k in claims},
            user_scopes=user_scopes,
            auth_method="AAuth person auth token (aa-auth+jwt) + RFC 9421 signature",
            proof=f"rfc9421-sig over {covered} created={created} "
                  f"jti={claims.get('jti')} ps={iss}",
        )

    raise AuthenticationError(f"unexpected token typ: {typ}")


def authenticate_with_ceremony(request) -> Principal:
    """Wrap authentication so an agent-only caller gets the 401 + resource token.

    With no gateway in front, minting that resource token is this server's job.
    """
    principal = authenticate(request)
    if principal.acting_for_user:
        return principal

    # Agent authenticated but no person yet. If the target needs a user, answer
    # with the requirement instead of a bare denial, so the agent knows how to
    # proceed rather than simply failing.
    from policy import REGISTRY
    params = request.get("params") or {}
    kind, name = {"tools/call": ("tool", params.get("name")),
                  "resources/read": ("resource", params.get("uri")),
                  "prompts/get": ("prompt", params.get("name"))
                  }.get(request.get("method"), (None, None))

    if kind and REGISTRY.get(kind, {}).get(name, {}).get("user_required"):
        token = headers_agent_token(request)
        raise AAuthRequired(
            f'auth_token_required -- AAuth-Requirement: requirement=auth-token; '
            f'resource-token="{token[:48]}..." '
            f'(POST it to the person server token_endpoint, then re-call)')

    return principal


def headers_agent_token(request) -> str:
    """Mint the resource token for the agent that just called."""
    raw = request["headers"]["signature-key"]
    token = raw.split('jwt="', 1)[1].rsplit('"', 1)[0]
    _, claims, _ = _jwt_parts(token)
    return mint_resource_token(claims, claims["cnf"]["jwk"], "whoami openid profile inbox")


server = MCPServer("05 - AAUTH  (per-request signature; agent + person, bound)",
                   authenticate_with_ceremony)


# ---------------------------------------------------------------------------
# Demo: builds REAL Ed25519 signatures so the verification above is genuine.
# ---------------------------------------------------------------------------

def _sign_request(private_key, token, method, authority, path, body=None, covered=None):
    """Sign one request the way an AAuth client does.

    `content-digest` (RFC 9530) is covered whenever there is a body -- an MCP
    call's identity lives in its JSON-RPC payload, so signing only
    method+authority+path would let a captured signature be reattached to a
    DIFFERENT tools/call on the same endpoint.
    """
    covered = covered or ["@method", "@authority", "@path", "signature-key"]
    headers = {"signature-key": f'sig=jwt;jwt="{token}"'}
    if body is not None:
        raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
        headers["content-digest"] = f"sha-256=:{base64.b64encode(hashlib.sha256(raw).digest()).decode()}:"
        covered = covered + ["content-digest"]
    created = int(time.time())
    request = {
        "method_http": method, "authority": authority, "path": path,
        "headers": dict(headers, **{"signature-input":
            f'sig=({" ".join(chr(34)+c+chr(34) for c in covered)});created={created}'}),
    }
    base = _signature_base(request, covered, created)
    sig = private_key.sign(base)
    request["headers"]["signature"] = f"sig=:{base64.b64encode(sig).decode()}:"
    return request


def _make_jwt(header, payload):
    return f"{_b64u(json.dumps(header).encode())}.{_b64u(json.dumps(payload).encode())}.demo-sig"


if __name__ == "__main__":
    # The agent's ephemeral key -- the one `cnf` binds to.
    agent_key = Ed25519PrivateKey.generate()
    agent_jwk = {"kty": "OKP", "crv": "Ed25519",
                 "x": _b64u(agent_key.public_key().public_bytes_raw())}
    now = int(time.time())

    agent_token = _make_jwt(
        {"alg": "EdDSA", "typ": "aa-agent+jwt", "kid": "2026-06-26_53f"},
        {"iss": "https://vchirrav-eng.github.io/aauth_research",
         "dwk": "aauth-agent.json",
         "sub": "aauth:local@vchirrav-eng.github.io",
         "jti": secrets.token_urlsafe(12), "cnf": {"jwk": agent_jwk},
         "iat": now, "exp": now + 3600, "ps": "https://person.hello.coop"})

    # What the person server returns after the human consents -- bound via
    # `cnf` to the SAME ephemeral key.
    auth_token = _make_jwt(
        {"alg": "EdDSA", "typ": "aa-auth+jwt", "kid": "2026-06-06T22:58:53.808Z_19f"},
        {"iss": "https://person.hello.coop", "dwk": "aauth-person.json",
         "jti": secrets.token_urlsafe(12),
         "sub": "sub_06ArJ53rsMNNtysCNieAP8Iu_7JR",
         "aud": THIS_RESOURCE,
         "agent": "aauth:local@vchirrav-eng.github.io",
         "act": {"agent": "aauth:local@vchirrav-eng.github.io"},
         "scope": "whoami inbox notes", "tenant": "personal",
         "name": "Vis Chirravuri", "email": "vchirrav@gmail.com",
         "email_verified": True, "cnf": {"jwk": agent_jwk},
         "iat": now, "exp": now + 3600})

    def req(rid, method, params, token, key=agent_key, path="/mcp"):
        """Build a signed MCP request, digest and all."""
        body = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        r = _sign_request(key, token, "POST", "mcp.example.com", path, body=body)
        r.update(body)
        return r

    # An attacker who STOLE the auth token but has no matching private key.
    attacker_key = Ed25519PrivateKey.generate()

    demo(server, [
        ("unsigned request",
         {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
          "params": {"name": "ping"}, "headers": {}}),

        ("agent token -> non-user tool  (ALLOW - Identity-Based mode)",
         req(2, "tools/call", {"name": "list_reports"}, agent_token)),

        ("agent token -> user tool  (401 + resource-token: ceremony starts)",
         req(3, "tools/call", {"name": "read_inbox"}, agent_token)),

        ("person-issued auth token -> user tool  (ALLOW - consented)",
         req(4, "tools/call", {"name": "read_inbox"}, auth_token)),

        ("auth token -> user's private notes  (ALLOW)",
         req(5, "resources/read", {"uri": "file:///users/me/notes.md"}, auth_token)),

        ("auth token -> payment  (DENY - person never consented to that scope)",
         req(6, "tools/call", {"name": "send_payment"}, auth_token)),

        ("STOLEN auth token, attacker's key  (DENY - cnf binding holds)",
         req(7, "tools/call", {"name": "read_inbox"}, auth_token, key=attacker_key)),
    ])

    # The last two cases reuse one request twice, so they are driven by hand.
    print("\n--- REPLAYED byte-identical request  (DENY - replay cache)")
    replay = req(8, "tools/call", {"name": "read_inbox"}, auth_token)
    server.handle(replay)                       # first time: accepted
    r = server.handle(replay)                   # same bytes again
    print(f"    -> ERROR {r['error']['code']}: {r['error']['message']}")

    print("\n--- signature captured for /mcp, replayed at /admin  (DENY - @path covered)")
    captured = req(9, "tools/call", {"name": "read_inbox"}, auth_token)
    captured["path"] = "/admin"                 # attacker moves it to another path
    r = server.handle(captured)
    print(f"    -> ERROR {r['error']['code']}: {r['error']['message']}")

    print("\n--- valid signature, body swapped read_inbox -> send_payment  "
          "(DENY - content-digest)")
    tampered = req(10, "tools/call", {"name": "read_inbox"}, auth_token)
    tampered["params"] = {"name": "send_payment"}   # signature left untouched
    r = server.handle(tampered)
    print(f"    -> ERROR {r['error']['code']}: {r['error']['message']}")

    print("\nNOTE: nothing in these requests is worth stealing. The token is bound by\n"
          "      `cnf` to a key the server never sees, and every call carries its own\n"
          "      signature -- a durable artifact that can be re-verified later.")
