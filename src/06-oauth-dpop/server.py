"""MCP server authenticated by OAUTH 2.1 + DPoP (RFC 9449).

  Identity        : `client_id` = which app; OIDC `sub` = which user
  Authentication  : bearer REPLACED by a per-request proof-of-possession JWT
  Authorization   : the same OAuth scopes and consent as 02-oauth-oidc
  Non-repudiation : good -- a stolen token is inert without the private key

WHAT CHANGES FROM 02-oauth-oidc
-------------------------------
Only the credential check. The flow, the scopes, the consent screen and the
claims are identical -- which is the point: DPoP is an upgrade you can apply to
an OAuth deployment you already run, without new infrastructure.

Two headers instead of one:

    Authorization: DPoP <access_token>     <- note: NOT "Bearer"
    DPoP: <proof JWT, typ "dpop+jwt">

The access token carries `cnf.jkt` -- the SHA-256 thumbprint of a public key the
client generated and never sent. The proof JWT carries that public key in its
`jwk` header and is signed by the matching private key. The server checks the
thumbprints match, so the token is only usable by whoever holds the key.

WHAT THE PROOF COVERS -- AND WHAT IT DOES NOT
---------------------------------------------
`htm` (method), `htu` (URI), `iat` (freshness), `jti` (replay), and `ath`
(hash of the access token). That stops token theft, cross-endpoint replay, and
proof reuse.

It does NOT cover the request BODY. For an MCP server that matters: every
`tools/call` goes to the same method and URI, so one captured proof is valid for
any tool name within its freshness window. An attacker who can alter the body in
flight can swap `read_inbox` for `send_payment` and the proof still verifies.
The demo below shows exactly this -- it is the one attack this server cannot
reject, and the reason 05-aauth additionally signs a `content-digest`.

Mitigations in practice: short `iat` windows, a server-issued `DPoP-Nonce`, and
keeping the transport authenticated (TLS) so bodies cannot be tampered with.
"""

import sys, os, json, time, base64, hashlib, hmac
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_common"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.exceptions import InvalidSignature

from mcp_server import MCPServer, demo
from policy import Principal, AuthenticationError

ISSUER = "https://as.example.com"
THIS_MCP_SERVER = "https://mcp.example.com"
THIS_URI = "https://mcp.example.com/mcp"     # the `htu` we require
MAX_PROOF_AGE = 60                           # seconds; RFC 9449 says keep it small

_AS_KEY = b"demo-authorization-server-signing-key"
_seen_jti = set()                            # replay cache; Redis with a TTL in production


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jkt(jwk: dict) -> str:
    """RFC 7638 JWK SHA-256 thumbprint -- the value that lands in `cnf.jkt`."""
    canonical = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
                           separators=(",", ":"), sort_keys=True)
    return _b64u(hashlib.sha256(canonical.encode()).digest())


def mint_access_token(claims: dict, bound_jwk: dict) -> str:
    """The AS issues a token PINNED to the client's key via `cnf.jkt`."""
    header = _b64u(json.dumps({"alg": "HS256", "typ": "at+jwt"}).encode())
    claims = dict(claims, cnf={"jkt": _jkt(bound_jwk)})
    payload = _b64u(json.dumps(claims).encode())
    sig = _b64u(hmac.new(_AS_KEY, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def authenticate(request) -> Principal:
    """Validate the DPoP-bound access token AND its per-request proof."""
    headers = request.get("headers") or {}
    authz = headers.get("authorization", "")

    # A DPoP deployment must REFUSE the Bearer scheme. Accepting both would let
    # an attacker downgrade a bound token back into a stealable one.
    if authz.startswith("Bearer "):
        raise AuthenticationError(
            "Bearer scheme refused -- this resource issues DPoP-bound tokens "
            '(WWW-Authenticate: DPoP error="invalid_token")')
    if not authz.startswith("DPoP "):
        raise AuthenticationError(
            'missing DPoP-bound token -- WWW-Authenticate: DPoP algs="EdDSA ES256"')
    if "dpop" not in headers:
        raise AuthenticationError("missing DPoP proof header")

    access_token = authz[len("DPoP "):]

    # --- 1. Validate the access token itself (as in 02-oauth-oidc) ----------
    try:
        at_h, at_p, at_s = access_token.split(".")
    except ValueError:
        raise AuthenticationError("malformed access token")

    expected = _b64u(hmac.new(_AS_KEY, f"{at_h}.{at_p}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, at_s):
        raise AuthenticationError("access token signature invalid")

    claims = json.loads(_unb64u(at_p))
    if claims.get("iss") != ISSUER:
        raise AuthenticationError(f"untrusted issuer {claims.get('iss')}")
    aud = claims.get("aud")
    if THIS_MCP_SERVER not in (aud if isinstance(aud, list) else [aud]):
        raise AuthenticationError(f"token audience {aud} is not this server")
    if claims.get("exp", 0) < time.time():
        raise AuthenticationError("access token expired")

    # The token MUST be bound. An unbound token here is a misconfigured AS.
    bound_jkt = (claims.get("cnf") or {}).get("jkt")
    if not bound_jkt:
        raise AuthenticationError(
            "access token has no `cnf.jkt` -- refusing to accept an unbound token")

    # --- 2. Validate the DPoP proof ----------------------------------------
    try:
        p_h, p_p, p_s = headers["dpop"].split(".")
        proof_header = json.loads(_unb64u(p_h))
        proof = json.loads(_unb64u(p_p))
    except (ValueError, KeyError):
        raise AuthenticationError("malformed DPoP proof JWT")

    if proof_header.get("typ") != "dpop+jwt":
        raise AuthenticationError(
            f"proof typ is {proof_header.get('typ')}, expected dpop+jwt")
    # `alg` must be asymmetric: "none" or an HMAC would let anyone mint proofs.
    if proof_header.get("alg") in (None, "none", "HS256", "HS384", "HS512"):
        raise AuthenticationError(f"proof alg {proof_header.get('alg')} is not acceptable")

    jwk = proof_header.get("jwk")
    if not jwk:
        raise AuthenticationError("proof header carries no `jwk` public key")
    if "d" in jwk:
        raise AuthenticationError("proof `jwk` must not contain a private key")

    # --- 3. THE BINDING CHECK: proof key must match the token's cnf.jkt -----
    # This single comparison is what makes the token non-transferable.
    if not hmac.compare_digest(_jkt(jwk), bound_jkt):
        raise AuthenticationError(
            "proof key thumbprint does not match the access token `cnf.jkt` -- "
            "the caller does not hold the key this token was issued to")

    # --- 4. Verify the proof signature over its own JWT --------------------
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise AuthenticationError("demo supports Ed25519 proofs only")
    try:
        Ed25519PublicKey.from_public_bytes(_unb64u(jwk["x"])).verify(
            _unb64u(p_s), f"{p_h}.{p_p}".encode())
    except InvalidSignature:
        raise AuthenticationError("DPoP proof signature does not verify")

    # --- 5. Bind the proof to THIS request ---------------------------------
    if proof.get("htm") != request.get("method_http"):
        raise AuthenticationError(
            f"proof htm={proof.get('htm')} does not match this request")
    # `htu` is compared without query or fragment, per RFC 9449.
    if proof.get("htu") != THIS_URI:
        raise AuthenticationError(
            f"proof htu={proof.get('htu')} is for a different endpoint -- "
            f"a proof captured elsewhere cannot be reused here")

    age = time.time() - proof.get("iat", 0)
    if age > MAX_PROOF_AGE:
        raise AuthenticationError(f"proof too old ({int(age)}s) -- outside the freshness window")
    if age < -30:
        raise AuthenticationError("proof `iat` is in the future -- clock skew or forgery")

    # `ath` ties the proof to this exact access token, so a proof captured with
    # one token cannot be paired with another.
    ath = _b64u(hashlib.sha256(access_token.encode("ascii")).digest())
    if proof.get("ath") != ath:
        raise AuthenticationError(
            "proof `ath` does not match the presented access token")

    jti = proof.get("jti")
    if not jti:
        raise AuthenticationError("proof has no `jti`")
    if jti in _seen_jti:
        raise AuthenticationError(f"DPoP proof replayed (jti={jti})")
    _seen_jti.add(jti)

    # --- 6. Identity, exactly as in 02-oauth-oidc --------------------------
    granted = set((claims.get("scope") or "").split())
    sub = claims.get("sub")
    is_user_flow = sub is not None and sub != claims.get("client_id")

    return Principal(
        client=claims.get("client_id", "unknown-client"),
        client_scopes=granted,
        user=sub if is_user_flow else None,
        user_claims={k: claims[k] for k in ("name", "email", "email_verified")
                     if k in claims},
        user_scopes=granted if is_user_flow else set(),
        auth_method="OAuth 2.1 + DPoP (RFC 9449, sender-constrained)",
        # A real per-request artifact -- but scoped to method/URI/token, never
        # to the body. Strong against theft; not a signature over content.
        proof=f"dpop-proof jti={jti} htm={proof.get('htm')} htu={proof.get('htu')} "
              f"jkt={bound_jkt[:16]}...",
    )


server = MCPServer("06 - OAUTH 2.1 + DPoP  (sender-constrained, no mTLS needed)", authenticate)


# ---------------------------------------------------------------------------
# Demo -- real Ed25519 keys, so every ALLOW/DENY below is genuine.
# ---------------------------------------------------------------------------

def make_proof(private_key, jwk, htm, htu, access_token=None, iat=None, jti=None,
               typ="dpop+jwt"):
    header = {"typ": typ, "alg": "EdDSA", "jwk": jwk}
    payload = {"jti": jti or _b64u(os.urandom(16)), "htm": htm, "htu": htu,
               "iat": int(iat if iat is not None else time.time())}
    if access_token:
        payload["ath"] = _b64u(hashlib.sha256(access_token.encode("ascii")).digest())
    h, p = _b64u(json.dumps(header).encode()), _b64u(json.dumps(payload).encode())
    sig = private_key.sign(f"{h}.{p}".encode())
    return f"{h}.{p}.{_b64u(sig)}"


if __name__ == "__main__":
    client_key = Ed25519PrivateKey.generate()
    client_jwk = {"kty": "OKP", "crv": "Ed25519",
                  "x": _b64u(client_key.public_key().public_bytes_raw())}

    # An attacker who stole the token but holds a different key.
    thief_key = Ed25519PrivateKey.generate()
    thief_jwk = {"kty": "OKP", "crv": "Ed25519",
                 "x": _b64u(thief_key.public_key().public_bytes_raw())}

    now = int(time.time())
    base = dict(iss=ISSUER, aud=THIS_MCP_SERVER, client_id="calendar-agent",
                iat=now, exp=now + 300)

    user_token = mint_access_token(dict(base, sub="user_8871", name="Vis Chirravuri",
                                        email="vis@example.com", email_verified=True,
                                        scope="reports:read inbox:read notes:read"),
                                   client_jwk)

    def req(rid, method, params, token=user_token, key=client_key, jwk=client_jwk,
            htu=THIS_URI, iat=None, jti=None, ath_token=None, typ="dpop+jwt"):
        return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params,
                "method_http": "POST",
                "headers": {"authorization": f"DPoP {token}",
                            "dpop": make_proof(key, jwk, "POST", htu,
                                               ath_token or token, iat, jti, typ)}}

    demo(server, [
        ("no credentials",
         {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
          "params": {"name": "ping"}, "headers": {}, "method_http": "POST"}),

        ("Bearer scheme on a DPoP resource  (DENY - no downgrade)",
         {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "ping"},
          "method_http": "POST", "headers": {"authorization": f"Bearer {user_token}"}}),

        ("valid token + valid proof -> user tool  (ALLOW)",
         req(3, "tools/call", {"name": "read_inbox"})),

        ("valid token + valid proof -> user's notes  (ALLOW)",
         req(4, "resources/read", {"uri": "file:///users/me/notes.md"})),

        ("payment  (DENY - scope never consented)",
         req(5, "tools/call", {"name": "send_payment"})),

        ("STOLEN token, thief's own key  (DENY - cnf.jkt binding)",
         req(6, "tools/call", {"name": "read_inbox"}, key=thief_key, jwk=thief_jwk)),

        ("proof captured for another endpoint  (DENY - htu)",
         req(7, "tools/call", {"name": "read_inbox"}, htu="https://other.example.com/api")),

        ("stale proof  (DENY - iat outside the window)",
         req(8, "tools/call", {"name": "read_inbox"}, iat=time.time() - 600)),

        ("proof paired with a different token  (DENY - ath)",
         req(9, "tools/call", {"name": "read_inbox"},
             ath_token="some.other.token")),

        ("proof with typ=JWT instead of dpop+jwt  (DENY)",
         req(10, "tools/call", {"name": "read_inbox"}, typ="JWT")),
    ])

    # Replay needs the same jti twice.
    print("\n--- replayed DPoP proof, same jti  (DENY - replay cache)")
    fixed = req(11, "tools/call", {"name": "read_inbox"}, jti="fixed-jti-abc123")
    server.handle(fixed)
    again = req(12, "tools/call", {"name": "read_inbox"}, jti="fixed-jti-abc123")
    r = server.handle(again)
    print(f"    -> ERROR {r['error']['code']}: {r['error']['message']}")

    # The limit of DPoP: the proof does not cover the body.
    print("\n--- body swapped read_inbox -> send_payment, proof untouched")
    tampered = req(13, "tools/call", {"name": "read_inbox"})
    tampered["params"] = {"name": "send_payment"}
    r = server.handle(tampered)
    verdict = "DENIED" if "error" in r else "ACCEPTED"
    detail = r["error"]["message"] if "error" in r else json.dumps(r["result"])[:120]
    print(f"    -> proof still VERIFIES (htm/htu/ath/jti all unchanged);")
    print(f"       request {verdict} at the AUTHORIZATION step: {detail}")

    print("\nNOTE: DPoP defeats token THEFT -- but the proof covers method, URI and\n"
          "      token hash, never the body. Here the swap was caught only because the\n"
          "      user lacked `payments:write`; had they held it, the tampered call would\n"
          "      have gone through. 05-aauth signs a content-digest to close this.")
