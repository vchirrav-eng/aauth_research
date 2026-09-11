"""MCP server authenticated by API KEY.

  Identity        : the key string maps to an account (coarse)
  Authentication  : weak -- possession of a SHARED secret
  Authorization   : coarse, server-side scopes attached to the key
  Non-repudiation : none -- the log records that *a* valid key arrived

WHAT THE SERVER CAN AND CANNOT KNOW
-----------------------------------
It knows WHICH KEY was used, and therefore which client account. It has no way
whatsoever to learn WHICH USER is behind the call. The key is a long-lived
shared secret; anyone holding it is indistinguishable from the legitimate
client, including the server's own staff who provisioned it.

So every user-scoped primitive (`read_inbox`, `send_payment`, the user's notes,
`draft_reply`) is DENIED -- not because the key lacks a scope, but because
there is no person to authorize on behalf of. Teams usually paper over this by
having the client pass a `user_id` argument; that is self-asserted and the
server cannot verify it, so it is not authentication. This example refuses to
pretend otherwise.
"""

import sys, os, hmac, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_common"))

from mcp_server import MCPServer, demo
from policy import Principal, AuthenticationError

# Store only HASHES -- never the raw keys. A leak of this table must not hand
# an attacker working credentials.
def _h(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

KEYS = {
    _h("sk_live_reporting_9c2f"): dict(client="reporting-agent",
                                       scopes={"reports:read"}),
    _h("sk_live_readonly_41ab"):  dict(client="status-agent", scopes=set()),
}


def authenticate(request) -> Principal:
    """Compare the presented key against the table, in constant time."""
    presented = (request.get("headers") or {}).get("x-api-key")
    if not presented:
        raise AuthenticationError("missing X-API-Key header")

    digest = _h(presented)
    record = None
    for known, value in KEYS.items():
        # hmac.compare_digest avoids leaking which prefix matched via timing.
        if hmac.compare_digest(known, digest):
            record = value
    if record is None:
        raise AuthenticationError("unrecognized API key")

    return Principal(
        client=record["client"],
        client_scopes=record["scopes"],
        # The ceiling of this mechanism: no user, ever.
        user=None,
        auth_method="api-key (shared bearer secret)",
        proof=None,   # nothing signed -> nothing to re-verify later
    )


server = MCPServer("01 - API KEYS  (client identity only, no user)", authenticate)

if __name__ == "__main__":
    K = "sk_live_reporting_9c2f"
    demo(server, [
        ("no key at all",
         {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
          "params": {"name": "ping"}, "headers": {}}),

        ("wrong key",
         {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
          "params": {"name": "ping"}, "headers": {"x-api-key": "sk_live_guess"}}),

        ("valid key -> unscoped tool  (ALLOW)",
         {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
          "params": {"name": "ping"}, "headers": {"x-api-key": K}}),

        ("valid key -> org tool in scope  (ALLOW)",
         {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
          "params": {"name": "list_reports"}, "headers": {"x-api-key": K}}),

        ("key without that scope  (DENY - client scope)",
         {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
          "params": {"name": "list_reports"},
          "headers": {"x-api-key": "sk_live_readonly_41ab"}}),

        ("user-scoped tool  (DENY - no user identity exists)",
         {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
          "params": {"name": "read_inbox"}, "headers": {"x-api-key": K}}),

        ("user's private resource  (DENY - no user identity exists)",
         {"jsonrpc": "2.0", "id": 7, "method": "resources/read",
          "params": {"uri": "file:///users/me/notes.md"}, "headers": {"x-api-key": K}}),

        ("tools/list -- only what this key can actually call",
         {"jsonrpc": "2.0", "id": 8, "method": "tools/list",
          "params": {}, "headers": {"x-api-key": K}}),
    ])
