"""A minimal MCP server core, shared by all five mechanism examples.

Deliberately dependency-free: this is a teaching model of where the checks go in
an MCP server, not a production framework. In a real build you would use the
MCP Python SDK (`mcp.server.Server`) and put the exact same two calls --
`authenticate(...)` then `authorize(...)` -- in the same two places.

THE POINT OF THIS FILE: there is **no MCP gateway** here. The MCP server itself
is the policy enforcement point. Nothing upstream has checked anything, so
every single `tools/call`, `resources/read`, and `prompts/get` must
independently re-derive who is calling. There is no "already authenticated"
state to trust.
"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from policy import (Principal, REGISTRY, authorize, decision_log,
                    AuthenticationError, AuthorizationError)

# MCP/JSON-RPC error codes. -32002 is the code MCP servers use to tell a client
# "you need to authenticate" over a transport that has no HTTP status to send.
E_AUTHN = -32002
E_AUTHZ = -32003
E_METHOD = -32601


class MCPServer:
    """MCP server whose authentication step is supplied by each mechanism.

    `authenticator(request)` -> Principal, or raises AuthenticationError.
    That single injected function is the ONLY difference between the five
    servers in this repo.
    """

    def __init__(self, name, authenticator, on_log=print):
        self.name = name
        self.authenticate = authenticator
        self.on_log = on_log

    # -- the two enforcement points ------------------------------------------

    def handle(self, request):
        """Handle one MCP JSON-RPC request. Every request re-authenticates."""
        method = request.get("method")
        params = request.get("params") or {}
        rid = request.get("id")

        # STEP 1 -- AUTHENTICATION. Who is calling? Runs before anything else,
        # on every request, including listings.
        try:
            principal = self.authenticate(request)
        except AuthenticationError as e:
            self.on_log(f"[DENY ] {method} :: authentication failed :: {e}")
            return self._err(rid, E_AUTHN, f"authentication failed: {e}")

        # Listings are filtered, not gated: the client sees exactly the
        # primitives it could actually invoke. Hiding what you cannot call
        # prevents the agent from planning around a tool it will be denied.
        if method in ("tools/list", "resources/list", "prompts/list"):
            kind = {"tools": "tool", "resources": "resource",
                    "prompts": "prompt"}[method.split("/")[0]]
            return self._ok(rid, {method.split("/")[0]: self._visible(principal, kind)})

        dispatch = {
            "tools/call":     ("tool",     params.get("name")),
            "resources/read": ("resource", params.get("uri")),
            "prompts/get":    ("prompt",   params.get("name")),
        }
        if method not in dispatch:
            return self._err(rid, E_METHOD, f"unknown method: {method}")
        kind, name = dispatch[method]

        # STEP 2 -- AUTHORIZATION. May this caller, acting for this user,
        # use this specific primitive?
        try:
            authorize(principal, kind, name)
        except AuthorizationError as e:
            self.on_log(decision_log(principal, kind, name, False, str(e)))
            return self._err(rid, E_AUTHZ, f"authorization denied: {e}")

        self.on_log(decision_log(principal, kind, name, True))
        return self._ok(rid, self._invoke(principal, kind, name, params))

    # -- helpers --------------------------------------------------------------

    def _visible(self, principal, kind):
        out = []
        for name, spec in REGISTRY[kind].items():
            try:
                authorize(principal, kind, name)
            except AuthorizationError:
                continue
            out.append({"name": name, "description": spec["desc"]})
        return out

    def _invoke(self, principal, kind, name, params):
        """Stand-in for real work -- echoes the identity the work ran under."""
        if kind == "resource":
            return {"contents": [{"uri": name, "mimeType": "text/plain",
                                  "text": f"<contents of {name} for "
                                          f"{principal.user or principal.client}>"}]}
        if kind == "prompt":
            return {"messages": [{"role": "user", "content": {"type": "text",
                     "text": f"<prompt {name} rendered for "
                             f"{principal.user or principal.client}>"}}]}
        return {"content": [{"type": "text",
                             "text": f"<{name} executed as client={principal.client} "
                                     f"user={principal.user or 'none'}>"}],
                "isError": False}

    def _ok(self, rid, result):
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    def _err(self, rid, code, message):
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def demo(server, cases):
    """Run labelled requests through a server and print the outcome of each."""
    print(f"\n{'=' * 74}\n  {server.name}\n{'=' * 74}")
    for label, request in cases:
        print(f"\n--- {label}")
        resp = server.handle(request)
        if "error" in resp:
            print(f"    -> ERROR {resp['error']['code']}: {resp['error']['message']}")
        else:
            print(f"    -> OK {json.dumps(resp['result'])[:180]}")
