"""Shared authorization policy + MCP primitive registry.

Every mechanism folder under `src/` authenticates differently but authorizes the
same way, so the interesting difference between the six servers stays visible:
only the *authentication* half changes.

Two independent questions, per the README's four properties:

  * authentication -> who is calling (the CALLER: agent/app, and the USER, if any)
  * authorization  -> may *that pair* touch this tool/resource/prompt

`Principal` is what a mechanism's authenticator returns. `client` is always
present (something authenticated the connection). `user` is present only when
the mechanism can actually carry a human identity -- API keys and SPIFFE cannot,
so they leave it None, and every user-scoped primitive is then denied.
"""

from dataclasses import dataclass, field
from typing import Optional


class AuthenticationError(Exception):
    """Caller could not be authenticated at all (-> MCP error, HTTP 401)."""


class AuthorizationError(Exception):
    """Caller is known but not permitted (-> MCP error, HTTP 403)."""


@dataclass
class Principal:
    """The authenticated result of one MCP request."""

    client: str                               # the MCP client / agent identity
    client_scopes: set = field(default_factory=set)
    user: Optional[str] = None                # human on whose behalf, if any
    user_claims: dict = field(default_factory=dict)
    user_scopes: set = field(default_factory=set)
    # How the caller proved itself -- recorded on every decision so the audit
    # log can distinguish a bearer secret from a per-request signature.
    auth_method: str = "unknown"
    proof: Optional[str] = None               # non-repudiation artifact, if any

    @property
    def acting_for_user(self) -> bool:
        return self.user is not None


# --- the primitives this server exposes -------------------------------------
#
# `user_required` is the key column: a primitive that touches a person's data
# cannot be served to a client that authenticated only as itself, no matter how
# strong that client authentication was. Machine identity != user consent.

REGISTRY = {
    "tool": {
        "ping": dict(scopes=set(), user_required=False,
                     desc="Liveness check. No caller-specific data."),
        "list_reports": dict(scopes={"reports:read"}, user_required=False,
                             desc="Org-wide report titles. Client scope only."),
        "read_inbox": dict(scopes={"inbox:read"}, user_required=True,
                           desc="The USER's mail. Needs a real person."),
        "send_payment": dict(scopes={"payments:write"}, user_required=True,
                             desc="Moves money for the USER. Highest bar."),
    },
    "resource": {
        "file:///public/handbook.md": dict(scopes=set(), user_required=False,
                                           desc="Public handbook."),
        "file:///reports/q3.csv": dict(scopes={"reports:read"}, user_required=False,
                                       desc="Org report data."),
        "file:///users/me/notes.md": dict(scopes={"notes:read"}, user_required=True,
                                          desc="The USER's private notes."),
    },
    "prompt": {
        "summarize_report": dict(scopes={"reports:read"}, user_required=False,
                                 desc="Summarize an org report."),
        "draft_reply": dict(scopes={"inbox:read"}, user_required=True,
                            desc="Draft a reply as the USER."),
    },
}


def authorize(principal: Principal, kind: str, name: str) -> dict:
    """Gate one MCP primitive. Raises AuthorizationError, or returns its spec.

    Order matters: existence -> user presence -> user scope -> client scope.
    The client check is last and always runs, so a user can never grant more
    than the client itself was issued (delegation cannot escalate).
    """
    table = REGISTRY.get(kind, {})
    if name not in table:
        raise AuthorizationError(f"unknown {kind}: {name}")
    spec = table[name]

    # 1. Does this primitive need a human, and do we have one?
    if spec["user_required"] and not principal.acting_for_user:
        raise AuthorizationError(
            f"{kind} '{name}' acts on user data, but '{principal.client}' "
            f"authenticated only as a client ({principal.auth_method} carries "
            f"no user identity). No user, no access."
        )

    required = spec["scopes"]

    # 2. The user's own grant must cover it (what the human consented to).
    if principal.acting_for_user and not required <= principal.user_scopes:
        raise AuthorizationError(
            f"user '{principal.user}' has not granted {sorted(required - principal.user_scopes)} "
            f"for {kind} '{name}'"
        )

    # 3. The client's grant must cover it too -- intersection, never union.
    if not required <= principal.client_scopes:
        raise AuthorizationError(
            f"client '{principal.client}' lacks {sorted(required - principal.client_scopes)} "
            f"for {kind} '{name}'"
        )

    return spec


def decision_log(principal: Principal, kind: str, name: str, allowed: bool, why: str = "") -> str:
    """One audit line per decision.

    `proof` is what separates the mechanisms at the bottom of the README's
    non-repudiation column: a bearer mechanism has nothing to log but the fact
    that a valid secret arrived, while a per-request signature leaves a durable
    artifact that can be re-verified later.
    """
    verdict = "ALLOW" if allowed else "DENY "
    user = principal.user or "-"
    proof = principal.proof or "none (bearer/transport -- not replayable evidence)"
    return (f"[{verdict}] {kind}:{name} client={principal.client} user={user} "
            f"via={principal.auth_method} proof={proof}" + (f" :: {why}" if why else ""))
