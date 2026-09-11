# API keys

`X-API-Key: sk_live_...` -> the server hashes it, looks it up, and gets a **client account**.

## What the MCP server learns
- **Client:** which key-holder. Coarse -- one key per app, not per caller.
- **User:** *nothing.* There is no place in this mechanism for a person.

## Authorization
Scopes attached to the key record. Every user-scoped tool, resource and prompt is **denied** --
not for lack of a scope, but because there is no person to act for. The common workaround is
having the client pass `user_id` as a tool argument; that is **self-asserted and unverifiable**,
so this example refuses to treat it as identity.

## Failure modes shown
missing key, unknown key, valid key without the scope, valid key reaching for user data.

## Notes
- Keys are stored **hashed**, compared with `hmac.compare_digest` (constant time).
- Nothing is signed, so the audit log can only say *a valid key arrived* -- no non-repudiation.
