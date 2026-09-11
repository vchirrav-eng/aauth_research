# SPIFFE / SPIRE

Workload identity. SPIRE **attests** the workload first -- which container image, which k8s
service account -- then issues a short-lived SVID that rotates every few minutes.

## What SPIFFE adds over plain mTLS
Not a stronger proof: a better **issuance** story. No hand-provisioned certificate sitting on disk
for a year; a leaked credential expires in minutes.

## What it still does not add
A **user**. A SPIFFE ID names a workload. No person, no consent, nothing to delegate -- so
user-scoped primitives are denied, as in `01` and `03`.

## Both SVID types, side by side
| | Proof | Is it a JWT? | Stolen credential |
|---|---|---|---|
| **X.509-SVID** | key possession at handshake (mTLS) | **no** | useless without the key |
| **JWT-SVID** | bearer | **yes** | **replayable for its lifetime** |

The X.509 form (not a JWT) is **stronger** than the JWT form (a JWT) -- the root README's point
that encoding and strength are independent axes, in one file.

`aud` checking on a JWT-SVID is therefore mandatory, and the example shows a JWT-SVID minted for
`.../sa/billing` being rejected here.

## Failure modes shown
no SVID, foreign trust domain, expired SVID, unregistered workload, wrong JWT-SVID audience, and
`ns/staging` vs `ns/prod` resolving to genuinely different identities.
