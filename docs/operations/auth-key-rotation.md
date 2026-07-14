# Auth key rotation: explicitly deferred

Routine signing-key and service-public-key rotation is **not implemented in the
first version**. The authority currently loads one signing key and publishes
one JWK. Its opaque authorization-code and refresh-token digests also depend on
that key material. Replacing it immediately removes verification for existing
JWTs and invalidates outstanding opaque credentials. Operators must not treat
the current implementation as an overlap-capable rotation mechanism.

Until the follow-up key-lifecycle plan lands, replacement is an emergency-only
operation with an accepted global reauthentication impact. The operator must
revoke active sessions and refresh families, replace the key and `kid`, deploy
the authority, and verify its single published JWK before reopening traffic.

The deferred implementation must introduce an independently managed stable
opaque-token digest key and an active-plus-retired signing-key ring. It must
prove new issuance, old-key verification during overlap, removal only after the
last affected token expires, and refresh continuity. Service public-key overlap
and revocation require the same explicit implementation and tests; runtime
services must never self-register keys.
