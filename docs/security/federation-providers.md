# Approved social identity providers

The first iteration permits exactly two providers: GitHub and Google. Their
durable external identities are `(https://github.com, subject)` and
`(https://accounts.google.com, subject)` respectively; an email is never a
durable provider key.

Automatic linking requires a provider-asserted, usable verified email. GitHub
adapters must obtain that assertion from the authenticated email endpoint and
must not treat an unverified profile email as verified. Google adapters must
validate the ID token issuer, signature, audience, nonce, expiry, and its
`email_verified` claim. Both providers use state, nonce, and PKCE; client
secrets remain secret references and are never logged or stored in PostgreSQL.
