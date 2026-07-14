# Auth redaction and retained data

Security audit events retain action, outcome, timestamp, and minimized request
metadata. They never contain passwords, tokens, authorization codes, PKCE
verifiers, WebAuthn challenges, provider access/refresh tokens, or client
secrets. Metrics use bounded outcome and endpoint labels only; they do not use
emails, raw user IDs, headers, or unbounded provider data.

Accepted first-iteration risks are the maximum five-minute access-token tail
after revocation and trusted verified-email assertions from the explicitly
approved GitHub and Google providers. Redis, if introduced, is disposable
coordination only and must never be an authority for identity, session,
revocation, audit, or event state.
