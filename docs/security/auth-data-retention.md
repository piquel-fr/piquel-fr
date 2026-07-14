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

Auth-service owns a bounded cleanup job. Every 15 minutes it removes at most
500 rows per ephemeral table in a transaction, then returns to serving traffic.
Expired or consumed WebAuthn ceremonies, federation transactions,
authorization continuations, and authorization codes are retained for at most
one additional day. Revoked or expired browser-session secrets and refresh
tokens are retained for at most one additional day. Empty refresh families are
eligible after revocation plus one day or creation plus 31 days; sessions are
removed only after their dependent codes and refresh families are gone. Audit
events and the transactional event log are not deleted by this job.

The cleanup interval and batch size are availability controls, not compliance
retention promises. Operators must alert on repeated cleanup failure and
database growth; any future deletion of audit or event records needs a separate
approved retention policy.
