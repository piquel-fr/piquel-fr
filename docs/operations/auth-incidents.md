# Auth incident response

For refresh-token replay, revoke the affected family in one transaction, retain
the sanitized audit record, and return only a generic invalid-grant response.
Existing access JWTs may remain valid for their accepted five-minute tail.

For an auth outage, fail closed for new authentication and token issuance;
resource servers may continue to validate unexpired access JWTs locally. Do not
copy raw tokens, authorization codes, WebAuthn challenges, or provider callback
parameters into tickets, dashboards, or logs.

After restoring a backup, validate user IDs, verified-email ownership, active
sessions, refresh-family revocation, and internal-event aggregate sequences
before accepting production traffic.
