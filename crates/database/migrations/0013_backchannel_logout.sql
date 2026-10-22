-- OIDC Back-Channel Logout 1.0: when a session ends, auth posts a logout token to
-- the back-channel logout URI of every client that received tokens from it.

-- NULL for clients that are not told.
ALTER TABLE oidc_clients ADD COLUMN backchannel_logout_uri TEXT;

-- Which clients received tokens from which session, written at code exchange.
CREATE TABLE oidc_session_clients (
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    first_issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, client_id)
);

-- Live sessions already exchanged codes: every redeemed code cleanup still keeps,
-- and every refresh family, records one. A session that only exchanged codes
-- cleanup has deleted, without refresh, is not found. Exchanges the previous release
-- makes while the deploy rolls out are not recorded either.
INSERT INTO oidc_session_clients (session_id, client_id, first_issued_at)
SELECT issued.session_id, issued.client_id, min(issued.created_at)
FROM (
    SELECT session_id, client_id, created_at FROM refresh_token_families
    UNION ALL
    SELECT session_id, client_id, created_at FROM authorization_codes
    WHERE consumed_at IS NOT NULL
) issued
JOIN sessions s ON s.id = issued.session_id
WHERE s.revoked_at IS NULL AND s.expires_at > now()
GROUP BY issued.session_id, issued.client_id;
