-- OIDC Back-Channel Logout 1.0: when a session ends, auth posts a logout token to
-- the back-channel logout URI of every client that received tokens from it.

-- NULL for clients that are not told.
ALTER TABLE oidc_clients ADD COLUMN backchannel_logout_uri TEXT;

-- Which clients received tokens from which session.
CREATE TABLE oidc_session_clients (
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    first_issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, client_id)
);

-- Every redeemed code records its client, whichever release redeems it: the
-- previous one during a deploy or after a rollback too. An exchange that fails
-- rolls back the redemption, so only clients that received tokens are recorded.
-- It runs as its owner: `migrate` grants the runtime role this table only after
-- the migrations, and the previous release keeps redeeming codes meanwhile.
CREATE FUNCTION oidc_session_clients_record_redeemed_code() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    INSERT INTO oidc_session_clients (session_id, client_id)
    VALUES (NEW.session_id, NEW.client_id)
    ON CONFLICT DO NOTHING;
    RETURN NULL;
END
$$;
CREATE TRIGGER authorization_codes_record_session_client
AFTER UPDATE OF consumed_at ON authorization_codes
FOR EACH ROW WHEN (OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL)
EXECUTE FUNCTION oidc_session_clients_record_redeemed_code();

-- Live sessions that already redeemed codes: every redeemed code cleanup still
-- keeps, and every refresh family, records one. A session that only redeemed codes
-- cleanup has deleted, without refresh, is not found.
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

-- Still untold: sessions the previous release ends during a deploy or after a
-- rollback, since it queues no logout tokens, and logout tokens still queued at a
-- rollback, which are sent only if this release returns within their hour.
