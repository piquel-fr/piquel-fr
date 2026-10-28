-- Sign-ins to the admin dashboard, which auth serves on its admin listener. An
-- administrator's passkey session on auth hands off to the dashboard with a
-- single-use code, which the dashboard redeems for a session of its own. Only
-- digests of the code and of the dashboard's cookies are stored.
CREATE TABLE dashboard_handoffs (
    code_digest BYTEA PRIMARY KEY,
    -- The auth session handing off, whose sign-in the dashboard session rests on.
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    -- The digest of the dashboard's state cookie in the browser that asked, which
    -- must present it to redeem the code.
    state_digest BYTEA NOT NULL,
    -- The dashboard path the browser goes on to once signed in.
    return_to TEXT NOT NULL,
    -- When a passkey confirmed the handoff, in a ceremony started for it.
    confirmed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX dashboard_handoffs_session_idx ON dashboard_handoffs (session_id);

-- The dashboard's own sessions. Each lasts while its auth session does, and
-- keeps its own passkey confirmation: one done for auth's pages never counts.
CREATE TABLE dashboard_sessions (
    secret_digest BYTEA PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX dashboard_sessions_session_idx ON dashboard_sessions (session_id);

-- The dashboard was the OIDC client `piquel-admin` until auth served it. It is
-- deleted as `auth-service client delete` would, so no deployment keeps it:
-- disabled and marked deleted, its secrets and consents removed, and its refresh
-- grants revoked. Unlike the command, this records no `client_deleted` event:
-- only the service writes events.
WITH client AS (
    UPDATE oidc_clients
    SET deleted_at = now(), enabled = FALSE, updated_at = now()
    WHERE id = 'piquel-admin' AND deleted_at IS NULL
    RETURNING id
),
secrets AS (
    DELETE FROM oidc_client_secrets s USING client WHERE s.client_id = client.id
),
consents AS (
    DELETE FROM oidc_consents c USING client WHERE c.client_id = client.id
)
UPDATE refresh_token_families f
SET revoked_at = now()
FROM client
WHERE f.client_id = client.id AND f.revoked_at IS NULL;
