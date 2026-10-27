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

