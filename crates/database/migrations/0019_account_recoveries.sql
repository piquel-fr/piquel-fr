-- Recoveries an administrator or operator started for an account whose owner lost
-- their passkeys. Each sends its owner a link that enrolls one passkey, once,
-- within a day. The link's token is derived from the recovery's ID, so only its
-- digest is stored. The owner can undo a recovery with a passkey enrolled before
-- it started.
CREATE TABLE account_recoveries (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_digest BYTEA NOT NULL UNIQUE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    -- When its link enrolled a passkey, and which one.
    completed_at TIMESTAMPTZ,
    passkey_id UUID,
    -- When a newer recovery replaced it before its link was used.
    cancelled_at TIMESTAMPTZ,
    -- When the owner undid it.
    undone_at TIMESTAMPTZ,
    CHECK ((completed_at IS NULL) = (passkey_id IS NULL))
);
CREATE INDEX account_recoveries_user_idx ON account_recoveries (user_id, started_at DESC);
