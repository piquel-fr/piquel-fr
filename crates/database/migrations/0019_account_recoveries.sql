-- Recoveries an administrator or operator started for an account whose owner lost
-- their passkeys. Each sends its owner a link that enrolls one passkey, once,
-- within a day. The link's token is derived from the recovery's ID, so only its
-- digest is stored. The owner can undo a recovery with a passkey enrolled before
-- it started, which takes back what the account gained since.
CREATE TABLE account_recoveries (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_digest BYTEA NOT NULL UNIQUE,
    -- The primary address when it started, which undoing it restores. Not a
    -- foreign key: the address may be removed meanwhile.
    primary_email_id UUID,
    -- The clock when it was stored, after its transaction took the account lock,
    -- so recoveries sort in the order they happened; `now()` would be when the
    -- transaction began.
    started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    -- When its link enrolled a passkey, and which one.
    completed_at TIMESTAMPTZ,
    passkey_id UUID,
    -- When a newer recovery, or disabling the account, replaced it before its
    -- link was used.
    cancelled_at TIMESTAMPTZ,
    -- When it was undone, by its owner or by support.
    undone_at TIMESTAMPTZ,
    CHECK ((completed_at IS NULL) = (passkey_id IS NULL)),
    CHECK (cancelled_at IS NULL OR (completed_at IS NULL AND undone_at IS NULL))
);
CREATE INDEX account_recoveries_user_idx ON account_recoveries (user_id, started_at DESC);
-- At most one recovery per account whose link was not used, replaced or undone.
-- An expired one counts until the next replaces it.
CREATE UNIQUE INDEX account_recoveries_one_open_idx ON account_recoveries (user_id)
    WHERE completed_at IS NULL AND cancelled_at IS NULL AND undone_at IS NULL;

-- When each consent was last given or extended. Undoing an account recovery
-- withdraws the consents given since it started, which an app the recovery's
-- holder approved could otherwise use to sign in again without asking.
ALTER TABLE oidc_consents ADD COLUMN granted_at TIMESTAMPTZ NOT NULL DEFAULT now();
