CREATE TABLE passkey_credentials (
    id UUID PRIMARY KEY,
    credential_id BYTEA NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential JSONB NOT NULL,
    signature_counter BIGINT NOT NULL DEFAULT 0 CHECK (signature_counter >= 0),
    transports JSONB NOT NULL DEFAULT '[]'::jsonb,
    backup_eligible BOOLEAN NOT NULL,
    backup_state BOOLEAN NOT NULL,
    friendly_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX passkey_credentials_active_user_idx ON passkey_credentials (user_id, created_at) WHERE revoked_at IS NULL;

-- Ceremony records are deliberately server-side and short lived. Their digest
-- prevents challenge material from appearing in persistent state or logs.
CREATE TABLE webauthn_ceremonies (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    ceremony_kind TEXT NOT NULL CHECK (ceremony_kind IN ('registration', 'authentication')),
    challenge_digest BYTEA NOT NULL,
    state JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX webauthn_ceremonies_expiry_idx ON webauthn_ceremonies (expires_at) WHERE consumed_at IS NULL;

CREATE TABLE browser_session_secrets (
    session_id UUID PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    secret_digest BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
