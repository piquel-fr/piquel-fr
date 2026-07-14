CREATE TABLE external_login_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_name TEXT NOT NULL CHECK (provider_name IN ('github', 'google')),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    linked_email TEXT NOT NULL,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (issuer, subject)
);
CREATE INDEX external_login_identities_user_idx ON external_login_identities (user_id) WHERE revoked_at IS NULL;

CREATE TABLE federation_transactions (
    id UUID PRIMARY KEY,
    provider_name TEXT NOT NULL CHECK (provider_name IN ('github', 'google')),
    state_digest BYTEA NOT NULL UNIQUE,
    browser_digest BYTEA NOT NULL,
    nonce TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX federation_transactions_expiry_idx ON federation_transactions(expires_at) WHERE consumed_at IS NULL;
