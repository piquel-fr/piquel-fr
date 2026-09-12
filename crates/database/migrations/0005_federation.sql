CREATE TABLE external_login_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_name TEXT NOT NULL CHECK (provider_name IN ('github', 'google')),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    linked_email TEXT,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);
-- Unlinking releases a provider subject, but keeps its audit history.
CREATE UNIQUE INDEX external_identity_active_subject ON external_login_identities(issuer,subject) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX external_identity_active_provider ON external_login_identities(user_id,provider_name) WHERE revoked_at IS NULL;

CREATE TABLE federation_transactions (
    id UUID PRIMARY KEY,
    provider_name TEXT NOT NULL CHECK (provider_name IN ('github', 'google')),
    state_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(state_digest)=32),
    browser_digest BYTEA NOT NULL CHECK (octet_length(browser_digest)=32),
    nonce TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    return_to TEXT NOT NULL,
    link_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    link_session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((link_user_id IS NULL) = (link_session_id IS NULL))
);
CREATE INDEX federation_transactions_expiry_idx ON federation_transactions(expires_at);

-- No user or normal session exists while social signup is pending. The browser
-- must finish its first passkey before this identity can be committed.
CREATE TABLE pending_federation (
    id UUID PRIMARY KEY,
    browser_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(browser_digest)=32),
    provider_name TEXT NOT NULL CHECK (provider_name IN ('github','google')),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    email TEXT,
    display_name TEXT NOT NULL,
    return_to TEXT NOT NULL,
    link_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    link_session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (link_session_id IS NULL OR link_user_id IS NOT NULL)
);
CREATE INDEX pending_federation_expiry_idx ON pending_federation(expires_at);
