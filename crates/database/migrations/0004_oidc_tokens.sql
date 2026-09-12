CREATE TABLE oidc_clients (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    client_secret_hash BYTEA CHECK (client_secret_hash IS NULL OR octet_length(client_secret_hash)=32),
    trusted BOOLEAN NOT NULL DEFAULT FALSE,
    allowed_scopes JSONB NOT NULL,
    allowed_audiences JSONB NOT NULL,
    allow_refresh BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE oidc_redirect_uris (
    client_id TEXT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    uri TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('authorization', 'post_logout')),
    PRIMARY KEY (client_id, uri, kind)
);

CREATE TABLE authorization_codes (
    id UUID PRIMARY KEY,
    secret_digest BYTEA NOT NULL UNIQUE,
    client_id TEXT NOT NULL REFERENCES oidc_clients(id),
    user_id UUID NOT NULL REFERENCES users(id),
    session_id UUID NOT NULL REFERENCES sessions(id),
    redirect_uri TEXT NOT NULL,
    pkce_challenge TEXT NOT NULL,
    nonce TEXT,
    scopes JSONB NOT NULL,
    audience TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX authorization_codes_active_idx ON authorization_codes (expires_at) WHERE consumed_at IS NULL;

CREATE TABLE authorization_requests (
    id UUID PRIMARY KEY,
    secret_digest BYTEA NOT NULL UNIQUE,
    client_id TEXT NOT NULL REFERENCES oidc_clients(id),
    redirect_uri TEXT NOT NULL,
    client_state TEXT NOT NULL,
    nonce TEXT,
    pkce_challenge TEXT NOT NULL,
    scopes JSONB NOT NULL,
    audience TEXT NOT NULL,
    force_login BOOLEAN NOT NULL,
    force_consent BOOLEAN NOT NULL,
    max_age BIGINT,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX authorization_requests_active_idx ON authorization_requests (expires_at) WHERE consumed_at IS NULL;

CREATE TABLE refresh_token_families (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    client_id TEXT NOT NULL REFERENCES oidc_clients(id),
    session_id UUID NOT NULL REFERENCES sessions(id),
    audience TEXT NOT NULL,
    scopes JSONB NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    family_id UUID NOT NULL REFERENCES refresh_token_families(id) ON DELETE CASCADE,
    secret_digest BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at TIMESTAMPTZ
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);

CREATE TABLE oidc_consents (
    user_id UUID NOT NULL REFERENCES users(id),
    client_id TEXT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    audience TEXT NOT NULL,
    scopes JSONB NOT NULL,
    PRIMARY KEY(user_id, client_id, audience)
);
