-- Initial authentication schema. Released migrations are immutable; later
-- schema changes go in new numbered files.

----------------------------------------------------------------------------
-- Accounts and verified email ownership
----------------------------------------------------------------------------

CREATE TABLE users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    profile_version BIGINT NOT NULL DEFAULT 1 CHECK (profile_version > 0),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_emails (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    normalized_email TEXT NOT NULL,
    verified_at TIMESTAMPTZ,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (NOT is_primary OR verified_at IS NOT NULL)
);
CREATE INDEX user_emails_user_id_idx ON user_emails (user_id);
CREATE INDEX user_emails_verified_lookup_idx ON user_emails (normalized_email) WHERE verified_at IS NOT NULL;
CREATE UNIQUE INDEX user_emails_one_primary_verified_idx ON user_emails (user_id) WHERE is_primary AND verified_at IS NOT NULL;

-- One row per verified address of an active account. The normalized address is
-- the unique lockable key, which makes concurrent first claims safe. Triggers
-- below keep it in sync with user_emails and users.status.
CREATE TABLE active_verified_email_ownership (
    normalized_email TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

-- Claims ownership when an active account gains a verified address.
CREATE FUNCTION claim_active_verified_email() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE account_active BOOLEAN;
BEGIN
    IF NEW.verified_at IS NOT NULL THEN
        -- Serialize email claims with status changes. Without this row lock an
        -- insert can observe an active account, wait behind disablement, and
        -- recreate ownership after the account has become disabled. NO KEY UPDATE
        -- still admits foreign-key checks, which FOR UPDATE would deadlock with.
        SELECT status = 'active' INTO account_active
        FROM users WHERE id = NEW.user_id FOR NO KEY UPDATE;
        IF account_active THEN
            INSERT INTO active_verified_email_ownership(normalized_email, user_id)
            VALUES (NEW.normalized_email, NEW.user_id)
            ON CONFLICT (normalized_email) DO UPDATE SET user_id = EXCLUDED.user_id
            WHERE active_verified_email_ownership.user_id = EXCLUDED.user_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'verified email already belongs to an active account' USING ERRCODE = 'unique_violation';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER user_emails_claim_active_verified
    BEFORE INSERT OR UPDATE OF normalized_email, verified_at, user_id ON user_emails
    FOR EACH ROW EXECUTE FUNCTION claim_active_verified_email();

-- Releases ownership once no verified row of the owner still holds the address.
-- AFTER triggers see the updated table, including an unchanged verified row.
CREATE FUNCTION release_active_verified_email() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.verified_at IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM user_emails e JOIN users u ON u.id=e.user_id
        WHERE e.user_id=OLD.user_id AND e.normalized_email=OLD.normalized_email
          AND e.verified_at IS NOT NULL AND u.status='active'
    ) THEN
        DELETE FROM active_verified_email_ownership
        WHERE normalized_email=OLD.normalized_email AND user_id=OLD.user_id;
    END IF;
    RETURN OLD;
END $$;
CREATE TRIGGER user_emails_release_active_verified
    AFTER DELETE OR UPDATE OF normalized_email, verified_at, user_id ON user_emails
    FOR EACH ROW EXECUTE FUNCTION release_active_verified_email();

-- Disabling an account releases its addresses; reactivating reclaims them and
-- fails if another active account claimed one in the meantime.
CREATE FUNCTION synchronize_user_email_ownership() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE address TEXT;
BEGIN
    IF NEW.status='disabled' THEN
        DELETE FROM active_verified_email_ownership WHERE user_id=NEW.id;
    ELSIF OLD.status='disabled' AND NEW.status='active' THEN
        FOR address IN SELECT DISTINCT normalized_email FROM user_emails WHERE user_id=NEW.id AND verified_at IS NOT NULL LOOP
            INSERT INTO active_verified_email_ownership(normalized_email,user_id) VALUES(address,NEW.id)
            ON CONFLICT(normalized_email) DO UPDATE SET user_id=EXCLUDED.user_id
            WHERE active_verified_email_ownership.user_id=EXCLUDED.user_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'verified email already belongs to an active account' USING ERRCODE='unique_violation';
            END IF;
        END LOOP;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER users_synchronize_email_ownership
    BEFORE UPDATE OF status ON users
    FOR EACH ROW EXECUTE FUNCTION synchronize_user_email_ownership();

-- An account with verified emails has exactly one verified primary, checked at commit.
CREATE FUNCTION enforce_primary_verified_email() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    affected UUID;
    affected_users UUID[];
BEGIN
    IF TG_OP = 'INSERT' THEN affected_users := ARRAY[NEW.user_id];
    ELSIF TG_OP = 'DELETE' THEN affected_users := ARRAY[OLD.user_id];
    ELSE affected_users := ARRAY[NEW.user_id, OLD.user_id];
    END IF;

    FOREACH affected IN ARRAY affected_users LOOP
        IF EXISTS (SELECT 1 FROM user_emails WHERE user_id=affected AND verified_at IS NOT NULL)
           AND (SELECT count(*) FROM user_emails WHERE user_id=affected AND verified_at IS NOT NULL AND is_primary) <> 1
        THEN RAISE EXCEPTION 'verified emails require exactly one primary' USING ERRCODE='check_violation'; END IF;
    END LOOP;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER user_emails_exactly_one_primary
    AFTER INSERT OR UPDATE OR DELETE ON user_emails
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION enforce_primary_verified_email();

----------------------------------------------------------------------------
-- Sessions and audit
----------------------------------------------------------------------------

-- management_expires_at is a short, session-bound window for account changes.
CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    authentication_methods JSONB NOT NULL,
    authenticated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    user_agent_family TEXT,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    management_expires_at TIMESTAMPTZ,
    CHECK (expires_at > authenticated_at)
);
CREATE INDEX sessions_active_user_idx ON sessions (user_id, expires_at) WHERE revoked_at IS NULL;

-- Browser cookies are stored only as digests.
CREATE TABLE browser_session_secrets (
    session_id UUID PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    secret_digest BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE security_audit_log (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    action TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'rejected')),
    request_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX security_audit_log_user_created_idx ON security_audit_log (user_id, created_at DESC);

----------------------------------------------------------------------------
-- Passkeys
----------------------------------------------------------------------------

CREATE TABLE passkey_credentials (
    id UUID PRIMARY KEY,
    credential_id BYTEA NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential JSONB NOT NULL,
    friendly_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX passkey_credentials_active_user_idx ON passkey_credentials (user_id, created_at) WHERE revoked_at IS NULL;

-- Ceremony state includes the challenge and is stored server-side until expiry.
-- It is never accepted twice and must never appear in logs.
CREATE TABLE webauthn_ceremonies (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    ceremony_kind TEXT NOT NULL CHECK (ceremony_kind IN ('registration', 'authentication', 'enrollment', 'purpose_authentication')),
    challenge_digest BYTEA NOT NULL,
    state JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX webauthn_ceremonies_expiry_idx ON webauthn_ceremonies (expires_at) WHERE consumed_at IS NULL;

----------------------------------------------------------------------------
-- OIDC clients, authorization and consent
----------------------------------------------------------------------------

-- Clients are provisioned from static configuration at startup.
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

-- A validated authorization request, resumed across login and consent.
-- hinted_user_id keeps the requested subject across that resumption.
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
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    hinted_user_id UUID
);
CREATE INDEX authorization_requests_active_idx ON authorization_requests (expires_at) WHERE consumed_at IS NULL;

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

CREATE TABLE oidc_consents (
    user_id UUID NOT NULL REFERENCES users(id),
    client_id TEXT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    audience TEXT NOT NULL,
    scopes JSONB NOT NULL,
    PRIMARY KEY (user_id, client_id, audience)
);

----------------------------------------------------------------------------
-- Refresh tokens
----------------------------------------------------------------------------

-- A family groups every rotation of one grant; revoking it ends the grant.
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
CREATE INDEX refresh_families_session_idx ON refresh_token_families (session_id);
CREATE INDEX refresh_families_active_user_idx ON refresh_token_families (user_id) WHERE revoked_at IS NULL;

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    family_id UUID NOT NULL REFERENCES refresh_token_families(id) ON DELETE CASCADE,
    secret_digest BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at TIMESTAMPTZ
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);

----------------------------------------------------------------------------
-- Social login federation
----------------------------------------------------------------------------

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
CREATE UNIQUE INDEX external_identity_active_subject ON external_login_identities (issuer, subject) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX external_identity_active_provider ON external_login_identities (user_id, provider_name) WHERE revoked_at IS NULL;

-- An in-flight provider redirect, bound to the initiating browser.
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
CREATE INDEX federation_transactions_expiry_idx ON federation_transactions (expires_at);

-- No user or normal session exists while social signup is pending. The browser
-- must finish its first passkey before this identity can be committed.
CREATE TABLE pending_federation (
    id UUID PRIMARY KEY,
    browser_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(browser_digest)=32),
    provider_name TEXT NOT NULL CHECK (provider_name IN ('github', 'google')),
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
CREATE INDEX pending_federation_expiry_idx ON pending_federation (expires_at);

----------------------------------------------------------------------------
-- Invitations and rate limits
----------------------------------------------------------------------------

CREATE TABLE invitations (
    secret_digest BYTEA PRIMARY KEY CHECK (octet_length(secret_digest) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    redeemed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Fixed-window request counters shared by every service process.
CREATE TABLE request_limits (
    bucket BYTEA PRIMARY KEY,
    requests INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
