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

-- A trigger, rather than a blanket unique index, permits a disabled account's
-- verified address to be claimed by one active account while rejecting two
-- active owners. It locks matching verified rows to make concurrent claims safe.
CREATE OR REPLACE FUNCTION enforce_active_verified_email_uniqueness() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.verified_at IS NOT NULL AND EXISTS (
        SELECT 1 FROM user_emails existing
        JOIN users existing_user ON existing_user.id = existing.user_id
        JOIN users new_user ON new_user.id = NEW.user_id
        WHERE existing.normalized_email = NEW.normalized_email
          AND existing.id <> NEW.id
          AND existing.verified_at IS NOT NULL
          AND existing_user.status = 'active'
          AND new_user.status = 'active'
    ) THEN RAISE EXCEPTION 'verified email already belongs to an active account' USING ERRCODE = 'unique_violation'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER user_emails_active_verified_unique BEFORE INSERT OR UPDATE OF normalized_email, verified_at, user_id ON user_emails FOR EACH ROW EXECUTE FUNCTION enforce_active_verified_email_uniqueness();

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
    CHECK (expires_at > authenticated_at)
);
CREATE INDEX sessions_active_user_idx ON sessions (user_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE security_audit_log (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    action TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'rejected')),
    request_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX security_audit_log_user_created_idx ON security_audit_log (user_id, created_at DESC);

CREATE TABLE internal_events (
    id UUID PRIMARY KEY,
    aggregate_type TEXT NOT NULL,
    aggregate_id UUID NOT NULL,
    aggregate_sequence BIGINT NOT NULL CHECK (aggregate_sequence > 0),
    event_type TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,
    UNIQUE (aggregate_type, aggregate_id, aggregate_sequence)
);
CREATE INDEX internal_events_unpublished_idx ON internal_events (occurred_at) WHERE published_at IS NULL;
