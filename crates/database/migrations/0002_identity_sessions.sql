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

-- The ownership row makes the no-existing-email concurrency case safe: the
-- normalized address itself is the unique lockable key.
CREATE TABLE active_verified_email_ownership (
    normalized_email TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

CREATE OR REPLACE FUNCTION claim_active_verified_email() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.verified_at IS NOT NULL AND (SELECT status = 'active' FROM users WHERE id = NEW.user_id) THEN
        INSERT INTO active_verified_email_ownership(normalized_email, user_id)
        VALUES (NEW.normalized_email, NEW.user_id)
        ON CONFLICT (normalized_email) DO UPDATE SET user_id = EXCLUDED.user_id
        WHERE active_verified_email_ownership.user_id = EXCLUDED.user_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'verified email already belongs to an active account' USING ERRCODE = 'unique_violation';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER user_emails_claim_active_verified BEFORE INSERT OR UPDATE OF normalized_email, verified_at, user_id ON user_emails FOR EACH ROW EXECUTE FUNCTION claim_active_verified_email();

CREATE OR REPLACE FUNCTION release_active_verified_email() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.verified_at IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM user_emails e JOIN users u ON u.id=e.user_id
        WHERE e.user_id=OLD.user_id AND e.normalized_email=OLD.normalized_email
          AND e.verified_at IS NOT NULL AND e.id<>OLD.id AND u.status='active'
    ) THEN DELETE FROM active_verified_email_ownership WHERE normalized_email=OLD.normalized_email AND user_id=OLD.user_id; END IF;
    RETURN OLD;
END $$;
CREATE TRIGGER user_emails_release_active_verified AFTER DELETE OR UPDATE OF normalized_email, verified_at, user_id ON user_emails FOR EACH ROW EXECUTE FUNCTION release_active_verified_email();

CREATE OR REPLACE FUNCTION synchronize_user_email_ownership() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE address TEXT;
BEGIN
    IF NEW.status='disabled' THEN DELETE FROM active_verified_email_ownership WHERE user_id=NEW.id;
    ELSIF OLD.status='disabled' AND NEW.status='active' THEN
        FOR address IN SELECT DISTINCT normalized_email FROM user_emails WHERE user_id=NEW.id AND verified_at IS NOT NULL LOOP
            INSERT INTO active_verified_email_ownership(normalized_email,user_id) VALUES(address,NEW.id)
            ON CONFLICT(normalized_email) DO UPDATE SET user_id=EXCLUDED.user_id WHERE active_verified_email_ownership.user_id=EXCLUDED.user_id;
            IF NOT FOUND THEN RAISE EXCEPTION 'verified email already belongs to an active account' USING ERRCODE='unique_violation'; END IF;
        END LOOP;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER users_synchronize_email_ownership BEFORE UPDATE OF status ON users FOR EACH ROW EXECUTE FUNCTION synchronize_user_email_ownership();

CREATE OR REPLACE FUNCTION enforce_primary_verified_email() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE affected UUID := COALESCE(NEW.user_id, OLD.user_id);
BEGIN
    IF EXISTS (SELECT 1 FROM user_emails WHERE user_id=affected AND verified_at IS NOT NULL)
       AND (SELECT count(*) FROM user_emails WHERE user_id=affected AND verified_at IS NOT NULL AND is_primary) <> 1
    THEN RAISE EXCEPTION 'verified emails require exactly one primary' USING ERRCODE='check_violation'; END IF;
    RETURN COALESCE(NEW, OLD);
END $$;
CREATE CONSTRAINT TRIGGER user_emails_exactly_one_primary AFTER INSERT OR UPDATE OR DELETE ON user_emails DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enforce_primary_verified_email();

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
