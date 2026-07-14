CREATE TABLE external_login_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_name TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    linked_email TEXT NOT NULL,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (issuer, subject)
);
CREATE INDEX external_login_identities_user_idx ON external_login_identities (user_id) WHERE revoked_at IS NULL;
