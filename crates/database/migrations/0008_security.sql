ALTER TABLE sessions ADD COLUMN management_expires_at TIMESTAMPTZ;

CREATE TABLE invitations (
    secret_digest BYTEA PRIMARY KEY CHECK (octet_length(secret_digest) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    redeemed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE request_limits (
    bucket BYTEA PRIMARY KEY,
    requests INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
