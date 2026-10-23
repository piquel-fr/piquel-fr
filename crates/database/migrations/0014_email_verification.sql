-- Users add their own email addresses, which stay unverified until someone
-- follows the link sent to them. Auth derives the link's token from the address's
-- ID with a server key, so the token itself is stored nowhere: only its SHA-256
-- digest, to look the address up. Verifying deletes the row; cleanup deletes
-- expired rows together with the unverified addresses they belong to.
CREATE TABLE email_verification_secrets (
    email_id UUID PRIMARY KEY REFERENCES user_emails(id) ON DELETE CASCADE,
    secret_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(secret_digest) = 32),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX email_verification_secrets_expires_idx ON email_verification_secrets (expires_at);
