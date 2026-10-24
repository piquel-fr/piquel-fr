-- Signing keys (#48). Every replica reloads them each minute; one replica at a
-- time advances their rotation, under a transaction-level advisory lock that the
-- `keys` commands take too. A key is published as `next`, signs as `active`, stays
-- published as `retiring`, then verifies only `id_token_hint`s as `retired` until
-- it is deleted. Its PKCS#8 private key is sealed with AES-256-GCM under the
-- key-encryption key from configuration, with `id || key_type` as associated
-- data, and erased once it retires.
CREATE TABLE signing_keys (
    id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
    key_type TEXT NOT NULL CHECK (key_type IN ('rsa')),
    state TEXT NOT NULL CHECK (state IN ('next', 'active', 'retiring', 'retired')),
    public_jwk JSONB NOT NULL,
    sealed_private_key BYTEA,
    created_at TIMESTAMPTZ NOT NULL,
    -- When it started signing, stopped signing, and left the key set.
    activated_at TIMESTAMPTZ,
    deactivated_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    CHECK ((state = 'retired') = (sealed_private_key IS NULL)),
    CHECK ((state = 'next') = (activated_at IS NULL)),
    CHECK ((state IN ('next', 'active')) = (deactivated_at IS NULL)),
    CHECK ((state = 'retired') = (retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX signing_keys_one_active ON signing_keys (key_type) WHERE state = 'active';
CREATE UNIQUE INDEX signing_keys_one_next ON signing_keys (key_type) WHERE state = 'next';

-- The fingerprint of the token digest key each stored secret digest was made
-- with, so `auth-service keys digest-usage` can tell when no stored digest
-- needs an old key. NULL: made before this migration, or by the previous
-- release during this deploy, under the key derived from the PEM signing key.
ALTER TABLE authorization_requests ADD COLUMN digest_key TEXT;
ALTER TABLE authorization_codes ADD COLUMN digest_key TEXT;
ALTER TABLE refresh_tokens ADD COLUMN digest_key TEXT;
