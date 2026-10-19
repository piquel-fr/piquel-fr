-- OIDC clients live in the database instead of AUTH_CLIENTS_FILE, so operators
-- change them at runtime with `auth-service client`.
--
-- A client may hold several secrets at once: rotating one caps the expiry of the
-- previous secrets, so the client keeps working while it redeploys. Only SHA-256
-- digests are stored; auth generates every secret with 256 random bits.
CREATE TABLE oidc_client_secrets (
    id UUID PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    secret_digest BYTEA NOT NULL CHECK (octet_length(secret_digest) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL until a rotation sets it on the previous secrets.
    expires_at TIMESTAMPTZ
);
CREATE INDEX oidc_client_secrets_client_idx ON oidc_client_secrets (client_id);

-- The client type is explicit instead of "has a secret hash".
ALTER TABLE oidc_clients
    ADD COLUMN client_type TEXT NOT NULL DEFAULT 'public'
        CHECK (client_type IN ('public', 'confidential')),
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

UPDATE oidc_clients SET client_type = 'confidential' WHERE client_secret_hash IS NOT NULL;
INSERT INTO oidc_client_secrets (id, client_id, secret_digest, created_at)
SELECT uuidv7(), id, client_secret_hash, created_at
FROM oidc_clients
WHERE client_secret_hash IS NOT NULL;

-- The previous release keeps writing client_secret_hash directly while it runs:
-- at startup it registers its file's clients, and an old replica may restart during
-- a deploy or after a rollback. Mirror those writes, so the new release never takes
-- a confidential client for a public one. Auth's own writes insert the secret row in
-- the same statement, so they match an existing secret and change nothing here. A
-- legacy write of a new hash replaces the previous secrets at once, as it used to.
-- A legacy write that clears the hash changes nothing: the client stays
-- confidential, and fails closed.
CREATE FUNCTION oidc_clients_mirror_legacy_secret() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM oidc_client_secrets
        WHERE client_id = NEW.id AND secret_digest = NEW.client_secret_hash
    ) THEN
        UPDATE oidc_clients SET client_type = 'confidential' WHERE id = NEW.id;
        UPDATE oidc_client_secrets SET expires_at = now()
        WHERE client_id = NEW.id AND (expires_at IS NULL OR expires_at > now());
        INSERT INTO oidc_client_secrets (id, client_id, secret_digest)
        VALUES (uuidv7(), NEW.id, NEW.client_secret_hash);
    END IF;
    RETURN NULL;
END
$$;
CREATE TRIGGER oidc_clients_mirror_legacy_secret
AFTER INSERT OR UPDATE OF client_secret_hash ON oidc_clients
FOR EACH ROW WHEN (NEW.client_secret_hash IS NOT NULL)
EXECUTE FUNCTION oidc_clients_mirror_legacy_secret();

-- The origin of each redirect URI, as browsers send it in an Origin header. A
-- public client's authorization redirect origins may call the token and UserInfo
-- endpoints, which look them up per request. Auth computes it on write. Existing
-- rows, and rows the previous release writes, have none: `auth-service migrate`
-- fills them in after the migrations, with the URL parser browsers' origins follow
-- (`OidcRepository::fill_redirect_origins`), which SQL cannot reproduce.
ALTER TABLE oidc_redirect_uris ADD COLUMN origin TEXT;
CREATE INDEX oidc_redirect_uris_origin_idx ON oidc_redirect_uris (origin)
    WHERE kind = 'authorization';

-- The previous release still disables every client it does not find in its
-- AUTH_CLIENTS_FILE whenever it starts. Register clients with the new release only
-- once no previous replica can restart, and re-enable them after a rollback.
--
-- PENDING CONTRACT: oidc_clients.client_secret_hash stays, and auth keeps it equal
-- to a confidential client's newest secret, because the previous release
-- authenticates clients with it, and would take a confidential client without it
-- for a public one. Once no deployed release reads or writes it, a new migration
-- must drop the oidc_clients_mirror_legacy_secret trigger and function, DROP COLUMN
-- client_secret_hash, and make oidc_redirect_uris.origin NOT NULL.
