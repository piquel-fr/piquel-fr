-- Origins whose pages may sign users in with their auth passkeys (WebAuthn
-- related origins). `/.well-known/webauthn` lists them, so browsers let those
-- pages use auth's RP ID. Only operators approve them: browsers honour few
-- distinct domains, and the client must be trusted and have a redirect URI on
-- the origin. The origin is written as browsers send it, e.g. https://app.example.
CREATE TABLE client_webauthn_origins (
    origin TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX client_webauthn_origins_client_idx ON client_webauthn_origins (client_id);

-- A deleted client's origins go with it, whichever release deleted it: clients
-- are tombstoned, so the foreign key never cascades, and the previous release,
-- including its account purge, does not know this table.
CREATE FUNCTION remove_deleted_client_origins() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    DELETE FROM client_webauthn_origins WHERE client_id = NEW.id;
    RETURN NULL;
END $$;
CREATE TRIGGER oidc_clients_remove_related_origins
    AFTER UPDATE OF deleted_at ON oidc_clients
    FOR EACH ROW WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
    EXECUTE FUNCTION remove_deleted_client_origins();

-- A passkey sign-in on a related origin. It is bound to its origin and the
-- pushed authorization request it completes, rather than to a browser cookie.
-- The previous release never consumes one: it looks ceremonies up by kind.
ALTER TABLE webauthn_ceremonies DROP CONSTRAINT webauthn_ceremonies_ceremony_kind_check;
ALTER TABLE webauthn_ceremonies ADD CONSTRAINT webauthn_ceremonies_ceremony_kind_check
    CHECK (ceremony_kind IN (
        'registration', 'authentication', 'enrollment', 'purpose_authentication',
        'related_authentication'
    ));
