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

-- A passkey sign-in on a related origin. It is bound to its origin and the
-- pushed authorization request it completes, rather than to a browser cookie.
-- The previous release never consumes one: it looks ceremonies up by kind.
ALTER TABLE webauthn_ceremonies DROP CONSTRAINT webauthn_ceremonies_ceremony_kind_check;
ALTER TABLE webauthn_ceremonies ADD CONSTRAINT webauthn_ceremonies_ceremony_kind_check
    CHECK (ceremony_kind IN (
        'registration', 'authentication', 'enrollment', 'purpose_authentication',
        'related_authentication'
    ));
