-- Administrator accounts. A separate table, rather than a role column, keeps
-- administrator rights out of tokens and out of a future groups model. Who
-- granted the rights is recorded by the AdministratorGranted event.
CREATE TABLE administrators (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Invitations gain an ID, so administrators can list and revoke them without
-- knowing their secret. The default fills existing rows and keeps the previous
-- release's inserts working; the service passes its own IDs. A revoked
-- invitation can no longer be redeemed.
ALTER TABLE invitations
    ADD COLUMN id UUID NOT NULL DEFAULT uuidv7(),
    ADD COLUMN revoked_at TIMESTAMPTZ;
ALTER TABLE invitations DROP CONSTRAINT invitations_pkey;
ALTER TABLE invitations ADD PRIMARY KEY (id);
ALTER TABLE invitations ADD CONSTRAINT invitations_secret_digest_key UNIQUE (secret_digest);
