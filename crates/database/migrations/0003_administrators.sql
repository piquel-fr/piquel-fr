-- Administrator accounts. Rows are granted and revoked only by the auth-service
-- CLI; no HTTP route writes this table. A separate table, rather than a role
-- column, keeps administrator rights out of tokens and the groups model.
-- granted_by holds the CLI actor that granted them (os_user, host).
CREATE TABLE administrators (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by JSONB NOT NULL
);

-- Invitations gain an ID, so administrators can list and revoke them without
-- knowing their secret. created_by is NULL for invitations created before
-- actors were recorded. A revoked invitation can no longer be redeemed.
ALTER TABLE invitations
    ADD COLUMN id UUID NOT NULL DEFAULT uuidv7(),
    ADD COLUMN created_by JSONB,
    ADD COLUMN revoked_at TIMESTAMPTZ;
-- The default only backfills existing rows; the service generates new IDs.
ALTER TABLE invitations ALTER COLUMN id DROP DEFAULT;
ALTER TABLE invitations DROP CONSTRAINT invitations_pkey;
ALTER TABLE invitations ADD PRIMARY KEY (id);
ALTER TABLE invitations ADD CONSTRAINT invitations_secret_digest_key UNIQUE (secret_digest);
