-- Clients an account registers and manages through the account API (#43).
--
-- owner_id is NULL for clients operators manage with `auth-service client`; the
-- account API never shows those. created_via records which path registered the
-- client; 'registration' is reserved for dynamic client registration (#44).
--
-- Deletion is a tombstone: the row stays, so its ID, which tokens carry as `aud`,
-- is never reused, and cleanup never deletes it. A tombstone is always disabled,
-- so no path can bring it back; the previous release, which never deletes, could
-- violate the check only by enabling a client this release deleted.
--
-- A suspension is an operator's block: the client is disabled, and its owner
-- cannot enable it until an operator lifts the suspension. Like a tombstone, a
-- suspended client is always disabled, so the previous release, which does not
-- know suspensions, still refuses it, and cannot enable it.
--
-- last_used_at moves at most once an hour, when a token is issued to the client.
ALTER TABLE oidc_clients
    ADD COLUMN owner_id UUID REFERENCES users(id),
    ADD COLUMN created_via TEXT NOT NULL DEFAULT 'cli'
        CHECK (created_via IN ('cli', 'account', 'registration')),
    ADD COLUMN deleted_at TIMESTAMPTZ,
    ADD COLUMN suspended_at TIMESTAMPTZ,
    ADD COLUMN last_used_at TIMESTAMPTZ,
    ADD CONSTRAINT oidc_clients_tombstone_disabled CHECK (deleted_at IS NULL OR NOT enabled),
    ADD CONSTRAINT oidc_clients_suspended_disabled CHECK (suspended_at IS NULL OR NOT enabled);

-- Counts an owner's live clients for the quota, and the clients, deleted or not,
-- they registered recently for the daily registration limit.
CREATE INDEX oidc_clients_owner_idx ON oidc_clients (owner_id, created_at);
