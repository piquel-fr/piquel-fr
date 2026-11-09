-- Retention limits on what an account leaves behind (#266). Cleanup deletes
-- revoked passkeys, unlinked identities and ended recoveries 90 days after they
-- end, notifications a year after they arrive, and a purged account's handles a
-- year after its purge, when anyone may claim them again.

-- A purged account's handles are released by its purge, whichever release runs
-- it: deleting the account sets their `user_id` to NULL, which fires this. It
-- also overwrites when an older handle was released, so every handle the account
-- held is freed a year after the purge, not after its rename.
CREATE FUNCTION release_purged_handle() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    NEW.released_at := now();
    RETURN NEW;
END $$;
CREATE TRIGGER handles_release_purged
    BEFORE UPDATE OF user_id ON handles
    FOR EACH ROW WHEN (OLD.user_id IS NOT NULL AND NEW.user_id IS NULL)
    EXECUTE FUNCTION release_purged_handle();

-- Accounts purged before this keep their handles a year from now.
UPDATE handles SET released_at = now() WHERE user_id IS NULL;

-- Cleanup's scans, so they read only what may be due.
CREATE INDEX passkey_credentials_revoked_idx ON passkey_credentials (revoked_at)
    WHERE revoked_at IS NOT NULL;
CREATE INDEX external_login_identities_revoked_idx ON external_login_identities (revoked_at)
    WHERE revoked_at IS NOT NULL;
CREATE INDEX notifications_created_idx ON notifications (created_at);
CREATE INDEX handles_purged_idx ON handles (released_at) WHERE user_id IS NULL;
