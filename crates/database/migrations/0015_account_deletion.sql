-- Account deletion (#84). A user, administrator or operator schedules it; the
-- account then waits in status 'deleting' for its grace period, during which a
-- passkey can restore it, and the purge job deletes it once the period ends.
--
-- A 'deleting' account keeps its verified emails: the ownership triggers only
-- release them for 'disabled', so restoring it can never collide. Deleting the row
-- at purge releases them.
--
-- The previous release already reads 'deleting' and the purge job's actor, though
-- it never writes them, so it keeps working beside this one and after a rollback.
ALTER TABLE users DROP CONSTRAINT users_status_check,
    ADD CONSTRAINT users_status_check CHECK (status IN ('active', 'disabled', 'deleting'));

-- One row per account scheduled for deletion, removed when it is restored or
-- purged. A passkey sign-in to the account stores the digest of a single-use,
-- short-lived restore token here; the token restores the account and signs in.
CREATE TABLE account_deletions (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    purge_after TIMESTAMPTZ NOT NULL,
    restore_token_digest BYTEA UNIQUE CHECK (octet_length(restore_token_digest) = 32),
    restore_token_expires_at TIMESTAMPTZ,
    CHECK ((restore_token_digest IS NULL) = (restore_token_expires_at IS NULL))
);
-- The purge job finds accounts past their grace period.
CREATE INDEX account_deletions_purge_idx ON account_deletions (purge_after);

-- Handles of purged accounts, never reused, so nobody can impersonate a deleted
-- account in applications that show `preferred_username`. Only the name and a
-- date are kept: nothing links it to the account or its events.
CREATE TABLE retired_usernames (
    username TEXT PRIMARY KEY,
    retired_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Rejects retired handles on every insert and rename, the previous release's
-- included, as a handle conflict. A purge deletes the account and retires its
-- name in one transaction. A signup for that name first waits on the account's
-- row: once the purge commits, the row is gone and the next statement, which reads
-- a fresh snapshot, sees the retired name.
--
-- It runs as its owner: `migrate` grants the runtime role retired_usernames only
-- after the migrations, and the previous release keeps signing up meanwhile. No
-- one else may execute it, as migration 0013 explains; the trigger still fires.
CREATE FUNCTION reject_retired_username() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    PERFORM 1 FROM users WHERE username = NEW.username AND id <> NEW.id FOR KEY SHARE;
    IF EXISTS (SELECT 1 FROM retired_usernames WHERE username = NEW.username) THEN
        RAISE EXCEPTION 'username % is retired', NEW.username USING ERRCODE = 'unique_violation';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION reject_retired_username() FROM PUBLIC;
CREATE TRIGGER users_reject_retired_username
    BEFORE INSERT OR UPDATE OF username ON users
    FOR EACH ROW EXECUTE FUNCTION reject_retired_username();

-- An account that stops being 'deleting' is no longer scheduled, however it left:
-- restored, or enabled or disabled by the previous release, which does not know
-- the schedule. Otherwise the purge would skip it forever, and it could never be
-- scheduled again.
CREATE FUNCTION end_account_deletion() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    DELETE FROM account_deletions WHERE user_id = NEW.id;
    RETURN NULL;
END $$;
CREATE TRIGGER users_end_account_deletion
    AFTER UPDATE OF status ON users
    FOR EACH ROW WHEN (OLD.status = 'deleting' AND NEW.status <> 'deleting')
    EXECUTE FUNCTION end_account_deletion();

-- An event keeps personal data only while every account it names, as subject or
-- actor, exists: a request still in flight when its account is purged must not
-- store it again, whichever release recorded it. Each named account is
-- key-share locked, which the purge's lock on the account conflicts with: either
-- the purge waits, then deletes this row, or this insert waits, finds the account
-- gone and is skipped.
CREATE FUNCTION skip_personal_data_of_purged_accounts() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF EXISTS (
        SELECT FROM domain_events e
        CROSS JOIN LATERAL (
            VALUES (e.subject_user_id), ((e.actor ->> 'user_id')::uuid)
        ) AS named(id)
        WHERE e.id = NEW.event_id
        AND named.id IS NOT NULL
        AND NOT EXISTS (SELECT FROM users WHERE id = named.id FOR KEY SHARE)
    ) THEN
        RETURN NULL;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER event_personal_data_skip_purged_accounts
    BEFORE INSERT ON event_personal_data
    FOR EACH ROW EXECUTE FUNCTION skip_personal_data_of_purged_accounts();

-- The legacy audit log names accounts too. The runtime role cannot touch it, so
-- deleting the account deletes its rows, which the cascade does as the owner.
ALTER TABLE security_audit_log DROP CONSTRAINT security_audit_log_user_id_fkey,
    ADD CONSTRAINT security_audit_log_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
