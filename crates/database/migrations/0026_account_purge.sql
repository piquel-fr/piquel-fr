-- An account purge leaves no personal data behind, and costs no more as
-- everyone's history grows (#265).
--
-- The previous release keeps working beside this one: it reads none of the new
-- columns, and the trigger scrubs the clients it deletes too.

-- A purge that fails is retried with a backoff, so accounts that keep failing no
-- longer hold back every other due account. next_attempt_at is NULL until the
-- first failure: the purge is due at purge_after until then. last_error is the
-- error's message chain, never a value from the account.
ALTER TABLE account_deletions
    ADD COLUMN attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN last_error TEXT,
    ADD COLUMN next_attempt_at TIMESTAMPTZ,
    ADD CHECK ((attempts = 0) = (last_error IS NULL)),
    ADD CHECK ((last_error IS NULL) = (next_attempt_at IS NULL));
-- The purge job reads due accounts in the order they became due. greatest()
-- ignores a NULL next_attempt_at.
CREATE INDEX account_deletions_due_idx
    ON account_deletions ((greatest(next_attempt_at, purge_after)));
DROP INDEX account_deletions_purge_idx;

-- A purge erases the personal data of the events the account acted in, found by
-- the actor's user ID. The index is not partial: PostgreSQL keeps no statistics
-- on a partial index's expression, and without them it estimates so many matches
-- that it scans every event's personal data instead.
CREATE INDEX domain_events_actor_user_idx ON domain_events ((actor ->> 'user_id'));
-- A purge deletes the email deliveries addressed to the account.
CREATE INDEX deliveries_email_recipient_idx ON deliveries (recipient)
    WHERE channel = 'email';
-- A purge deletes, or deleting the account cascades or sets NULL in, every row
-- of the account, revoked or released ones included, which the partial indexes
-- on these columns leave out. The other foreign keys to users without an index
-- are on short-lived state: ceremonies, codes and pending sign-ins, which
-- cleanup keeps small.
CREATE INDEX active_verified_email_ownership_user_idx
    ON active_verified_email_ownership (user_id);
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX refresh_families_user_idx ON refresh_token_families (user_id);
CREATE INDEX passkey_credentials_user_idx ON passkey_credentials (user_id);
CREATE INDEX external_login_identities_user_idx ON external_login_identities (user_id);
CREATE INDEX handles_user_idx ON handles (user_id);
-- Purging an owner erases its clients' related origins from the events about
-- them, and deleting its clients deletes their consents.
CREATE INDEX domain_events_client_idx ON domain_events (client_id)
    WHERE client_id IS NOT NULL;
CREATE INDEX oidc_consents_client_idx ON oidc_consents (client_id);

-- Personal data is erased, never rewritten. Purging an app's owner erases the
-- app's related origins from other people's events by removing them from
-- `details`, the only column the runtime role may update; any other update fails.
CREATE FUNCTION guard_personal_data_erasure() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM jsonb_each(NEW.details) kept
        WHERE OLD.details -> kept.key IS DISTINCT FROM kept.value
    ) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'personal data of event % can only be erased', OLD.event_id
        USING ERRCODE = 'integrity_constraint_violation';
END $$;
CREATE TRIGGER event_personal_data_guard_erasure
    BEFORE UPDATE ON event_personal_data
    FOR EACH ROW EXECUTE FUNCTION guard_personal_data_erasure();

-- A deleted client keeps only its ID, settings that identify nobody, and its
-- lifecycle dates: its name, redirect URIs and back-channel logout URI may name a
-- person or their domain. Its name becomes empty rather than NULL, which the
-- previous release could not read.
CREATE FUNCTION scrub_deleted_client() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    NEW.display_name := '';
    NEW.backchannel_logout_uri := NULL;
    DELETE FROM oidc_redirect_uris WHERE client_id = NEW.id;
    RETURN NEW;
END $$;
CREATE TRIGGER oidc_clients_scrub_deleted
    BEFORE UPDATE OF deleted_at ON oidc_clients
    FOR EACH ROW WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
    EXECUTE FUNCTION scrub_deleted_client();

-- Clients deleted before this migration.
UPDATE oidc_clients SET display_name = '', backchannel_logout_uri = NULL
WHERE deleted_at IS NOT NULL;
DELETE FROM oidc_redirect_uris r USING oidc_clients c
WHERE r.client_id = c.id AND c.deleted_at IS NOT NULL;
