-- Recoveries an operator started for an account whose owner lost their
-- passkeys. Each sends its owner a link that enrolls one passkey, once, within a
-- day. The link's token is derived from the recovery's ID, so only its digest is
-- stored. For 15 days after the link is used, the recovery is in probation: its
-- passkey signs in but never confirms a session, and a passkey from before it
-- can undo it.
CREATE TABLE account_recoveries (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_digest BYTEA NOT NULL UNIQUE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    -- When its link enrolled a passkey, which one, and when its probation ends.
    -- `settles_at` is computed by auth from its probation length, so SQL never
    -- repeats the constant.
    completed_at TIMESTAMPTZ,
    passkey_id UUID,
    settles_at TIMESTAMPTZ,
    -- When a newer recovery, the account's disabling or its owner's undo cancelled
    -- it before its link was used.
    cancelled_at TIMESTAMPTZ,
    -- When it was undone after its link was used, by its owner or by support.
    undone_at TIMESTAMPTZ,
    CHECK ((completed_at IS NULL) = (passkey_id IS NULL)),
    CHECK ((completed_at IS NULL) = (settles_at IS NULL)),
    CHECK (cancelled_at IS NULL OR (completed_at IS NULL AND undone_at IS NULL)),
    CHECK (undone_at IS NULL OR completed_at IS NOT NULL)
);
CREATE INDEX account_recoveries_user_idx ON account_recoveries (user_id, started_at DESC);
CREATE UNIQUE INDEX account_recoveries_passkey_idx ON account_recoveries (passkey_id);
-- At most one recovery per account whose link was not used, cancelled or undone.
-- An expired one counts until the next start cancels it.
CREATE UNIQUE INDEX account_recoveries_one_open_idx ON account_recoveries (user_id)
    WHERE completed_at IS NULL AND cancelled_at IS NULL AND undone_at IS NULL;

-- The account's recovery that can still be undone, if any: its link still works,
-- or it is in probation (its rows with `completed_at` set). The one SQL copy of
-- auth's `RecoveryState`; only the trigger functions below call it, as their
-- owner.
CREATE FUNCTION undoable_recovery(account UUID) RETURNS SETOF account_recoveries
LANGUAGE sql VOLATILE SET search_path = pg_catalog, public, pg_temp AS $$
    SELECT * FROM public.account_recoveries
    WHERE user_id = account
    AND undone_at IS NULL AND cancelled_at IS NULL
    AND (settles_at > clock_timestamp()
        OR (completed_at IS NULL AND expires_at > clock_timestamp()))
$$;
REVOKE EXECUTE ON FUNCTION undoable_recovery(UUID) FROM PUBLIC;

-- A probation passkey never confirms a session, whichever release writes it:
-- the previous one during a deploy confirms every passkey sign-in, and a
-- release rolled back below this one would too. A confirmation that names no
-- passkey fails closed while the account is in probation. The trigger functions
-- run as their owner, because the previous release fires them before the
-- runtime role is granted `account_recoveries`.
CREATE FUNCTION sessions_no_probation_confirmation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF NEW.passkey_confirmed_at IS NOT NULL AND EXISTS (
        SELECT 1 FROM public.undoable_recovery(NEW.user_id)
        WHERE completed_at IS NOT NULL
        AND (NEW.passkey_id IS NULL OR passkey_id = NEW.passkey_id)
    ) THEN
        NEW.passkey_confirmed_at := NULL;
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION sessions_no_probation_confirmation() FROM PUBLIC;
CREATE TRIGGER sessions_no_probation_confirmation
    BEFORE INSERT OR UPDATE OF passkey_confirmed_at, passkey_id ON sessions
    FOR EACH ROW EXECUTE FUNCTION sessions_no_probation_confirmation();

-- No account is made an administrator while a recovery of it can be undone:
-- the rights would go live for whoever holds its passkey once it settles.
CREATE FUNCTION administrators_no_grant_mid_recovery() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.undoable_recovery(NEW.user_id)) THEN
        RAISE EXCEPTION 'account % has a recovery that can still be undone', NEW.user_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION administrators_no_grant_mid_recovery() FROM PUBLIC;
CREATE TRIGGER administrators_no_grant_mid_recovery
    BEFORE INSERT ON administrators
    FOR EACH ROW EXECUTE FUNCTION administrators_no_grant_mid_recovery();

-- While a recovery can be undone, no passkey but its own is revoked, by anyone,
-- so nothing takes away the passkeys that can undo it.
CREATE FUNCTION passkeys_kept_mid_recovery() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM public.undoable_recovery(OLD.user_id)
        WHERE passkey_id IS DISTINCT FROM OLD.id
    ) THEN
        RAISE EXCEPTION 'account % has a recovery that can still be undone', OLD.user_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION passkeys_kept_mid_recovery() FROM PUBLIC;
CREATE TRIGGER passkeys_kept_mid_recovery
    BEFORE UPDATE OF revoked_at ON passkey_credentials
    FOR EACH ROW WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
    EXECUTE FUNCTION passkeys_kept_mid_recovery();
