-- Handles replace usernames. One table holds every account's current handle, the
-- ones it held before and the ones of purged accounts, so PostgreSQL keeps all of
-- them unique, along with their look-alikes. A released row stays forever: only
-- its former owner may claim it again, until an operator deletes it.
--
-- This drops users.username, which the previous release reads: its replicas fail
-- until this release replaces them. Accounts are few and invite-only, and the
-- alternative, keeping both columns in sync for a release, would let a signup on
-- an old replica create an account without a handle.

-- The confusable skeleton `Handle::skeleton` computes, which a test pins to it:
-- hyphens dropped, `0` read as `o`, `1` and `i` as `l`, `5` as `s`, then `rn` as
-- `m` and `vv` as `w`.
CREATE FUNCTION handle_skeleton(handle TEXT) RETURNS TEXT
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    SET search_path = pg_catalog, public, pg_temp
    RETURN replace(replace(translate(handle, '01i5-', 'olls'), 'rn', 'm'), 'vv', 'w');

-- Every username must already be a valid handle without a look-alike: the previous
-- release's `auth-service handle check` lists the ones to rename.
DO $$
DECLARE offending TEXT;
BEGIN
    SELECT string_agg(username, ', ' ORDER BY username) INTO offending
    FROM users
    WHERE length(username) NOT BETWEEN 3 AND 32
        OR username !~ '^[a-z0-9]+(-[a-z0-9]+)*$'
        OR handle_skeleton(username) IN (
            SELECT handle_skeleton(username) FROM users GROUP BY 1 HAVING count(*) > 1
        );
    IF offending IS NOT NULL THEN
        RAISE EXCEPTION 'these usernames are not valid, distinct handles: %', offending
            USING HINT = 'Rename them with the previous release''s `auth-service handle rename`, '
                'which `auth-service handle check` guides.';
    END IF;
END $$;

CREATE TABLE handles (
    handle TEXT PRIMARY KEY
        CHECK (length(handle) BETWEEN 3 AND 32 AND handle ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    skeleton TEXT NOT NULL UNIQUE GENERATED ALWAYS AS (handle_skeleton(handle)) STORED,
    -- NULL once the account is purged.
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL while it is the account's current handle.
    released_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX handles_current_idx ON handles (user_id) WHERE released_at IS NULL;

INSERT INTO handles (handle, user_id, claimed_at)
SELECT username, id, created_at FROM users;

-- When the handle last changed, for the rename cooldown. Reclaiming an old handle
-- keeps its row's claimed_at, so the cooldown cannot read that.
ALTER TABLE users ADD COLUMN handle_changed_at TIMESTAMPTZ NOT NULL DEFAULT now();
UPDATE users SET handle_changed_at = created_at;
ALTER TABLE users DROP COLUMN username;
