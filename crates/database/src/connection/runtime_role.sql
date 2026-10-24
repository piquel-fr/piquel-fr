-- Renders the script `Database::provision` runs as the schema owner after
-- migrations. It creates the runtime role $1, or resets it, with the password $2,
-- and grants it row access to the app tables and nothing else. `RuntimeRole`
-- only accepts plain identifiers, so the name is safe inside the DO block. The
-- advisory lock $3 serializes overlapping runs, whose catalog updates conflict.
SELECT format($script$
SELECT pg_advisory_xact_lock(%4$s);
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = %1$L AND (rolsuper OR rolname = current_user)) THEN
        RAISE EXCEPTION 'the runtime role %1$s must not be the schema owner or a superuser';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = %1$L) THEN
        CREATE ROLE %1$I;
    END IF;
END $$;
ALTER ROLE %1$I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD %2$L;
GRANT CONNECT ON DATABASE %3$I TO %1$I;
GRANT USAGE ON SCHEMA public TO %1$I;
-- Start from nothing, so privileges narrowed below never linger.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %1$I;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %1$I;
-- Only migrations read it.
REVOKE ALL ON _sqlx_migrations FROM %1$I;
-- History is append-only, and its personal data is erased but never rewritten.
REVOKE UPDATE, DELETE ON domain_events FROM %1$I;
REVOKE UPDATE ON event_personal_data FROM %1$I;
REVOKE DELETE ON event_consumers FROM %1$I;
$script$, $1::text, $2::text, current_database(), $3::bigint) AS "script!"
