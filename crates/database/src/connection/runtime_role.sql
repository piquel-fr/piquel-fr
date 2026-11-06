-- Renders the script `Database::provision` runs as the schema owner after
-- migrations. It creates the runtime role $1, or resets it, with the SCRAM
-- verifier $2 as its password (see `ScramVerifier`),
-- and grants it row access to the app tables and nothing else. `RuntimeRole`
-- only accepts plain identifiers, so the name is safe inside the DO block. The
-- advisory lock $3 serializes overlapping runs, whose catalog updates conflict.
--
-- A role that is a member of another role would keep that role's privileges, and
-- one that owns objects could change them, so an existing role must be neither.
-- Large objects and default privileges are left out: any role may create them,
-- and they reach neither the schema nor the history; the defaults apply only to
-- objects the role creates, and it can create only large objects. A role granted
-- a server parameter, directly or through PUBLIC, could set one such as
-- session_replication_role, so it is refused too. Its settings and its
-- privileges on the database, schema and sequences are reset, so only what is
-- granted here remains.
SELECT format($script$
SELECT pg_advisory_xact_lock(%4$s);
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = %1$L AND (rolsuper OR rolname = current_user)) THEN
        RAISE EXCEPTION 'the runtime role %1$s must not be the schema owner or a superuser';
    END IF;
    IF EXISTS (
        SELECT FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member
        WHERE r.rolname = %1$L
    ) THEN
        RAISE EXCEPTION 'the runtime role %1$s must not be a member of another role';
    END IF;
    IF EXISTS (
        SELECT FROM pg_parameter_acl p CROSS JOIN LATERAL aclexplode(p.paracl) a
        WHERE a.grantee = 0
        OR a.grantee = (SELECT oid FROM pg_roles WHERE rolname = %1$L)
    ) THEN
        RAISE EXCEPTION 'the runtime role %1$s must not be granted any server parameter';
    END IF;
    IF EXISTS (
        SELECT FROM pg_shdepend d JOIN pg_roles r ON r.oid = d.refobjid
        WHERE d.refclassid = 'pg_authid'::regclass AND d.deptype = 'o' AND r.rolname = %1$L
        AND d.classid NOT IN ('pg_largeobject'::regclass, 'pg_default_acl'::regclass)
    ) THEN
        RAISE EXCEPTION 'the runtime role %1$s must not own anything';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = %1$L) THEN
        CREATE ROLE %1$I;
    END IF;
END $$;
ALTER ROLE %1$I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD %2$L;
ALTER ROLE %1$I RESET ALL;
ALTER ROLE %1$I IN DATABASE %3$I RESET ALL;
REVOKE ALL ON DATABASE %3$I FROM %1$I;
GRANT CONNECT ON DATABASE %3$I TO %1$I;
-- Every role may create temporary tables by default, which could shadow the
-- tables functions read. Only the owner, a superuser, needs them.
REVOKE TEMPORARY ON DATABASE %3$I FROM PUBLIC, %1$I;
REVOKE ALL ON SCHEMA public FROM %1$I;
GRANT USAGE ON SCHEMA public TO %1$I;
-- Start from nothing, so privileges narrowed below never linger.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %1$I;
-- Inserting into an identity column needs no privilege on its sequence.
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM %1$I;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %1$I;
-- Only migrations read it.
REVOKE ALL ON _sqlx_migrations FROM %1$I;
-- History is append-only. An event is inserted with only the columns auth
-- writes, so its transaction, time, sequence and chain columns keep their
-- defaults; a migration adding a column auth writes adds it here. Sealing sets an
-- event's chain position, hash and format, which triggers allow only while they
-- are unset, and only right after the position before. Checkpoints are only added,
-- and a trigger refuses one that is not of a sealed event's hash, or is dated in
-- the future; auth checks their signatures. Only the schema owner prunes, so
-- moves the anchor.
REVOKE INSERT, UPDATE, DELETE ON domain_events FROM %1$I;
GRANT INSERT (
    id, kind, version, payload, actor, subject_user_id, client_id, session_id, trace_id
) ON domain_events TO %1$I;
GRANT UPDATE (chain_position, chain_hash, chain_format) ON domain_events TO %1$I;
REVOKE UPDATE, DELETE ON audit_checkpoints FROM %1$I;
REVOKE INSERT, UPDATE, DELETE ON audit_anchor FROM %1$I;
-- Personal data is erased but never rewritten: it is inserted only with an
-- event of the same transaction, which a trigger checks, and with its retention
-- clock starting now. A purge removes values from `details`, and a trigger
-- refuses any other change; retention and purges delete rows.
REVOKE INSERT, UPDATE ON event_personal_data FROM %1$I;
GRANT INSERT (
    event_id, client_ip, user_agent_family, platform, details, reason
) ON event_personal_data TO %1$I;
GRANT UPDATE (details) ON event_personal_data TO %1$I;
REVOKE DELETE ON event_consumers FROM %1$I;
$script$, $1::text, $2::text, current_database(), $3::bigint) AS "script!"
