-- Contracts what migrations 0005 (#135) and 0008 (#143) kept for the releases
-- before them, which no environment runs anymore.

-- Migration 0005 imported security_audit_log into domain_events, but kept the
-- table for the previous release to write to during the deploy. Import what it
-- wrote since, as 0005 did, then drop the log.
INSERT INTO domain_events (id, occurred_at, kind, version, payload, actor, subject_user_id)
SELECT
    id,
    created_at,
    'imported',
    1,
    jsonb_build_object('action', action, 'outcome', outcome, 'metadata', request_metadata),
    '{"type": "unrecorded"}',
    user_id
FROM security_audit_log a
WHERE NOT EXISTS (SELECT 1 FROM domain_events e WHERE e.id = a.id)
ORDER BY created_at, id;
DROP TABLE security_audit_log;

-- Migration 0008 mirrored the previous release's writes to
-- oidc_clients.client_secret_hash into oidc_client_secrets. Every deployed release
-- writes oidc_client_secrets itself.
DROP TRIGGER oidc_clients_mirror_legacy_secret ON oidc_clients;
DROP FUNCTION oidc_clients_mirror_legacy_secret();

-- Every deployed release computes a redirect URI's origin on write, and
-- `auth-service migrate` filled in the ones from before.
ALTER TABLE oidc_redirect_uris ALTER COLUMN origin SET NOT NULL;

-- PENDING CONTRACT: oidc_clients.client_secret_hash stays, because the previous
-- release still writes it, though nothing reads it. Once no deployed release
-- writes it, a new migration must DROP COLUMN client_secret_hash.
