-- Functions run with the caller's search_path, which looks in pg_temp first unless
-- it lists it. auth's runtime role may create temporary tables, so a temporary
-- `users` could shadow the table these triggers read. Each function pins its own
-- path, which a session cannot override, with pg_temp last.
ALTER FUNCTION claim_active_verified_email() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION release_active_verified_email() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION synchronize_user_email_ownership() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION enforce_primary_verified_email() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION oidc_clients_mirror_legacy_secret() SET search_path = pg_catalog, public, pg_temp;
