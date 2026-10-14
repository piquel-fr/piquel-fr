-- Functions run with the caller's search_path, which searches pg_temp first
-- unless it is listed. A temporary table named `users` would then shadow the
-- table the email-ownership triggers read. Pin every function to the schema,
-- with pg_temp explicitly last; new functions must set the same search_path.
ALTER FUNCTION claim_active_verified_email() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION release_active_verified_email() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION synchronize_user_email_ownership() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION enforce_primary_verified_email() SET search_path = pg_catalog, public, pg_temp;
