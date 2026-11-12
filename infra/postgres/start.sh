#!/bin/sh
# Starts PostgreSQL as the image does, after setting the superuser's password to
# the one in POSTGRES_PASSWORD_FILE. The image reads that file only when it
# initializes a new volume, so without this a regenerated `database-password`
# would never reach the database. See "The database password" in
# docs/dev/operations/secrets.md.
set -eu

if [ -s "$PGDATA/PG_VERSION" ]; then
	# A single-user server, before the real one listens. It reads the file itself
	# and strips one line ending, as auth does, so the password is in no command
	# line or statement.
	gosu postgres postgres --single -j -D "$PGDATA" \
		-c sourceorigin.password_file="$POSTGRES_PASSWORD_FILE" postgres >/dev/null <<'SQL'
DO $$
DECLARE
	password text;
BEGIN
	password := regexp_replace(
		pg_read_file(current_setting('sourceorigin.password_file')), E'\r?\n$', '');
	EXECUTE format('ALTER ROLE %I PASSWORD %L', current_user, password);
EXCEPTION WHEN OTHERS THEN
	-- Raised again with its message only, since its context would quote the
	-- statement, password included. A single-user server carries on after an
	-- error, so `exit_on_error` makes this one stop the container instead of
	-- starting it with the old password.
	PERFORM set_config('exit_on_error', 'on', false);
	RAISE EXCEPTION 'could not set the password of %: %', current_user, SQLERRM
		USING ERRCODE = SQLSTATE;
END
$$;

SQL
fi

exec docker-entrypoint.sh postgres
