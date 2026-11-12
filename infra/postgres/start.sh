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
	# line or statement. Terse logging leaves out every message's context, which
	# could quote the `ALTER ROLE` and its password, and `exit_on_error` stops the
	# container on a failure instead of starting it with the old password.
	gosu postgres postgres --single -j -D "$PGDATA" \
		-c exit_on_error=on -c log_error_verbosity=terse \
		-c sourceorigin.password_file="$POSTGRES_PASSWORD_FILE" postgres >/dev/null <<'SQL'
DO $$
BEGIN
	EXECUTE format('ALTER ROLE %I PASSWORD %L', current_user, regexp_replace(
		pg_read_file(current_setting('sourceorigin.password_file')), E'\r?\n$', ''));
END
$$;

SQL
fi

exec docker-entrypoint.sh postgres
