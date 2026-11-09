# Adding a database migration

This guide adds a change to auth's PostgreSQL schema: a table, a column, a
constraint or a trigger. The rules a migration follows are in
[PostgreSQL boundary](../architecture/database.md); this page is the order you
apply them in.

## What you'll have at the end

- A numbered SQL file in `crates/database/migrations`, which `auth-service
  migrate` applies before a deploy's new release starts.
- A schema the previous release keeps working against while it still serves.
- The runtime role's grants covering the change.
- Checked queries over it, with the committed query cache regenerated.

## Before you start

You need PostgreSQL 18's server binaries and sqlx-cli for the database recipes:
`just install-tools` installs sqlx-cli. Every recipe below runs against a scratch
cluster it creates and deletes, so you need no database of your own.

Read the paragraphs on migrations in
[PostgreSQL boundary](../architecture/database.md) first. The rule that shapes
every migration: a deploy runs `migrate`, then the previous release keeps
serving against the new schema until the new one is healthy, so every migration
must keep that release working.

## 1. Number it

Create `crates/database/migrations/<NNNN>_<name>.sql`, numbered one after the
latest migration on `main`, such as `0035_recovery_codes.sql`. Numbers count up
from `0001` with no gap or repeat, which `migration_versions_are_unique_and_contiguous`
checks. If another branch merges a migration first, rebase and renumber yours.

Never edit a migration once it is on `main`: a later change is a new file.

## 2. Say what it does, and why

Open the file with SQL comments that say what the migration changes, why, and
why the previous release keeps working:

```sql
-- The profile picture URL a provider reported with its evidence, so a social
-- signup can import it once the account exists. Nullable: the previous release
-- inserts evidence without one, and its signups import nothing.
ALTER TABLE pending_federation
    ADD COLUMN picture_url TEXT CHECK (char_length(picture_url) <= 2048);
```

The comments are the migration's documentation; nothing else describes it.

## 3. Expand now, contract later

Migrations expand, then contract, as
[PostgreSQL boundary](../architecture/database.md) sets out: this migration
adds what the new release needs, such as a table, or a column that is nullable
or has a default. What removes the old shape, or adds a constraint the previous
release could violate, waits for a later release, once no deployed code uses
the old shape.

A migration may break the rule only when the previous release cannot be harmed,
and then says why in its own comments. `0034_notification_emails.sql` cancels
the deliveries an older kind of message left, since there are no real users yet:

```sql
-- Those still waiting to be sent, or failed, are cancelled rather than
-- translated: there are no real users yet, and a notice that late is stale.
```

A value of a closed vocabulary, such as a new `CHECK` value read into a
`str_enum!`, is added in a release that never writes it, and written from a later
one: see [domain events](../architecture/database.md#domain-events).

## 4. Write functions and triggers safely

- Pin every function's `search_path`:
  `SET search_path = pg_catalog, public, pg_temp`. A test fails for any function
  without it.
- A trigger function runs as the role that fires it, unless it reads or writes a
  table its own migration creates: the runtime role is granted that table only
  after the migrations, while the previous release already fires the trigger.
  Make that function `SECURITY DEFINER`, and revoke `EXECUTE` from everyone but
  its owner. A test fails for one others may execute.

See [roles](../architecture/database.md#roles) for why.

## 5. Check the runtime role's grants

Auth serves as `piquel_auth`, a role with row privileges only. `migrate`,
connected as the schema owner, grants it `SELECT, INSERT, UPDATE, DELETE` on every table after the migrations,
so a new table needs nothing. A table that needs less, such as append-only
history, gets its exception in
`crates/database/src/connection/runtime_role.sql`, in the same change, and so
does a migration that drops a table listed there. Narrowing a grant on an
existing table is a contract step.

## 6. Let the account's data go with it

A table that holds rows about an account must lose them when the account is
purged. Reference `users(id)` with `ON DELETE CASCADE`, as `profile_pictures`
and `notifications` do, or delete the rows in `deletions().purge`. If the rows
are the account's data, the owner's export includes them: see
[adding an account setting](account-setting.md#7-add-it-to-the-data-export).

## 7. Query it

Write the queries in the repository of the table, under
`crates/database/src/repositories/`, with SQLx's checked macros, as
[PostgreSQL boundary](../architecture/database.md) describes. A new repository
joins the `repositories!` block of `repositories/mod.rs`. SQL never leaves the
database crate.

Then regenerate the query cache and commit it with the migration:

```console
just db prepare
```

Builds compile against the cache, never a database, so a query whose text
changed fails to build until you run it.

## Test it

```console
just db test
```

It migrates a scratch cluster, runs the database tests, which ordinary runs
skip, then `just db prepare-check`, which fails when a migration breaks a cached
query or the cache holds a query the code no longer uses.

A migration that changes existing rows gets a test of its own: it migrates a
schema up to the migration before it, writes rows in the old shape, applies the
migration and checks the result, as
`the_migration_refuses_usernames_that_are_not_handles` does in
`crates/database/src/repositories/handles/tests.rs`. It finds the migration by its
name, so renumbering needs no change.

To look at the migrated schema yourself:

```console
just db scratch -- psql
```

## Document it

The migration documents itself, in its comments. Update
[PostgreSQL boundary](../architecture/database.md) only when the change adds or
changes a rule there, such as an invariant, a lock order or a grant in
[roles](../architecture/database.md#roles).
