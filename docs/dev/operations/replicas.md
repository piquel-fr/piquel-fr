# Running several replicas

This page helps you change how many auth replicas an environment runs, and
explains what keeps them consistent.

Auth keeps its state in PostgreSQL, so any number of replicas can serve one
environment. Two already overlap on every deployment: auth mounts no volume, so
piqueld starts the new replica, after the `migrate` job, before stopping the old
one. On one node, a second replica removes the restart gap after a crash, but
adds no capacity.

## Change the number of replicas

1. Set `auth_replicas` in `infra/piqueld.toml`. The default is 1. To change one
   environment only, set it in that environment's `variables`:

   ```toml
   [spec.environments.production.variables]
   auth_replicas = 2
   ```

2. Merge the change to `main`. Staging deploys it.
3. [Promote](deploying.md#promote-to-production) staging to apply it to
   production.

Change it in the file: piquel-fr reads its manifest from the repository.

## What replicas share

- **State.** Sessions, ceremonies, federation state, rate-limit budgets and
  refresh-token rotation live in PostgreSQL. Database tests build two instances
  on one database, to check that sign-in, logout, budgets and refresh rotation
  span them.
- **Configuration.** Replicas must run with the same `AUTH_*` settings, which
  the manifest gives them. They share the `key-encryption-key`, which opens the
  signing keys in the database, and the token digest keys, from which
  refresh-token digests and email and recovery links derive. They sign audit
  checkpoints with the same key, `AUTH_AUDIT_KEY_PROVIDER`: the stored
  `audit-key-production` or `audit-key-staging`, or a preview's generated
  `audit-key`. See [secrets](secrets.md).
- **Clients.** OIDC clients, and the public-client origins CORS allows, are read
  from the database on each request, so a client change reaches every replica at
  once.

## What each replica keeps

Each replica caches only signing keys: Google's, and auth's own key set, which
it reloads each minute. A signing key change reaches every replica within a
minute (see [signing keys](signing-keys.md#how-replicas-load-keys)).

## Background jobs

Jobs run through one runner (`apps/auth-service/src/jobs/mod.rs`):

- **Exclusive jobs** hold a PostgreSQL advisory lock while they run, so one
  replica at a time runs each, and the others skip that run. They include
  expired-state cleanup and the purge of deleted accounts, every five minutes,
  audit sealing, every five seconds, and the audit chain's verification, once
  none was recorded for six hours.
- **Signing key rotation** runs on every replica each minute, in a transaction
  that takes a transaction-level advisory lock if it's free, so one replica at a
  time advances it. The `keys` commands wait for the same lock.

A run that fails or panics is logged, and retried at the next interval. On
shutdown, once in-flight requests drain, running jobs get 10 seconds to finish,
and cleanup stops after its current batch. Then they are cancelled, which
closes their connection and releases their lock.

Jobs raise alerts for administrators when something keeps going wrong: see
[respond to an alert](administration.md#respond-to-an-alert) for each.

## Migrations

During a deployment, the previous release keeps serving against the new
schema until its replacement is healthy. So every migration keeps the previous
release working: a column or table is dropped only in a later release, once no
deployed code uses it (see [database](../architecture/database.md)).
