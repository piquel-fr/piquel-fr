# Secrets

This page helps you find the secrets SourceOrigin's deployments use, store the
ones piqueld can't generate, and rotate any of them.

Every secret reaches a service as a file under `/run/secrets/`, and auth reads
it through a `file://` reference (see [configuration](configuration.md)).
piqueld keeps two kinds:

- **Generated secrets** are declared in `infra/piqueld.toml` (`[[spec.secrets]]`).
  piqueld generates each one per environment and per preview, on the first
  deployment that mounts it, and never changes it unless you regenerate it.
- **Stored secrets** are set by hand with `piquelctl app secret`, for the
  environments that may mount them. Their values can't be read back.

## List the secrets

```sh
piquelctl env secret sourceorigin --env production list   # generated, with their versions
piquelctl app secret sourceorigin list                    # stored, with who may mount them
```

Neither prints a value.

## Store a secret

Set a stored secret before the first deployment that mounts it, which fails
without it. Each is mountable by the environments that use it only:

```sh
piquelctl app secret sourceorigin set resend-production --stdin --environments production --no-previews
```

`--stdin` asks for the value without echo on a terminal, and drops one trailing
newline. `--file <path>` reads it from a file instead.
[Stored secrets](#stored-secrets) lists each one's access and where its value
comes from.

## Rotate a stored secret

1. Get the new value from where the secret comes from, such as a new Resend key.
2. Set it again under the same name, with the same access:

   ```sh
   piquelctl app secret sourceorigin set resend-production --stdin --environments production --no-previews
   ```

3. Deploy the environments that mount it. Running services keep the old value
   until then. Deploy staging with
   `piquelctl --timeout 30m env deploy sourceorigin staging`, and production by
   [deploying its own release again](deploying.md#pick-up-a-changed-secret-in-production).
4. Revoke the old value where it came from, once the deployments succeeded.

[Email](email.md#rotate-a-resend-key) and
[sign-in providers](sign-in-providers.md#rotate-a-client-secret) give the
steps for their keys, and [audit history](../security/audit-history.md#rotating-the-audit-key)
for the audit keys, which change in a commit.

## Rotate a generated secret

Check the secret's row in [generated secrets](#generated-secrets) first: some
must never be regenerated, and others need care.

1. Generate a new value:

   ```sh
   piquelctl env secret sourceorigin --env production regenerate <name>
   ```

2. Deploy the environment. Running services keep the old value until then.

> **Warning:** a [restore or a rollback](deploying.md#roll-back-production)
> deploys the secret versions the earlier deployment used, so it brings an old
> value back.

### The database runtime password

`database-runtime-password` is `sourceorigin_auth`'s password. The next deployment's
`migrate` job sets the new one before the rollout. From then until the new auth
replicas are healthy, the old replicas keep their open connections but can't
open new ones.

If that deployment fails after `migrate`, auth goes down as its pool's
connections expire, within 30 minutes. So rotate it during a deployment you
watch, and fix forward if it fails: a retry reuses the new secret.

## Generated secrets

| Secret | Mounted by | What it is | Regenerating it |
| --- | --- | --- | --- |
| `database-password` | `postgres`, the `migrate` job | the superuser `sourceorigin`'s password | **never**: the database keeps the password it stored when its volume was created, so the `migrate` job, which logs in with the new value, fails and every deployment after it stops. Regenerating makes a value nobody sees, so it can't be set in PostgreSQL first either: there is no supported way to change this password yet |
| `database-runtime-password` | `auth` | `sourceorigin_auth`'s password | takes effect on the next deployment: see [the database runtime password](#the-database-runtime-password) |
| `key-encryption-key` | `auth` | `AUTH_KEY_ENCRYPTION_KEY`, which seals the signing keys in the database | **never**: the stored signing keys would no longer open, and auth can't change it |
| `token-digest-key` | `auth` | `AUTH_TOKEN_DIGEST_KEY` | ends every refresh token and login in progress under it: change it in two deployments instead, as [changing the token digest key](signing-keys.md#change-the-token-digest-key) describes |
| `signing-key` | `auth` | the RSA key from before signing keys moved to the database, now `AUTH_TOKEN_DIGEST_KEY_ACCEPTED`, which the `signing-key-import` job imports into an empty key set | ends the refresh tokens still under it: leave it until `keys digest-usage` lists none, then remove it as its comment in the manifest says |
| `audit-key` | `auth`, in previews | the seed that signs a preview's audit checkpoints | makes the preview's earlier checkpoints fail verification |
| `no-provider-secret` | `auth` | the placeholder mounted for a sign-in provider that's off | nothing: auth never reads it |

Each is 32 random bytes, as hex or unpadded base64url text, except
`signing-key`, a 3072-bit RSA key.

## Stored secrets

| Secret | Mountable by | What it is |
| --- | --- | --- |
| `resend-production` | production | the Resend key production sends with: see [email](email.md) |
| `resend-dev` | staging and previews | the Resend key for `dev.sourceorigin.dev` |
| `github-production`, `github-staging` | that environment | its GitHub OAuth app's client secret: see [sign-in providers](sign-in-providers.md) |
| `google-production`, `google-staging` | that environment | its Google OAuth client's secret |
| `audit-key-production-2`, `audit-key-staging-2` | that environment | the seed that signs its audit checkpoints, whose verifier key is committed: see [audit history](../security/audit-history.md#the-audit-key) |

The manifest's variables pick which stored secret each environment mounts:
`smtp_secret`, `github_secret`, `google_secret` and `audit_key`.

The [telemetry stack](telemetry.md) has one generated secret of its own,
`grafana-admin-password`.

Signing keys are not secrets of the manifest: auth keeps them in its database
and rotates them on its own (see [signing keys](signing-keys.md)).
