# Adding a configuration variable

This guide adds an environment variable that auth-service or sourceorigin-web reads at
startup. A variable is declared once, with the doc comment operators read: the
[configuration](../operations/configuration.md) reference is generated from it,
so the two can't disagree.

## What you'll have at the end

- A variable read once, at startup, into a validated value: a missing or
  invalid one stops the service with an error naming it and saying how to fix
  it.
- Its entry in the configuration reference, with its default.
- Its value in every environment piqueld deploys.

## Before you start

Find the section the variable belongs to. Each declares its variables beside the
code that reads them:

| Section | File |
| --- | --- |
| auth-service itself: origins, listeners, rate limits | `apps/auth-service/src/config/mod.rs` |
| The database connections | `apps/auth-service/src/config/database.rs` |
| Keys | `apps/auth-service/src/config/keys.rs` |
| Sign-in providers | `apps/auth-service/src/config/federation.rs` |
| Email | `apps/auth-service/src/config/email.rs` |
| sourceorigin-web | `apps/web/src/main.rs` |

OIDC clients and signing keys are not configuration: they live in the database.

## 1. Declare it

Add the variable to the section's `sourceorigin_common::variables!` block
(`crates/common/src/config/reference.rs` defines the macro):

```rust
sourceorigin_common::variables! {
    /// The service's own variables, in the configuration reference's order.
    #[cfg(test)]
    pub(crate) const VARIABLES;

    // ...
    /// How many requests one client may make a minute in each rate category, such
    /// as pages, sign-in and tokens.
    const REQUESTS_PER_MINUTE = "AUTH_REQUESTS_PER_MINUTE", default DEFAULT_REQUESTS_PER_MINUTE;
}
/// [`REQUESTS_PER_MINUTE`] when none is configured: enough for a person, not
/// for a browser suite or a scraper.
const DEFAULT_REQUESTS_PER_MINUTE: &str = "120";
```

Each entry becomes a `const` of type `Variable`, and joins the section's list,
`VARIABLES`, in order. Its doc comment is its entry in the reference, rendered as
Markdown outside rustdoc, so write it for operators, without intra-doc links:
what it does, its format, and whether it is required. A blank comment line starts
a new paragraph. `default` names the `&str` constant the code falls back to,
which the reference shows; leave it out when there is none.

Name it `AUTH_…` for auth-service and `WEB_…` for sourceorigin-web.

## 2. Read it

Read the variable in the section's `from_environment`, through `Variable`'s
methods, and keep the validated value in the section's configuration type, such
as `AuthConfig`, `EmailConfig` or sourceorigin-web's `Web`:

| Method | Reads |
| --- | --- |
| `optional()` / `required()` | text, absent or not |
| `flag(default)` | exactly `true` or `false` |
| `parse()` / `parse_or(DEFAULT)` / `parse_optional()` | any `FromStr` type, such as `Origin` or `SocketAddr` |

```rust
let budget: std::num::NonZeroU32 =
    REQUESTS_PER_MINUTE.parse_or(DEFAULT_REQUESTS_PER_MINUTE)?;
```

A secret is never set directly. Its variable holds a `SecretReference`, an
`env://NAME` or `file:///path` that `resolve()` reads. Its bytes stay redacted;
`utf8()` borrows them as text.

Reject a bad value with `variable.invalid(reason)`, or `variable.error(reason,
source)` to keep the parser's error as its source. The reason says what the
operator must change and never repeats the value:

```rust
return Err(id.invalid("must contain 1 to 512 characters assigned by the provider"));
```

Downstream code takes the validated value, never the variable: only the
configuration sections read the environment.

## 3. List a new section

A variable joins the list of its section's block. A new block, for a new
section of auth-service, declares its own `VARIABLES` list and joins the sections
of `configuration_reference_is_current`, in `apps/auth-service/src/config/tests.rs`,
in the order the reference lists them. sourceorigin-web has one section, in
`apps/web/src/main.rs`.

## 4. Regenerate the reference

```console
just docs reference
```

It rewrites `docs/dev/operations/variables/auth-service.md` or `sourceorigin-web.md`,
which the configuration page includes. `just test` fails while they are stale.

## 5. Set it in each environment

Set the variable in the service's `[spec.services.environment]` in
[`infra/piqueld.toml`](https://github.com/sourceorigin-dev/sourceorigin/blob/main/infra/piqueld.toml).
A required variable must be set in the same pull request, or the next deploy
fails to start.

- A value that differs per environment is a variable of the manifest:
  a default in `[spec.variables]`, overridden in an environment's own
  `variables`, and used as `${{ vars.<name> }}`.
- A secret is a `[[spec.secrets]]` entry, which piqueld generates, or stored by
  hand with `piquelctl app secret`, mounted with `[[spec.services.secrets]]`. The
  variable then points at the mount, such as `file:///run/secrets/<name>`. See
  [secrets](../operations/secrets.md).

## Test it

Test the parsing, not the environment. Put the validation on the value, such as
`AuditConfig::parse`, so a test passes it a value and checks the result and the
error, which must name the variable:

```console
just test -p auth-service config
```

To try it end to end, `just preview` deploys the checkout with the manifest's
preview values.

## Document it

The reference documents the variable. When it needs more than its entry, such
as a procedure for choosing its value, add that to its feature's operations
page, such as [email](../operations/email.md), and link the reference.

A variable that is removed is refused at startup rather than silently ignored,
so a deployment that still sets it fails loudly: list it as `AuthConfig::from_environment`
does `AUTH_CLIENTS_FILE`, with the reason it was removed.
