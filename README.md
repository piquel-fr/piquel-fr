# piquel.fr

The monorepo behind piquel.fr: one account, secured by passkeys, for Piquel's
services and any app built on them.

- **auth.piquel.fr** is a passkey-first OpenID Connect provider. It serves
  sign-in, the account settings and the developer console, where anyone can
  register an app. It is one Rust executable, with PostgreSQL as its only data
  service. GitHub and Google are optional ways to sign in.
- **admin.piquel.fr** is the admin dashboard, served by the same executable on
  a private listener.
- **piquel.fr** is the homepage and policies.
- **The SDKs**, `piquel-auth` for Rust and `@piquel/auth` for TypeScript, sign
  users in and validate auth's tokens.

## Documentation

The [documentation](https://docs.piquel.fr) has a user guide, for account holders and
app developers, and a contributor guide, for people who change piquel.fr.

## Quick start

```console
just install-tools   # once
just build
just preview         # deploy this checkout to a private preview
```

See [getting started](docs/dev/getting-started.md) for the tools these need.

## Repository

| Path | What it is |
| --- | --- |
| `apps/auth-service` | auth.piquel.fr, the admin dashboard and the operator CLI |
| `apps/web` | piquel.fr's own site |
| `crates/` | `auth-sdk` (the Rust SDK), `common`, `crypto`, `database`, `telemetry` and `ui` |
| `packages/auth` | the TypeScript SDK |
| `infra/` | Dockerfiles and piqueld deployments |
| `tests/` | the browser tests and the cases every SDK passes |
| `docs/` | the documentation book |

## Contact

- Questions and feedback: [contact@piquel.fr](mailto:contact@piquel.fr)
- Security vulnerabilities: [security@piquel.fr](mailto:security@piquel.fr),
  privately; see [SECURITY.md](SECURITY.md).

## License

Piquel is free to use, change and share for any purpose except a commercial one,
under the [PolyForm Noncommercial License 1.0.0](LICENSE). The SDKs, and the
crate they depend on, are under the [Apache License 2.0](LICENSE-APACHE) instead,
so any application, commercial or not, can sign its users in with Piquel:
`crates/auth-sdk`, `crates/common` and `packages/auth`.
