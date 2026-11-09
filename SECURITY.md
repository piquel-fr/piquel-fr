# Security policy

Report a vulnerability privately, by email to
[security@sourceorigin.dev](mailto:security@sourceorigin.dev). Never open a public issue,
pull request or discussion about it.

Include what you found, how to reproduce it, and what an attacker could do with
it. Please give us time to fix the issue before you disclose it.

## Scope

- auth.sourceorigin.dev: sign-in, the account settings, the developer console and the
  OpenID Connect endpoints.
- admin.sourceorigin.dev, the admin dashboard.
- sourceorigin.dev.
- The SDKs: `sourceorigin-auth` (Rust) and `@sourceorigin/auth` (TypeScript).

Only what is deployed and the SDKs' latest releases are supported: fixes go to
`main`, then to production and the next SDK release.

The contributor guide's [threat model](docs/dev/security/threat-model.md) says
what auth protects, from whom, and which risks it accepts. The pages beside it
describe its [security boundaries](docs/dev/security/boundaries.md), what auth
[guarantees](docs/dev/security/properties.md), and the designs behind account
recovery and the audit history.
