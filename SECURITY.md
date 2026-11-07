# Security policy

Report a vulnerability privately, by email to
[security@piquel.fr](mailto:security@piquel.fr). Never open a public issue,
pull request or discussion about it.

Include what you found, how to reproduce it, and what an attacker could do with
it. Please give us time to fix the issue before you disclose it.

## Scope

- auth.piquel.fr: sign-in, the account settings, the developer console and the
  OpenID Connect endpoints.
- admin.piquel.fr, the admin dashboard.
- piquel.fr.
- The SDKs: `piquel-auth` (Rust) and `@piquel/auth` (TypeScript).

Only what is deployed and the SDKs' latest releases are supported: fixes go to
`main`, then to production and the next SDK release.

The contributor guide's [security pages](docs/dev/security/properties.md)
describe what auth guarantees, and the designs behind account recovery and the
audit history.
