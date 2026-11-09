# SourceOrigin

SourceOrigin gives you one account, your Origin Account, secured by passkeys, that signs you in to
SourceOrigin's services and to any app built on it. Its sign-in service,
Origin Auth (auth.sourceorigin.dev), is an OpenID Connect provider: apps register in its developer
console and sign their users in with the Rust or TypeScript SDK, or any OpenID
Connect library.

This documentation has two parts:

- The [user guide](user/introduction.md) is for people who have an Origin
  Account, and for people building apps that sign in with it.
- The [contributor guide](dev/getting-started.md) is for people who change
  SourceOrigin itself: development setup, testing, architecture, security, how to
  extend it, and how it is operated.

## Contact

- Questions and feedback: [contact@sourceorigin.dev](mailto:contact@sourceorigin.dev)
- Security vulnerabilities: [security@sourceorigin.dev](mailto:security@sourceorigin.dev).
  Report them privately, never in a public issue; see the
  [security policy](https://github.com/sourceorigin-dev/sourceorigin/blob/main/SECURITY.md).
