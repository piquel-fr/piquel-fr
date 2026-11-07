# piquel.fr

piquel.fr gives you one account, secured by passkeys, that signs you in to
Piquel's services and to any app built on it. Its sign-in service,
auth.piquel.fr, is an OpenID Connect provider: apps register in its developer
console and sign their users in with the Rust or TypeScript SDK, or any OpenID
Connect library.

This documentation has two parts:

- The [user guide](user/introduction.md) is for people who have a piquel.fr
  account, and for people building apps that sign in with it.
- The [contributor guide](dev/getting-started.md) is for people who change
  piquel.fr itself: development setup, testing, architecture, security, how to
  extend it, and how it is operated.

## Contact

- Questions and feedback: [contact@piquel.fr](mailto:contact@piquel.fr)
- Security vulnerabilities: [security@piquel.fr](mailto:security@piquel.fr).
  Report them privately, never in a public issue; see the
  [security policy](https://github.com/piquel-fr/piquel-fr/blob/main/SECURITY.md).
