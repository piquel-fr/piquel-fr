# sourceorigin-crypto

The cryptography [Origin Auth](https://auth.sourceorigin.dev) and its Rust SDK
share, so both judge keys and signatures the same way: secrets and digests, PKCE,
RS256 signing and verification of JSON Web Tokens, AES-256-GCM sealing, and signed
notes. It builds on [aws-lc-rs](https://docs.rs/aws-lc-rs), which needs a C
compiler.

To sign users in or validate tokens, use
[`sourceorigin-auth`](https://crates.io/crates/sourceorigin-auth) instead, which
depends on this crate.

It needs Rust 1.88 or newer. The
[API documentation](https://docs.rs/sourceorigin-crypto) describes each primitive.

## Versions

`sourceorigin-common`, `sourceorigin-crypto` and `sourceorigin-auth` are released
together, at the same version, and depend on each other at exactly that version.
[The releases](https://github.com/sourceorigin-dev/sourceorigin/releases) list the
changes in each.

## License

[Apache-2.0](LICENSE-APACHE).
