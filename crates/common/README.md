# sourceorigin-common

The types [Origin Auth](https://auth.sourceorigin.dev) and its SDKs share:
identifiers, string vocabularies, and the wire types of auth's protocol, such as
token claims, discovery metadata and Bearer challenges.

To sign users in or validate tokens, use
[`sourceorigin-auth`](https://crates.io/crates/sourceorigin-auth) instead, which
depends on this crate and re-exports what an app needs from it.

## Features

With no features, the crate is what the SDKs build on. The others are for
SourceOrigin's own servers, and compile nothing unless enabled: `admin`,
`client-spans`, `config`, `email`, `events`, `similarity` and `sqlx`. The
[API documentation](https://docs.rs/sourceorigin-common) describes each.

It needs Rust 1.88 or newer.

## Versions

`sourceorigin-common`, `sourceorigin-crypto` and `sourceorigin-auth` are released
together, at the same version, and depend on each other at exactly that version.
[The releases](https://github.com/sourceorigin-dev/sourceorigin/releases) list the
changes in each.

## License

[Apache-2.0](LICENSE-APACHE).
