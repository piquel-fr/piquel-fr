# Adding a feature to the SDKs

This guide adds a feature to both SDKs, the Rust SDK `sourceorigin-auth` and the
TypeScript SDK `@sourceorigin/auth`, such as a claim apps can read. The SDKs share
their wire types with auth, and pass the same test vectors, so every SDK accepts
and rejects the same inputs. [SDK design](../architecture/sdk.md) describes
what they do; this page is the order you change them in.

The examples follow the `picture` claim, which apps read as
`SignedIn::picture()` in Rust and `user.picture` in TypeScript.

## What you'll have at the end

- The wire type in `sourceorigin_common::protocol`, which auth serializes and the Rust
  SDK reads, and its TypeScript declaration, generated from it.
- The feature in both SDKs, under the same names and with the same behavior.
- Vectors in `tests/sdk-vectors` that both SDKs pass.
- The SDK design, and each SDK's own documentation, saying how to use it.

## Before you start

- The Rust SDK is the reference implementation. Write the feature there first;
  the TypeScript SDK mirrors its behavior and names.
- Check what the feature does to older SDKs, which apps keep running: a new
  claim must be optional, and a value a newer auth may add to a vocabulary must
  not fail them. See [forward compatibility](../architecture/sdk.md#forward-compatibility).

## 1. Define the wire type

Add the field or type to `crates/common/src/protocol`, in the module of its
document: `claims`, `metadata`, `jwt`, `oauth`, `challenge`, `step_up` or `sdk`.
Its doc comment is also its documentation in TypeScript:

```rust
/// URL of the profile picture, a square JPEG, with the profile scope. Absent
/// when the account has none. A new picture has a new URL, so the image at one
/// never changes and may be cached for good.
#[serde(default, skip_serializing_if = "Option::is_none")]
pub picture: Option<String>,
```

- A struct the TypeScript SDK reads derives `ts_rs::TS` under `cfg(test)`, as the
  others in the module do.
- A claim name is a `Claim` variant in `jwt.rs`.
- A closed vocabulary is a `str_enum!`, which older SDKs cannot extend: a value
  they don't know is dropped or reads as none. Use `open_str_enum!` for values a
  newer peer may add, such as OAuth error codes.
- A new failure is an `ErrorReason`, and its category an `ErrorCategory`, in
  `sdk.rs`, which every SDK reports the same way.

## 2. Issue it from auth

Auth builds its tokens and documents from these types, never with `json!`, so
set the new field where auth fills in the struct. The profile claims are built
in `apps/auth-service/src/oidc/token.rs`, and `Scopes::release`, in
`apps/auth-service/src/oidc/mod.rs`, keeps each only under the scope that
releases it, so a new claim needs its scope's arm there. Discovery advertises the
claims in `SUPPORTED_CLAIMS`, beside it. Auth and the Rust SDK then share one
definition.

## 3. Regenerate the TypeScript declarations

A new type joins `generate()` in `crates/common/src/protocol/typescript.rs`, in
the group of its module. A closed vocabulary joins `closed!`, an open one
`open!`, and an ID or a validated string `builtin!`. A new field of a type
already listed needs nothing there. Then:

```console
just sdk-types
```

It rewrites `packages/auth/src/protocol.ts`. `just test` fails while it is
stale.

## 4. Add it to the Rust SDK

In `crates/auth-sdk/src`, read the new type where the SDK decodes its document,
and expose it under the name both SDKs will use, with a doc comment:

```rust
/// The URL of the user's profile picture, a square JPEG, when the `profile`
/// scope was granted and the account has one.
pub fn picture(&self) -> Option<&str> {
    self.claims().profile.picture.as_deref()
}
```

`sourceorigin_auth::protocol` re-exports the shared modules by name, in
`crates/auth-sdk/src/lib.rs`: that list is the SDK's contract, so a new
protocol module joins it.

## 5. Add it to the TypeScript SDK

In `packages/auth/src`, mirror the Rust SDK:

1. Decode the field where the SDK reads its document. The decoders read exactly
   what the Rust types accept: the profile claims are in `claims.ts`, as
   `picture: json.optional(json.string)`.
2. Add a new value of a closed vocabulary to its list in `vocabulary.ts`. Each
   list is keyed by the generated union, so `tsc` refuses one that misses a
   value.
3. Expose it under the Rust SDK's name, as the `picture` getter of `SignedIn`
   does in `login.ts`.

The SDK has no runtime dependencies and runs in browsers, Node, Bun and Workers:
use `fetch` and WebCrypto only.

## 6. Pin it with vectors

Add cases to the generator, `crates/crypto/tests/sdk_vectors.rs`, in the method of
their category, such as `tokens` or `id_tokens`. A case gives the inputs, a fixed
`now`, and either the parsed value or the expected error's category and reason.
Then:

```console
just sdk-vectors
```

It rewrites `tests/sdk-vectors`, which both SDKs' tests read. A new category of
cases also needs its method called from `sdk_vectors_are_current`, its directory
in `Vectors::finish`, its row in the
[vectors' README](https://github.com/sourceorigin-dev/sourceorigin/blob/main/tests/sdk-vectors/README.md),
and a runner in each SDK: `crates/auth-sdk/src/tests.rs` and
`packages/auth/test/vectors.test.ts`.

## Test it

```console
just test           # Rust, the vectors and the generated files included
just web test       # the TypeScript SDK, the vectors included
just web smoke      # the built TypeScript SDK in Node, Bun and workerd
```

Test what the vectors can't show in each SDK's own tests: the type tests in
`packages/auth/test/types.ts`, which `tsc` checks, and the compile-fail tests in
`crates/auth-sdk/tests/ui`, for misuse that must not compile.
`tests/browser/sdk.spec.ts` signs in through the TypeScript SDK against the real
binary; extend it when the feature changes the login flow.

## Document it

1. Describe the behavior in [SDK design](../architecture/sdk.md), the contract
   every SDK follows: its wire types, checks, order of checks and errors.
2. Show how to use it in each SDK's own documentation: the Rust SDK's crate
   documentation, in `crates/auth-sdk/src/lib.rs`, and the TypeScript SDK's
   [README](https://github.com/sourceorigin-dev/sourceorigin/blob/main/packages/auth/README.md),
   which is also its page on npm.
3. If apps see something new, such as a claim, describe it in the user guide's
   [OpenID Connect reference](../../user/reference/oidc.md), or the guide of the
   task it serves.

Both SDKs get every feature, as
[every surface gets the feature](../contributing.md#every-surface-gets-the-feature)
asks; the vectors are how they stay equal.
