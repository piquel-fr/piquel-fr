# Adding a federation provider

This guide adds a sign-in provider, such as GitLab, next to GitHub and Google.
The shared federation code already runs the flow: state, PKCE, browser binding,
signup, linking and unlinking. A provider supplies only its protocol facts and
the way it proves who the user is.

The examples add a hypothetical GitLab provider. Replace `gitlab`, `GitLab` and
`GITLAB` with your provider's names.

## What you'll have at the end

- People can sign up and sign in with the provider, and link or unlink it in
  their settings.
- Administrators unlink it on the dashboard, and operators with
  `auth-service account <user> identities unlink gitlab`, with no change of
  yours: both read the provider list.
- The provider stays off in every environment until its client ID and secret are
  set.

## Before you start

The shared code exchange, `FederationApplication::exchange` in
`apps/auth-service/src/federation/providers/mod.rs`, requires the provider to
support:

- the authorization code flow with PKCE `S256`;
- a client secret sent in the token request's form body.

If the provider needs something else, change the shared exchange for every
provider rather than adding a special case.

Then decide how the provider proves who the user is:

- **OpenID Connect**, as Google does: take the identity only from a signed ID
  token. Verify its signature against the provider's published keys, then its
  issuer, exclusive audience, nonce and expiry. Cache the keys:
  `GoogleProtocol` holds the Rust SDK's `piquel_auth::KeyCache`, which keeps them
  for the response's `max-age`, refetches once when a token names an unknown
  key, and fetches at most once every 30 seconds.
- **OAuth only**, as GitHub does: fetch the profile with the access token.

Either way, the subject is the provider's stable account ID, never an email.
Keep an email only if the provider says it is verified. Call it authoritative
only if the provider hosts the mailbox, as Google does for Gmail addresses and
its Workspace domains: another provider verified the address once, and it may
have changed owners since, as a lapsed domain does. Signup and linking import an
authoritative address as verified, and any other as unverified, with a
verification email.

## 1. Name the provider

Add a variant to `Provider` in `crates/common/src/lib.rs`, and its display name
to `Provider::name` below it:

```rust
/// GitLab `OpenID` Connect identity.
GitLab = "gitlab",
```

The wire name is stored in the database and appears in URLs, such as the
callback's `/login/gitlab/callback`, so never change it once released. Every
`match` on `Provider` now fails to compile: the errors list the places the next
steps fill in. The sign-in and sign-in methods pages list enabled providers by
`Provider::name`, so they need no change.

## 2. Allow it in the database

Three tables restrict `provider_name` with a `CHECK` constraint:
`external_login_identities`, `federation_transactions` and `pending_federation`.
Add a migration that widens all three, following
[adding a migration](migration.md). Widening a constraint is an expand step: the
previous release never writes the new value.

## 3. Declare its variables

In `apps/auth-service/src/config/federation.rs`, add two variables to the
`piquel_common::variables!` block, then map them in `ProviderConfig::variables`:

```rust
piquel_common::variables! {
    // ...
    /// The client ID of auth's GitLab OAuth app, as `AUTH_GITHUB_CLIENT_ID` is
    /// GitHub's.
    const GITLAB_CLIENT_ID = "AUTH_GITLAB_CLIENT_ID";
    /// Where to read the GitLab OAuth app's secret, as for
    /// `AUTH_GITHUB_CLIENT_SECRET`.
    const GITLAB_CLIENT_SECRET = "AUTH_GITLAB_CLIENT_SECRET";
}
```

```rust
Provider::GitLab => (GITLAB_CLIENT_ID, GITLAB_CLIENT_SECRET),
```

`ProviderConfig::from_environment` already reads every provider's pair: an empty
or unset client ID leaves the provider off, and a client ID requires the secret.
The doc comments are the variables' entries in the configuration reference, so
write them for operators. See
[adding a configuration variable](configuration-variable.md).

## 4. Write the provider module

Create `apps/auth-service/src/federation/providers/gitlab.rs`. Model it on
`google.rs` for OpenID Connect, or on `github.rs` for OAuth. It holds everything
specific to the provider:

- **`SCOPES`:** the scopes requested.
- **`impl ProviderEndpoints`:** `pub(super) fn gitlab() -> Self`, with the issuer
  stored beside each subject, the authorization and token URLs, the scopes and
  the identity strategy. A provider whose facts need a request, such as Google's
  key cache, takes the client and may fail:
  `fn google(client: &reqwest::Client) -> Result<Self, FederationConfigError>`.
- **`GitLabProtocol`:** the back-channel URLs the identity step calls, such as
  the key set or the profile endpoint. They are `String`s, so tests can point
  them at a local fixture.
- **`GitLabError`:** one variant per provider-specific check, each with a
  message that says what failed.
- **`impl FederationApplication`:** `pub(super) async fn gitlab_identity(...)`,
  which turns the token response into a `VerifiedIdentity`.
  - Read every response through `Self::json`. It enforces the size limit, and
    keeps the provider's OAuth error when a request fails.
  - Build the result with `VerifiedIdentity::new(Provider::GitLab, subject,
    (email, authoritative), (name, fallback_name), picture)`. It refuses an empty
    or overlong subject, drops an invalid email or a picture off the provider's
    host, and bounds the display name. `authoritative` is `true` only for an
    address the provider hosts. A social signup imports `picture` as the
    account's first picture.
- **Response types:** private `Deserialize` structs for the provider's JSON.

## 5. Connect it in `providers/mod.rs`

In `apps/auth-service/src/federation/providers/mod.rs`:

1. Declare `mod gitlab;` and `pub(super) use gitlab::GitLabProtocol;`.
2. Add `GitLab(#[from] gitlab::GitLabError)` to `ProviderError`, and list it in
   `ProviderError::sign_in_failure` with the other evidence checks, which record
   `SignInFailure::InvalidCredential`.
3. Add `Provider::GitLab => Ok(Self::gitlab())` to `ProviderEndpoints::new`.
4. Add a `GitLab(GitLabProtocol)` variant to `IdentityStrategy`, then its arms:
   - in `IdentityStrategy::extend_authorization`: an OpenID Connect provider
     sends the flow's `nonce`, as `GoogleProtocol::extend_authorization` does;
   - in `FederationApplication::exchange`: call `gitlab_identity`.
5. Add the `Provider::GitLab` arm to `ProviderPicture::parse`: the host its
   pictures are on, and how to ask for the stored size, if it can. Nothing else
   is ever fetched.

## Test it

Add tests to `apps/auth-service/src/federation/tests/protocols.rs`, serving the
provider's endpoints from a local mock, as the Google tests there do. Cover the
evidence the provider must reject, such as a wrong audience, a wrong nonce, an
expired token or a bad signature, not only the successful sign-in. `TestApp`
in `tests/mod.rs` points the GitHub fixture at a local server; its match on
`IdentityStrategy` needs the new variant's arm too.

```console
just test -p auth-service federation
just db test -E 'test(federation)'
```

The first runs the protocol tests; the second the sign-in, signup and linking
flows, which need a database. See [testing](../testing.md).

## Enable it

1. Register an application with the provider in each environment that enables
   it, with that environment's callback URL:

   ```text
   https://<auth origin>/login/gitlab/callback
   ```

2. In
   [`infra/piqueld.toml`](https://github.com/piquel-fr/piquel-fr/blob/main/infra/piqueld.toml),
   add `gitlab_client_id = ""` and `gitlab_secret = "no-provider-secret"` to
   `[spec.variables]`, set `AUTH_GITLAB_CLIENT_ID` and
   `AUTH_GITLAB_CLIENT_SECRET` in the `auth` service's environment, and mount the
   secret, as GitHub's and Google's are.
3. Ship the provider before you enable it. `Provider` is a closed vocabulary
   that older releases cannot read (see
   [domain events](../architecture/database.md#domain-events)), so set an
   environment's client ID in a later deploy than the one that adds the variant:
   [sign-in providers](../operations/sign-in-providers.md#enable-a-provider)
   says how.

## Document it

1. Name the provider in the help of `account <user> identities unlink`, the
   doc comment of `Identities::Unlink` in `apps/auth-service/src/cli/account.rs`.
   Then run `just docs reference`, which adds the two variables to the
   [configuration](../operations/configuration.md) reference and the help to
   [the command reference](../operations/cli-commands.md).
2. Add the provider's callback URL, scopes and registration steps to
   [sign-in providers](../operations/sign-in-providers.md).
3. Name the provider where the others are named: the user guide's
   [introduction](../../user/introduction.md), and the privacy policy and terms
   in `apps/web/assets/policies/`, which say what each provider tells Piquel.

The settings, the dashboard and the CLI list providers from `Provider::ALL`, so
every surface gets the provider without more work; see
[every surface gets the feature](../contributing.md#every-surface-gets-the-feature).
