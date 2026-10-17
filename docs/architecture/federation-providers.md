# Adding a federation provider

A federation provider lets people sign in with an external account, like GitHub or
Google. The shared code already handles the rest of the flow: state, PKCE, browser
binding, signup, linking and unlinking. A new provider supplies only its protocol
facts and the way it proves who the user is.

The examples use a hypothetical GitLab provider. Replace `gitlab`, `GitLab` and
`GITLAB` with your provider's names.

## Before you start

The shared code exchange in `federation/providers/mod.rs` requires the provider to
support:

- the authorization code flow with PKCE `S256`;
- a client secret sent in the token request's form body.

If it needs something else, change the shared exchange for every provider rather
than adding a special case.

Pick how the provider proves identity:

- **`OpenID` Connect** (like Google): take the identity only from a signed ID token.
  Verify its signature against the provider's published keys, then its issuer,
  exclusive audience, nonce and expiry. Cache the keys rather than fetching them on
  every sign-in: `GoogleProtocol` holds the Rust SDK's `piquel_auth::KeyCache`, which
  keeps them for the response's `max-age`, refetches once when a token names an
  unknown key, and fetches at most once every 30 seconds.
- **OAuth only** (like GitHub): fetch the profile with the access token.

Either way, the subject must be the provider's stable account ID, never an email.
Keep an email only if the provider says it is verified.

## 1. Name the provider

Add a variant to `Provider` in `crates/auth-protocol/src/lib.rs`:

```rust
/// GitLab `OpenID` Connect identity.
GitLab = "gitlab",
```

The wire name appears in URLs and in the database, so never change it later.
Every `match` on `Provider` now fails to compile. Those errors list the places you
still need to update.

## 2. Allow it in the database

Three tables restrict `provider_name` with a `CHECK` constraint:
`external_login_identities`, `federation_transactions` and `pending_federation`.
Add a migration in `crates/database/migrations` that widens all three. Never edit
an existing migration.

## 3. Add its configuration

In `apps/auth-service/src/config.rs`, declare the two variables and map them in
`ProviderConfig::variables`:

```rust
/// GitLab-assigned client identifier.
const GITLAB_CLIENT_ID: Variable = Variable::new("AUTH_GITLAB_CLIENT_ID");
/// Reference to the GitLab client secret.
const GITLAB_CLIENT_SECRET: Variable = Variable::new("AUTH_GITLAB_CLIENT_SECRET");
```

The provider is enabled only when both variables are set. Add them to the
environment table in `README.md`.

## 4. Write the provider module

Create `apps/auth-service/src/federation/providers/gitlab.rs`. Model it on
`google.rs` for `OpenID` Connect or `github.rs` for OAuth. It holds everything
specific to the provider:

- **`SCOPES`:** the requested scopes, using `Scope` for standard ones.
- **`impl ProviderEndpoints { fn gitlab() -> Self }`:** the issuer stored beside
  each subject, the authorization and token URLs, the scopes and the identity
  strategy.
- **`GitLabProtocol`:** the back-channel URLs the identity step calls, such as the
  key set or profile endpoint. Tests replace them to point at a local fixture.
- **`GitLabError`:** one variant per provider-specific check, each with a message
  that says what failed.
- **`impl FederationApplication { async fn gitlab_identity(...) }`:** turns the
  token response into a `VerifiedIdentity`.
  - Read every response through `Self::json`. It enforces the size limit and keeps
    the provider's OAuth error when a request fails.
  - Build the result with `VerifiedIdentity::new`, which bounds the subject and
    display name and drops invalid emails.
- **Response types:** private `Deserialize` structs for the provider's JSON.

## 5. Connect it in `providers/mod.rs`

- Declare `mod gitlab;` and re-export `GitLabProtocol`.
- Add `ProviderError::GitLab(#[from] gitlab::GitLabError)`.
- Add the `Provider::GitLab => Self::gitlab()` arm to `ProviderEndpoints::new`.
- Add an `IdentityStrategy::GitLab(GitLabProtocol)` variant, then its arms:
  - in `extend_authorization`: an `OpenID` Connect provider must send the flow's
    `nonce` (see `GoogleProtocol::extend_authorization`);
  - in `exchange`: call `gitlab_identity`.

## 6. Show it in the frontends

In `packages/auth-sdk/src/index.ts`, add the wire name to the `Provider` type and
its display name to `providerName`. The login and settings pages list providers
from `/login/providers`, so they need no other change.

## 7. Test it

Add tests to `apps/auth-service/src/federation/tests.rs`, serving the provider's
endpoints from a local mock (see the GitHub fixture in `TestApp` and the Google
mock test). Cover the evidence the provider must reject, such as a wrong
audience, a wrong nonce, an expired token or a bad signature, not only the
successful sign-in.

## 8. Register and enable it

Register an application with the provider, using this callback URL:

```text
https://<auth origin>/login/gitlab/callback
```

Set `AUTH_GITLAB_CLIENT_ID` and `AUTH_GITLAB_CLIENT_SECRET`, then restart the
service. The provider then appears in `/login/providers`. Add the callback URL
and scopes to the provider list in `README.md`.
