# Step-up authentication

Ask for more than a signed-in user before a sensitive action: a passkey rather
than a GitHub or Google sign-in, or a sign-in from the last few minutes. Your
API answers with a step-up challenge ([RFC 9470]), your app signs the user in
again, and retries the action with the new token.

## Before you start

- You need an app that signs users in ([registering an app](register-an-app.md)),
  and an API that validates its access tokens, with the Rust SDK (`piquel-auth`)
  or the TypeScript SDK (`@piquel/auth`).

## Choose a requirement

A requirement has two optional parts.

- **`acr`: how the user signed in.** Ask for `phr` when a phished or reused
  GitHub or Google login must not be enough, for example to delete data or
  change who can access it. `phr` means a passkey signed in or confirmed the
  session. `urn:piquel:acr:social` is weaker, and `phr` also meets it.
- **`max_age`: how recently, in seconds.** Ask for it when the user should be
  present right now, for example before showing a recovery code or exporting
  their data. Five minutes (`300`) is what Piquel's own settings use. An API
  should ask for a positive age: by the time a token reaches it, `auth_time` is
  already in the past.

Most sensitive actions want both: `phr` within `300` seconds. A `max_age` alone
accepts a recent GitHub or Google sign-in.
[Authentication claims](../reference/oidc.md#authentication-claims) lists what
each value means.

## Require it in your API

Check the access token's `acr` and `auth_time` claims. When they fall short,
answer `401` with a challenge naming the requirement:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="A passkey confirmation is required", acr_values="phr", max_age="300"
```

In Rust, `StepUpRequirement` holds the requirement, and
`AccessToken::require_authentication` checks a validated token against it:

```rust
use piquel_auth::StepUpRequirement;

const DELETE_REPOSITORY: StepUpRequirement = StepUpRequirement::passkey_within(300);

// `token` is the validated `AccessToken`, `validator` the `ResourceValidator` that
// validated it.
if let Err(error) = token.require_authentication(DELETE_REPOSITORY, validator.now()) {
    // Answer 401 with `error.challenge()`.
}
```

Pass the issuer's clock, `ResourceValidator::now`. With the `axum` feature, the
`RequireAuthentication<P>` extractor does all of this for an
`AuthenticationPolicy` `P` that names the requirement.

In TypeScript, `token.requireAuthentication({ acr_values: 'phr', max_age: 300 })`
throws an `AuthError` with the code `insufficient_user_authentication`, whose
`toResponse()` answers with that challenge.

Both SDKs allow 30 seconds of clock difference on `auth_time`.

## Step up in your app

With the SDKs' login routes, a page asks for the requirement itself, and the
SDK sends the user through Piquel and back to the same page:

- In Rust, `user.require::<P>()?` on a `SignedIn` user, for a page, or
  `user.step_up(requirement)` with the requirement an API's challenge named.
- In TypeScript, `user.require(requirement)`, which returns `null` when the
  sign-in already meets it and otherwise the response to send, or
  `user.stepUp(challenge)` with a challenge `parseChallenge` read.

The new sign-in must be the same user, and must meet the requirement. Asked
again on the page's return, the SDKs answer `403` instead of looping.

Without the login routes, when an API answers with
`insufficient_user_authentication`:

1. Start a new authorization request with the challenge's `acr_values` and
   `max_age` (`StepUpRequirement::authorize_params` gives both in Rust). Keep
   the user's place in `state`, and send the current ID token as
   `id_token_hint`, so Piquel issues tokens only for that account.
2. Send the user through it interactively.
3. Check that the new ID token's `sub` is unchanged, then retry the action once
   with the new access token. If it fails the same requirement again, show an
   error: starting another authorization would loop.

Piquel signs the user in again on the same session. The new tokens keep the
same `sid` and carry a newer `auth_time`, so your app's other sessions and other
apps are unaffected.

## Check that it works

1. Sign in to your app with GitHub or Google, or wait more than `max_age`
   seconds after signing in.
2. Try the protected action. Piquel asks for a passkey, only passkeys if you
   asked for `phr`.
3. After you confirm, the action succeeds without asking again.

## Troubleshooting

- **The authorization comes back with `login_required`.** The request sent
  `prompt=none`, which never asks for a passkey. Step up interactively.
- **It comes back with `unmet_authentication_requirements`.** The user signed
  in, but can't reach `phr` for now, as with a passkey added by account recovery
  until the recovery settles. Tell the user, rather than asking again.
- **The retry still fails the requirement.** Check that your API and the SDK
  agree on the requirement, and that your server's clock is synchronized
  ([clock skew](troubleshooting.md#clock-skew)).
- **The user came back as another account.** Signing in as another account ends
  the previous session. Send `id_token_hint`, and refuse a token whose `sub`
  changed; the SDKs' login routes already do.

[RFC 9470]: https://www.rfc-editor.org/rfc/rfc9470
