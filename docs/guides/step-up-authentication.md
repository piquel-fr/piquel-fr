# Step-up authentication

Some actions need more than a signed-in user: a passkey rather than a social
sign-in, or a sign-in from the last few minutes. An application asks for this
with a step-up challenge ([RFC 9470]). Auth then signs the user in again, and
the application retries the action with the new token.

## Choosing a requirement

A requirement has two optional parts.

- **`acr`: how the user signed in.** Ask for `phr` when a phished or reused
  social login must not be enough, for example to delete data or change who
  can access it. `phr` means a passkey signed in or confirmed the session.
  `urn:piquel:acr:social` is weaker, and `phr` also meets it.
- **`max_age`: how recently.** Ask for a number of seconds when the user should
  be present right now, for example before showing a recovery code or
  exporting their data. Five minutes (`300`) is what auth's own settings use.
  An API should ask for a positive age: by the time a token reaches it,
  `auth_time` is already in the past. `0` only makes sense in an authorization
  request, where it means "sign in again now".

Most sensitive actions want both: `phr` within `300` seconds. A `max_age`
alone accepts a recent social sign-in.

## Resource servers

Check the access token's `acr` and `auth_time` claims. When they fall short,
answer `401` with a challenge naming the requirement:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="A passkey confirmation is required", acr_values="phr", max_age="300"
```

In Rust, `piquel_auth_protocol::step_up::StepUpRequirement` holds the
requirement and checks the claims. Auth's own settings use the same check.

```rust
use piquel_auth_protocol::step_up::StepUpRequirement;

const DELETE_REPOSITORY: StepUpRequirement = StepUpRequirement::passkey_within(300);

if let Err(requirement) = DELETE_REPOSITORY.check(acr, auth_time, now - LEEWAY) {
    // Answer 401 with the challenge for `requirement`.
}
```

Pass `now` minus your clock-skew leeway, since `auth_time` comes from auth's
clock.

## Clients

When an API answers with `insufficient_user_authentication`:

1. Start a new authorization request with the challenge's `acr_values` and
   `max_age` (`StepUpRequirement::authorize_params` gives both). Keep the
   user's place in `state`.
2. Send the user through it interactively. With `prompt=none`, auth answers
   `login_required` instead of asking for a passkey.
3. Retry the action once with the new access token. If it fails the same
   requirement again, show an error. Starting another authorization would loop.

Auth signs the user in again on the same session. The new tokens keep the same
`sid` and carry a newer `auth_time`, so session-based logout and other
applications are unaffected. That holds only if the user signs in as the same
account: signing in as another one ends the previous session. Send the current
ID token as `id_token_hint`, so auth issues tokens only for that account, and
check that the new token's `sub` is unchanged before retrying.

Server-rendered apps should do this in their server hook: a challenge from an
API becomes a redirect to the app's login route, with the requirement attached.

## Auth's own settings

Auth's account APIs use the session cookie, not bearer tokens, so they don't
send RFC 9470 challenges. They check the same requirement and answer
`403 {"error": "...", "code": "step_up_required", "max_age": 300}`. The
settings frontend then confirms the passkey on auth's `/confirm` page.

[RFC 9470]: https://www.rfc-editor.org/rfc/rfc9470
