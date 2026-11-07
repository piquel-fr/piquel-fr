# Troubleshooting sign-in

Find what a sign-in failure means and how to fix it, from the error auth or an
SDK reports. Each error comes with an `error` code and an `error_description`
that says what went wrong: search this page for either.

## Where errors appear

- **In the browser, at auth.** Until auth knows the request comes from your
  app, it never sends the browser back to it. It answers `400` with the error
  as JSON instead, and your app hears nothing:

  ```json
  {"error":"invalid_request","error_description":"redirect_uri is not registered for this client; it must match exactly"}
  ```

- **At your redirect URI.** Once auth has checked the client and the redirect
  URI, it sends the browser back with `error`, `error_description`, `state` and
  `iss` in the query. The SDKs report it as an `oauth` error carrying both.
- **At your server.** The code exchange, refreshes and pushed requests answer
  your server with the error as JSON.

## Errors in the browser

| `error_description` | What to do |
| --- | --- |
| `client_id is not a registered, enabled client` | Check the client ID on the app's **Overview** tab. A disabled, suspended or deleted app answers this too. |
| `redirect_uri is not registered for this client; it must match exactly` | Register the URI your app sends, character for character: scheme, host, port, path and trailing slash. See [local development](local-development.md#which-redirect-uris-work-locally) for loopback addresses. |
| `authorization request is malformed: …` | A parameter is repeated or has the wrong type. The rest of the description names it. |

## Errors at your redirect URI

| `error` | Common causes | What to do |
| --- | --- | --- |
| `invalid_request` | The request lacks S256 PKCE, sends `state` or `nonce` longer than 512 bytes, or an `id_token_hint` issued to another app. Or the app requires pushed requests and this one came through the browser. | Fix what the description names. The SDKs send valid requests, and push them whenever auth offers it. |
| `invalid_scope` | The request asks for a scope the app may not request, often `offline_access`, which the SDKs' login routes always request. | Check the scope under **Scopes** on the app's **Settings** tab ([app settings](app-settings.md#settings)). |
| `invalid_target` | `audience` names something other than the app. | Leave `audience` out: an app registered in the console gets access tokens for itself only. |
| `access_denied` | The user selected **Cancel** on the consent screen. | Let the user try again. |
| `login_required` | The request sent `prompt=none`, and the user must sign in first. | Send the user through an interactive sign-in. |
| `consent_required` | The request sent `prompt=none`, and the user hasn't consented to the app yet. | Send the user through an interactive sign-in. |
| `unmet_authentication_requirements` | The user signed in during the request, but still can't reach its `acr_values`. A passkey added by account recovery can't confirm `phr` until the recovery settles. | Tell the user the action needs a stronger sign-in for now. Asking again at once fails the same way. |
| `request_not_supported` | The request sent a signed `request` object. | Send the parameters directly, or push them. |
| `server_error` | Auth failed to complete the request. | Try again. If it keeps happening, [ask for help](#getting-help). |

## Errors at your server

| `error` | `error_description` | What to do |
| --- | --- | --- |
| `invalid_client` | `the client secret is incorrect or expired` | Deploy the app's current secret ([rotating a client secret](rotate-secrets.md)). |
| `invalid_client` | `this client must authenticate with HTTP Basic credentials` | A confidential app sends its secret with HTTP Basic: give it to the SDK. |
| `invalid_grant` | `code is unknown or expired, …` | A code works once, within two minutes. Exchange it as soon as the callback arrives. It also fails when the app, the account or the user's session no longer allows it. |
| `invalid_grant` | `redirect_uri must match the one sent with the authorization request` | Send the same redirect URI at both steps. |
| `invalid_grant` | `code was already used, …` or `refresh_token was already used, …` | A code, or a browser app's refresh token, was presented twice, so auth revoked the tokens issued from it. Sign the user in again. |
| `invalid_grant` | `the sign-in session behind this grant has ended` or `the user withdrew consent for this application` | The user signed out, or removed your app under **Connected apps** in their settings. Sign them in again. |
| `invalid_grant` | `the client or account no longer allows this grant, …` | A scope was removed, or refresh tokens turned off ([app settings](app-settings.md#change-the-settings)). Sign the user in again. |
| `invalid_request_uri` | `request_uri is unknown, expired, already used or issued to another client` | A pushed request lasts 60 seconds and works once. Push a new one for each sign-in. |

## `interaction_required`

Only a page that [signs users in with passkeys itself](passkey-sign-in.md) sees
this, from `/webauthn/related/start` or `/webauthn/related/finish`:

```json
{"error":"This sign-in request needs Piquel's own pages.","code":"interaction_required"}
```

The sign-in needs auth's own pages, for example because the request sent
`prompt=consent` or `prompt=none`, or the account has no passkey. Send the
browser to `/oauth/authorize` instead: with the same `request_uri` when start
answered this, or with a newly pushed request when finish did. The TypeScript
SDK's `signInWithPasskey` does this for you.

## Step-up challenges

An API that needs a stronger or more recent sign-in answers `401` with
`insufficient_user_authentication`, naming the `acr_values` and `max_age` it
needs. Sign the user in again with them, then retry once.
[Step-up authentication](step-up.md) explains how. If the retry fails the same
way, show an error: signing in again would loop.

## SDK errors

Every error from the Rust and TypeScript SDKs carries a category, and for most
categories a reason naming the check that failed. Rust errors return both from
`code()`. TypeScript's `AuthError` has them as `code` and `reason`.

| Category | What failed | What to do |
| --- | --- | --- |
| `discovery` | Fetching or checking auth's metadata. | Configure the issuer exactly as the app's **Overview** tab shows it: `https://auth.piquel.fr`. |
| `keys` | Fetching or reading auth's signing keys. | Usually temporary: the SDKs keep the last good keys. |
| `invalid_token` | A token failed validation. The reason names the check, such as `expired`, `wrong_audience` or `bad_signature`. | For `expired`, `not_yet_valid` or `issued_in_future`, check your server's clock ([below](#clock-skew)). |
| `insufficient_scope` | A valid token lacks a scope the API requires. | Request the scope at sign-in, and allow it on the app. |
| `insufficient_user_authentication` | A valid token's sign-in is too weak or too old. | [Step up](#step-up-challenges). |
| `callback` | The redirect back to your app failed its checks before the code was exchanged: `state_mismatch`, `issuer_mismatch`, `missing_issuer` or `missing_code`. | For `state_mismatch`, the callback belongs to another sign-in attempt: start again from your app. |
| `oauth` | Auth answered with an OAuth error. | Look up its `error` on this page. |
| `network` | Auth couldn't be reached, or answered outside its protocol. | Check your server can reach `https://auth.piquel.fr`, then retry. |

The SDKs' login routes also answer `400` themselves, before any of these:

- **This sign-in has no pending login; start again.** The callback arrived
  without the cookie the sign-in set when it started. Open your app at the same
  host as its redirect URI, such as `127.0.0.1` rather than `localhost`.
- **This sign-in expired; start again.** The user took too long at auth. Start
  again from your app.

## Clock skew

The SDKs allow 30 seconds of clock difference on a token's `exp`, `nbf`, `iat`
and `auth_time`. Access tokens last five minutes, so a server clock off by more
than that rejects tokens as `expired`, `not_yet_valid` or `issued_in_future`.
Keep your servers' clocks synchronized, for example with NTP.

## Getting help

Write to contact@piquel.fr with the `error` and `error_description`, your app's
client ID, and when it happened. Never send the client secret or a token.

To report a vulnerability, write to security@piquel.fr instead.
