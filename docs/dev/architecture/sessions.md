# Sessions

This page explains how auth keeps a browser signed in: the session row and its
cookie, how a sign-in creates or re-authenticates one, how a passkey confirms
it, and how it ends. Read it before changing anything that signs a browser in or
out, or checks how it signed in.

The code is in `apps/auth-service/src/security/session.rs` (`Session` and its
extractors), `src/sessions` (listing and signing out, for the settings and the
CLI) and `crates/database/src/repositories/sessions.rs` (`SessionRepository`).

## The session and its cookie

A session is one row of `sessions`: its account, the methods that authenticated
it, when it signed in (`authenticated_at`), when a passkey last confirmed it
(`passkey_confirmed_at`) and with which passkey (`passkey_id`), its absolute
expiry, and the coarse browser family and IP address it was last seen from.

The browser holds a random secret in the `__Host-sourceorigin_session` cookie:
host-only, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`, for 30 days
(`BrowserCookie` in `src/security/cookie.rs`). Only the secret's SHA-256 digest is
stored, in `browser_session_secrets`. A cookie that is malformed, or sent twice,
counts as absent, so an injected cookie can never shadow the browser's own.

`Session::optional` finds the session by the cookie's digest, if it is
unrevoked, unexpired and its account active. The extractors (`OptionalSession`,
`Session`, `Confirmed`) and authorization requests resolve it with
`Session::resolve`, which also records its activity: `last_seen_at` and its IP
are written at most once every five minutes (`LAST_SEEN_INTERVAL`), so reads
rarely become writes.

## Signing in

Every sign-in calls `Session::sign_in` inside the transaction of the operation
that proved who the browser is, with the `Credential` it proved it with:

| Credential | From | Confirms the session |
| --- | --- | --- |
| `Passkey` | a passkey assertion (`src/passkey`), or restoring an account scheduled for deletion | yes |
| `Probation` | the passkey of a recovery still in probation | no |
| `Federation` | a GitHub or Google sign-in (`src/federation`) | no |

`sign_in` first locks the account, which must be active, so a sign-in and a
disablement serialize. Then it reads the browser's current session:

- **None, or another account's:** it revokes that session
  (`RevocationReason::AccountSwitched`) and creates a new one, which expires 30
  days later. A passkey credential confirms it at once, so an action right after
  signing in asks for nothing more.
- **This account's:** it re-authenticates that session instead (see below), so
  the session ID, which tokens carry as `sid`, stays the same.

Either way it records `SignedIn` and returns a `SignedIn` holding the new
session secret and the browser's device secret (see
[known devices](#known-devices)). The caller sets both cookies with
`SignedIn::set_on`, only after its transaction commits.

Three sign-ins differ:

- **Signing up** and a **recovery link** sign in with `Session::sign_in_anew`,
  which always revokes the browser's session and creates a new one, so an
  existing session can neither make a recovery's link fail nor carry over. The
  browser becomes known to the account without an alert.
- A **passkey sign-in on an app's own page** (`src/passkey/related.rs`) creates a
  session with `Session::create_inline`, which has no browser secret and so no
  cookie: only the tokens the app gets from it use it. It is listed and signed
  out like any other. It never sees the device cookie either, so it is never a
  new device's: the related origin's passkey ceremony already needed the
  passkey itself.

## Known devices

A browser keeps a second host-only cookie, `__Host-sourceorigin_device`: a
random secret that lives 400 days, the most browsers allow, and is set again
by every sign-in. Signing out deletes only the session cookie, so the browser
stays known. `known_devices` stores, per account, the SHA-256 digest of each
device secret that signed in, its last browser family, and when it was first
and last seen.

In the sign-in's transaction, `Session::sign_in` remembers the browser
(`SessionRepository::remember_device`). A browser without a device cookie gets
a new one. When the account did not know its digest, the sign-in is a new
device's: `SignedIn` records `new_device: true`, which gives the owner a
`NewDeviceSignIn` security notification (see
[notifications](notifications.md#security-alerts)). `sign_in_anew` remembers the
browser without the flag. Maintenance deletes a known device unused for 400
days, by which time its cookie expired too. The data export, `GET
/account/devices`, `auth-service account <user> sessions known`, the
**Devices** settings tab and the dashboard's account page list them.

## Re-authenticating and confirming

`Session::reauthenticate` records a new authentication of an existing session.
What it may do depends on the credential:

- A **passkey** confirms the session: `passkey_confirmed_at` becomes now, the
  passkey is recorded, and `passkey` joins its methods.
- A **provider**, or a recovery's passkey in **probation**, renews
  `authenticated_at`, but only while no passkey has confirmed the session, since
  either would lower its `acr`. Otherwise it is refused, with `passkey_required`.

Every re-authentication replaces the browser secret, so the cookie from before
stops working, and a copy of it never gains the new authentication.

A settings change that needs a fresh confirmation runs the confirmation ceremony
at `/account/passkeys/confirm/start` and `/finish` (`src/passkey/confirmation.rs`).
The ceremony is bound to the session that started it, and its finish
re-authenticates that session with the passkey and records `PasskeyConfirmed`. A
recovery's passkey in probation never confirms.

## Authentication claims

`SessionAuthentication::from(&StoredSession)` derives how a session
authenticated, as tokens report it:

- `acr` is `phr` once a passkey confirmed the session, and
  `urn:sourceorigin:acr:social` before.
- `auth_time` is the last passkey confirmation, or else the sign-in.
- `amr` is the union of its methods' values: `pop`, `mfa` and `user` for a
  passkey, `fed` for a provider.

The age counts from the confirmation itself, so using a confirmation never
extends it. Token issuance, authorization requirements and auth's own step-up
checks all read this one type. An authorization code copies it when it is
issued, and a refresh family copies it from its code, so a grant keeps reporting
the authentication it started with ([authorization flow](oidc.md)). The OIDC
reference lists the claims as apps see them:
[authentication claims](../../user/reference/oidc.md#authentication-claims).

`Confirmed<MAX_AGE>` extracts a session whose confirmation is at most `MAX_AGE`
seconds old, five minutes by default (`CONFIRMATION_MAX_AGE`), checked with
`StepUpRequirement::passkey_within`, the rule bearer-protected resources apply.
Otherwise it answers `403` with `step_up_required`, and the page confirms, then
retries. The operation checks the confirmation again under the account lock
(`Owner::lock_confirmed`), so a session revoked meanwhile cannot finish it.

## Expiry and revocation

A session expires 30 days after it was created. Re-authenticating never extends
it, and neither do the refresh tokens issued from it, which expire with it.
Expiry is passive: the lookups ignore an expired session, and nothing is recorded
or sent.

Ending a session early has one path: `DatabaseTransaction::revoke_sessions`. It
revokes the account's sessions in a `SessionScope` (one, every other one, or all),
revokes the refresh families issued from them, and records one `SessionRevoked`
per session with its `RevocationReason`. The repository method underneath is
private to the database crate, so no revocation can skip the event. Its callers:

- `Session::revoke`, attributed to the request's own session: signing out, and
  the account switch of a sign-in.
- `AccountService`'s session operations (`src/sessions`), which sign one session
  or every other one out from the settings, the admin dashboard and
  `auth-service account <user> sessions`. They need a session but no passkey
  confirmation: a user who suspects a stolen cookie must be able to act at once.
- Changes that end the account's other sessions: removing a passkey
  (`src/passkey/settings.rs`), unlinking an identity
  (`src/federation/identities.rs`) and reporting a history entry as not the
  owner's (`src/history`). Undoing a recovery (`src/recovery`) ends every session.
- `Session::end_all`, for an account disabled, scheduled for deletion, purged or
  recovered, and for `AdminService::revoke_user_sessions`, which the dashboard
  and `auth-service session revoke-all` run: every session, then every
  refresh grant of the account, those of sessions that already expired included.

Signing out (`AccountService::sign_out`) ends the browser's session and clears
its cookie. RP-initiated logout signs out the same way, recording the client
that asked ([logout](oidc.md#logout)).

## Back-channel logout

Recording `SessionRevoked` queues the logout tokens of the session's apps, in
the same transaction. A trigger records each client that redeemed a code from the
session in `oidc_session_clients`, and the `backchannel_logout` channel creates
one delivery per such client that registered a back-channel logout URI. The
delivery workers sign and post each token outside the request, retrying for up
to an hour until the app accepts it. So every app of a revoked session is sent a
logout token, and no app of an expired one is.

[The delivery queue](delivery-queue.md#channels) describes the channel, and
[back-channel logout](../../user/apps/back-channel-logout.md) what an app receives.

## The admin dashboard's session

The admin dashboard, on its own origin, keeps a session of its own that hangs off
an auth session (`DashboardSignIn` in `src/admin/sign_in.rs`):

1. Auth's handoff page hands a session signed in with a passkey, of an account
   that holds administrator rights, to the dashboard, once a passkey proved the
   handoff in a ceremony started for it. It answers with a code that works once,
   for 60 seconds, bound to the dashboard's state cookie
   (`__Host-sourceorigin_dashboard_state`).
2. Redeeming the code creates a `dashboard_sessions` row naming the auth session,
   confirmed by the handoff's proof, which ends 12 hours later however busy, and
   the `__Host-sourceorigin_dashboard` cookie on the dashboard's origin, whose
   digest alone is stored, for those 12 hours.
3. Every request finds the dashboard session only while its auth session is
   active, it was used in the last 30 minutes and it has not reached its end, and
   counts as its latest use. It checks again that the account holds
   administrator rights and that the auth session's `acr` is `phr`.

So signing out of auth, revoking the auth session or replacing it ends the
dashboard's too, while signing out of the dashboard ends only its own. Revoking
the account's administrator rights deletes its dashboard sessions and pending
handoffs in the same transaction; writing or redeeming a handoff holds those
rights, so neither outlives a revocation. Cleanup deletes the sessions that
ended. The
dashboard keeps its own confirmation time, set only by a passkey proof made for
it, and a change needs that confirmation from the last five minutes; the auth
session's confirmation never counts. [admin.sourceorigin.dev](surfaces.md#adminsourceorigindev)
describes the handoff and confirmation from the administrator's side.
