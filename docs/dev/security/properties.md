# Security properties

This page lists the guarantees auth makes about passkeys, handles, sessions and
browser flows, and the limits it enforces. [Security boundaries](boundaries.md)
maps where they are checked, and the [threat model](threat-model.md) says what
they defend against. The pages after this one explain the larger designs in
detail.

- Passkeys require user verification and prefer resident credentials. Synced
  passkeys and security keys are accepted. On Android, signup and adding a passkey
  offer an explicit Google Password Manager option for devices with Google services,
  never chosen automatically; a standard passkey or security key stays the default.
  Authentication supports the browser account picker and a handle fallback.
- Every account page tells the browser's password manager, by the WebAuthn Signal
  API, the account's current handle and display name, and the credential ID of
  every passkey that still signs in: the passkeys sign-in itself checks. Where the
  browser supports it, its passkeys then show a new handle, and one removed in the
  settings disappears from it instead of failing at sign-in. A security key keeps
  its copy, which only fails.
- An account's handle is its public identifier and login name, released as
  `preferred_username`: 3–32 characters of `[a-z0-9-]`, without a leading, trailing
  or double hyphen, so it is a valid DNS label. Signup trims and lowercases it, and
  refuses reserved names (infrastructure labels such as `auth` and `www`, RFC 2142
  mailboxes, sourceorigin.dev routes, the brand, and the handles administrators reserve)
  and names that look like one: hyphens
  are dropped, and `0`, `1` or `i`, `5`, `rn` and `vv` read as `o`, `l`, `s`, `m` and
  `w`. Every handle and look-alike stays unique, current or not: a handle is not
  reassigned to another account unless an operator releases it, though its former
  owner may take it back. Handles are not secret: handle sign-in says when no
  active account has one, and signup names the look-alike that blocks one (see
  [handles](handles.md)).
  The Profile settings change the handle, which needs a passkey confirmation
  like other sensitive changes and is refused within 30 days of the last change,
  saying when it may change again. The handle chosen at signup has no cooldown,
  so it can be corrected at once. They change the display name too, which
  grants nothing, so it needs only ordinary login and no cooldown
  (`PATCH /account/profile` with `{"display_name": …}`). Either bumps the profile
  version, so relying parties refresh `preferred_username` or `name`.
- An account's profile picture, set on the Profile settings tab, is released as
  `picture` with the `profile` scope: a 512-pixel square JPEG auth encodes from the
  upload, keeping none of its metadata, at a URL whose image never changes. A
  social signup starts with the provider's picture (see
  [profile pictures](../architecture/surfaces.md#profile-pictures)).
- Social-first signup remains pending until its first passkey is committed. Only
  a registration that names the pending identity shown on the signup page attaches
  it; plain registration ignores it. A social login can never replace an
  established account's passkeys.
- Sensitive changes (changing the handle, adding or removing a passkey, linking or unlinking a provider,
  adding, removing or changing the primary email address, and registering an OIDC
  client or changing one in any way: its settings, enabling or disabling it,
  rotating its secret or deleting it) need a passkey confirmation of the current
  browser session from the last five minutes. A passkey sign-in counts; social
  sign-in never does. The age counts from the confirmation and is never extended
  by use, and it never applies to another session. Adding a passkey checks it
  when the ceremony starts, so a confirmation that lapses while the authenticator
  runs, which may take the ceremony's five minutes, does not discard the new
  passkey. Without one, a page asks for the passkey before it posts the change,
  and again if the change is refused; the API answers `403` with
  `"code": "step_up_required"` and `max_age`. Reads, renaming a passkey,
  changing the display name and setting the profile picture need only ordinary
  login.
- Matching verified email suggests linking; it never grants account access.
  Linking requires possession of the provider account and the target account's
  passkey confirmation. Explicit linking, started from settings, permits
  different/missing provider email and is bound to the session that started it.
- One Google and one GitHub identity may be linked. Unlinking releases the provider
  identity so another account can link it; account data and credentials never move.
  Settings keep listing identities of disabled providers so they can be unlinked.
- An account keeps at most 100 active passkeys (`PasskeyRepository::LIMIT`): a
  database trigger enforces it, and enrollment refuses the 101st before the
  authenticator creates it. The last passkey cannot be removed. Removing a passkey/provider revokes other
  central sessions. An owner who lost every passkey is recovered with a link to
  auth's `/recover` that enrolls one new passkey; for 15 days after, it confirms
  no change, and another passkey of the account can undo the recovery on
  `/recover/undo` (see
  [recovering an account](../architecture/surfaces.md#recovering-an-account)).
- Sessions last at most 30 days. An admin dashboard session lasts at most 12
  hours, ends after 30 minutes without a request, and starts only with a passkey
  proved for it. Access tokens last five minutes. Refresh tokens
  stop when their central session expires or is revoked; a public client's rotate
  and detect reuse. Ending a
  session tells the clients that registered a back-channel logout URI, which end
  their own sessions; already issued access tokens stay valid until they expire.
- Browser state and opaque secrets are random, and hashed where lookup is needed.
  Browser flows are bound, by a cookie, to the browser that started them: WebAuthn
  ceremonies, a social sign-in's provider redirect, a pending social signup or
  link, the offer to restore an account, and a sign-in to the admin dashboard.
  A pending authorization is not: its
  token travels in the sign-in and consent URLs, as the authorization request it
  continues does, and only a session that meets the request's requirements
  finishes it. Auth cookies are host-only, Secure and HttpOnly.
  Mutations require an exact allowed origin and CSRF header; OIDC back-channel
  endpoints instead validate their protocol credentials. A form posted to one of
  auth's server-rendered pages must come from auth's own pages: `Sec-Fetch-Site:
  same-origin`, or the auth origin when the browser sends no `Sec-Fetch-Site`.
  The one exception is `/unsubscribe`, which mail clients post to from anywhere
  (RFC 8058): its link's token is its credential, and it only turns one
  account's announcements' email off.
- Request throttling and expiring-state cleanup use PostgreSQL. Throttling uses separate login, token, userinfo, account and page budgets per client IP, and covers every API route except health probes and discovery.
  By default it uses the direct peer IP; only peers in `AUTH_TRUSTED_PROXIES`
  may supply a single overwritten `X-Forwarded-For`. Configure this when terminating TLS
  at a reverse proxy so users do not share the proxy’s budget. Untrusted headers
  are ignored; missing/ambiguous headers from a trusted proxy fail closed. Security events are
  retained; the IP addresses, browser families and provider subjects recorded with
  them are deleted after 90 days. Readiness checks PostgreSQL and that the signing keys were reloaded in the last
  5 minutes; startup validates configured signing/provider
  secrets. Connections, requests, provider calls and shutdown have bounded timeouts,
  and each listener refuses requests beyond 64 in flight (see [timeouts and
  limits](../operations/deploying.md#timeouts-and-limits)).
