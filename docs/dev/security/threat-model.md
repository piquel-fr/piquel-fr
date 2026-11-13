# Threat model

This page says what Origin Auth protects, from whom, and which risks it
accepts. Use it to judge whether a change weakens a defense, or needs one of its
own. It builds on the [security boundaries](boundaries.md); the
[security properties](properties.md) and the pages after them hold the details.

## Assets

| Asset | Why it matters | Where it lives |
| --- | --- | --- |
| Accounts and their passkeys | A passkey is the strongest way in, and the only one that confirms sensitive changes | `users`, `passkey_credentials`; the private keys stay on the owner's authenticators |
| Sessions | A session signs its browser in for up to 30 days | `sessions`, with only the cookie's digest, in `browser_session_secrets` |
| Tokens | Codes, refresh tokens and ID and access tokens let apps act as the user | Codes and refresh tokens as HMAC digests; issued tokens at the apps |
| Signing keys | Whoever holds one can mint any token apps accept | `signing_keys`, sealed under the key-encryption key |
| Personal data | Email addresses, IP addresses, devices, profile pictures, the apps an account uses | PostgreSQL; IPs and devices in `event_personal_data`, deleted after 90 days |
| The audit history | The record of every change, which owners, support and the chain rely on | `domain_events`, sealed into a hash chain with signed checkpoints |

## Actors

- **An anonymous attacker** on the internet. They can reach the public listener
  and any public page, but hold no account, or only one of their own.
- **An account holder,** acting on their own account. They may try to reach
  other accounts, or exceed what their account may do.
- **A malicious or compromised app.** Any account can register an app in the
  developer console, and an app receives tokens, claims and consent.
- **An administrator,** signed in to the dashboard on the tailnet with a passkey,
  or someone who took over an administrator's account.
- **An operator,** or anyone with database access or a shell in an auth
  container. They hold the root of trust.
- **Someone with a stolen passkey or mailbox:** a phone, a synced-passkey account,
  or an email account that is the owner's but in someone else's hands.

## Threats and mitigations

### At the public listener

| Threat | Mitigation |
| --- | --- |
| Guessing or phishing a credential | There are no passwords. Passkeys require user verification and are bound to auth's RP ID, so a phishing site cannot use them ([properties](properties.md)). |
| Cross-site requests | Cookies are host-only, Secure and HttpOnly. JSON mutations need an allowed origin and the CSRF header, and page forms must come from auth's own pages (`check_browser` in `apps/auth-service/src/security/http.rs`). |
| Taking over a flow started elsewhere | WebAuthn ceremonies, provider redirects and pending social signups are bound to the browser that started them by a cookie ([properties](properties.md)). |
| Brute force and floods from one source | Per-IP budgets per category, in PostgreSQL; never per account, so naming an account cannot lock its owner out ([handles](handles.md#threat-model)). |
| Learning who has an account | Accepted: handles are public, and handle sign-in says whether one has an active account ([handles](handles.md)). |
| Look-alike handles | Signup and renames refuse a handle that reads like a reserved or held one ([handles](handles.md)). |
| Claiming another person's email | Email is a verified contact, never an identifier, and a verified address belongs to one active account at most ([email normalization](email-normalization.md), [database](../architecture/database.md)). |

### Against an account

| Threat | Mitigation |
| --- | --- |
| A session stolen or left signed in | Every way into an account needs a passkey confirmation from the last five minutes, which a social sign-in never gives. Sessions end after 30 days, and the owner signs others out from the settings. |
| A linked GitHub or Google account taken over | A social sign-in can use the account, but cannot add a way in, and never replaces an established account's passkeys ([properties](properties.md)). |
| A stolen passkey | It grants everything, as it would the owner. Support confirms the owner under the evidence policy, then recovers with `--revoke`, keeping only the passkeys the owner vouches for ([stolen older passkeys](account-recovery.md#stolen-older-passkeys)). |
| A stolen mailbox | Email signs nobody in. A recovery link sent there gives only a probation sign-in, which adds no way in, and every verified address and the owner's next passkey sign-in hear of it ([account recovery](account-recovery.md#threat-model)). |
| Talking support into a recovery | The evidence policy, the 15-day probation, and the owner's undo with an older passkey, which nobody can take away mid-recovery ([account recovery](account-recovery.md#threat-model)). |

### From apps

| Threat | Mitigation |
| --- | --- |
| A code or token used by another app, or sent elsewhere | Exact redirect URIs, S256 PKCE for every client, codes tried once, and tokens bound to their audience ([OIDC](../../user/reference/oidc.md#codes-tokens-and-consent)). |
| An app impersonating another, or SourceOrigin | Console apps are never trusted, so the consent page shows unless the user already consented to the scopes asked, naming the host it returns to and labelling the app unverified with its owner's handle. `prompt=consent` forces it. Their names may not contain a well-known brand ([OIDC clients](../operations/clients.md)). |
| An app keeping access | The owner, an administrator or an operator removes an app's access, which ends its refresh grants and outstanding codes. A public client's refresh token rotates, and replaying a spent one revokes the grant, unless it repeats the newest rotation within 10 seconds, which answers with the same new token. |
| A logout URI aimed at the internal network | Deliveries go only over HTTPS to public addresses, and never follow a redirect ([outbound HTTP](../architecture/delivery-queue.md#outbound-http)). |
| Registering apps in bulk | An account may hold 10 apps and register 20 a day ([OIDC clients](../operations/clients.md)). |

### From administrators

| Threat | Mitigation |
| --- | --- |
| Taking over an account | Administrators view, edit and remove, but never add a way in or an address; the types make it a compile error ([changing an account](../architecture/surfaces.md#changing-an-account-on-its-owners-behalf)). A recovery an administrator starts is only mailed, never shown to them. |
| Acting without a trace | Every change is recorded with the administrator as its actor, and reads as views. Changes to an account's settings on its owner's behalf, and most actions on the account, need a reason, most of which the owner sees in their history; granting or revoking rights, enabling an account and signing its sessions out from the account's dashboard page or with `session revoke` and `session revoke-all` need none. |
| One administrator against another | An administrator may not change another administrator's account, nor their own rights or the last active administrator's. |
| A stolen session reaching the dashboard | The dashboard needs a passkey sign-in, a confirmation of its own for every change, a request naming its host, and the tailnet ([admin.sourceorigin.dev](../architecture/surfaces.md#adminsourceorigindev)). |

### With database access

| Threat | Mitigation |
| --- | --- |
| Rewriting or deleting history | The runtime role cannot change sealed events or checkpoints. Through the schema owner, changes break the hash chain or the signed checkpoints, and `audit verify` names the first position that no longer matches ([audit history](audit-history.md)). Auth's own verification, at least every six hours, raises an alert that notifies every administrator. |
| Reading secrets from a dump | Signing keys are sealed under a key the database never holds. Cookies, client secrets, codes, refresh tokens and emailed links' tokens are stored only as digests ([boundaries](boundaries.md#secrets-and-keys)). A dump with the token digest key and any spent refresh token of a public client's grant derives the grant's live token ([refresh tokens](../architecture/oidc.md#refresh-families)). |
| A bug in auth bypassing a way-in rule | Database triggers hold the recovery rules a way in depends on, for every writer ([database backstops](account-recovery.md#database-backstops)). |

Beyond these, database access is trusted: it can bind any passkey to any account
([NIST SP 800-63B-4](account-recovery.md#nist-sp-800-63b-4)).

## Accepted risks and limits

- **Operators are trusted.** Whoever holds database access, or a shell in an
  auth container, can do anything. The CLI records its changes with `$USER` and
  the host name, which the operator's own environment supplies.
- **Truncation and new events go unseen.** Someone with the schema owner's
  rights can delete the newest events with their checkpoints, and the runtime
  role can insert events that seal like genuine ones. No external witness exists
  yet, so only checkpoint copies kept elsewhere reveal a truncation
  ([limits](audit-history.md#limits)). Personal data is outside the chain.
- **Recovery departs from NIST.** The operator path relies on support's
  judgment, not two recovery factors. Self-service recovery and dedicated
  recovery rate limits are not built ([limits](account-recovery.md#limits)).
- **Issued tokens outlive their session.** An access token stays valid up to five
  minutes after its session ends. After a signing key is revoked, apps that
  cached the key set accept it for up to an hour
  ([a compromised signing key](../operations/incidents.md#a-compromised-signing-key)).
- **Undo doesn't reach inside apps.** What a recovery's link holder did in an app
  that doesn't ask for `phr` stays done ([undoing a recovery](account-recovery.md#undoing-a-recovery)).
- **Handles are not private.** Anyone can check whether a handle has an account,
  and add failed sign-ins to its history ([handles](handles.md#limits)).
- **Synced passkeys are accepted.** An account is then as safe as the passkey
  provider's account that syncs it.
- **Rate limits are per IP.** They slow one source, not an attacker with many
  addresses.
- **An approved related origin is trusted.** Its page runs passkey sign-in for
  its client, without auth's pages; an administrator approves each origin, for
  trusted clients only ([passkey sign-in](../../user/apps/passkey-sign-in.md)).
- **An administrator's account is an administrator.** Someone who took one over,
  with its passkey, can do what that administrator can, granting other
  administrators included, until another administrator or an operator revokes it.

## Out of scope

- The infrastructure auth runs on: piqueld and its host, the tailnet, the
  Cloudflare Tunnel and DNS. Whoever controls them controls the secrets and the
  database.
- The user's device, browser and authenticator, and the security of GitHub,
  Google, the passkey providers and email providers.
- How apps protect the tokens and sessions they receive; the SDKs only validate
  what auth issues ([SDK design](../architecture/sdk.md)).
- Volumetric denial of service beyond the per-IP budgets.
