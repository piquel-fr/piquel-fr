# Account recovery

Recovery binds a new passkey to an existing account: the same `UserId` and the
same `sub`. It never moves data or changes identity. Piquel has one recovery
path today, run by an operator at the terminal. This document states its policy
as built, as testable invariants, each naming the test that pins it. It is part
of [#85](https://github.com/piquel-fr/piquel-fr/issues/85), which also designs
self-service recovery; [What is left](#what-is-left) lists the rest.

Recovery is the weakest link of a passkey-first system. Phishing-resistant
passkeys mean little if someone can talk their way around them, so the most
important part of this document is [Support's evidence
policy](#supports-evidence-policy).

Lockout and takeover are both failures. Where they conflict, this path prefers
lockout that support can fix over takeover that nobody can: an account that is
refused a recovery can still be recovered later, but a link sent to the wrong
person cannot be taken back once its passkey is used. Undo exists so that a
mistaken recovery costs the attacker everything they gained.

The code is `apps/auth-service/src/recovery` (links, undo, protections),
`AdminService::recover_account`, `recent_recoveries` and `undo_recovery`
(`apps/auth-service/src/admin/service.rs`), and the CLI's `user recover` and
`user undo-recovery`. Tests named below live in
`apps/auth-service/src/recovery/tests.rs` unless another file is given.

## Starting a recovery

An operator at the terminal starts one with `auth-service user recover <user>
--reason "…"`. `AdminService::recover_account` also accepts an administrator,
for the dashboard *(planned)*; the admin API has no route for it.

- **R1.** Only an active account can be recovered
  (`administrators_never_see_the_link`, `replaced_undone_or_disabled_links_stop_working`).
- **R2.** No account is recovered while it holds administrator rights, by
  anyone, including the CLI (`administrators_never_see_the_link`). See
  [Administrators](#administrators).
- **R3.** While another recovery of the account can still be undone, starting one
  is refused unless the operator passes `--despite-undoable`
  (`WhileUndoable::Proceed`) (`support_undoes_a_hijacked_recovery`,
  `administrators_never_see_the_link`).
- **R4.** Starting a recovery ends every session and refresh grant of the
  account, cancels any older unused link, and records `RecoveryStarted` with the
  operator's reason, which the owner sees in their history
  (`a_link_enrolls_one_passkey_and_signs_in_with_it` for the sessions,
  `replaced_undone_or_disabled_links_stop_working` for the older link; the
  refresh grants and the event's reason are untested).
- **R5.** The account has at most one recovery whose link was not used,
  replaced or undone, enforced by a partial unique index
  (`crates/database/tests/recoveries.rs: one_open_recovery_per_account`).
- **R6.** An administrator never receives the link, so they may recover only an
  account with a primary address. The operator at the terminal is shown the link
  too, which also reaches an owner without an address
  (`administrators_never_see_the_link`).
- **R7.** Before starting, `user recover` lists the account's recoveries of the
  last 30 days, with the passkey each enrolled and, for each one that can still
  be undone, everything it would take back (`AdminService::recent_recoveries`:
  `support_undoes_a_hijacked_recovery`,
  `a_second_recovery_trusts_only_what_predates_both`; the printout itself is
  untested). Reading them records that an operator viewed the account, which the
  owner sees.

## The link

- **L1.** The link is `{auth origin}/recover#token=…`. The token is in the
  fragment, so it never reaches a server log
  (`deliveries::email::tests::a_recovery_link_is_sent_while_it_works`).
- **L2.** The token is an HMAC of the recovery's ID under a key derived from the
  token digest key. Only its SHA-256 digest is stored; the email's delivery
  stores neither, only the recovery's and the address's IDs. This holds by type:
  `EmailMessage::RecoveryLink` has no token field.
- **L3.** The token alone authorizes the link. `POST /recovery/check` names the
  account without using the link; `POST /recovery/start` and `/finish` are a
  browser-bound registration ceremony on auth's origin, the RP ID
  (`a_link_enrolls_one_passkey_and_signs_in_with_it`).
- **L4.** The link goes to the account's primary address only, never to its other
  addresses, and is not sent once it was used or replaced, or the account is
  disabled (`a_link_enrolls_one_passkey_and_signs_in_with_it`,
  `deliveries::email::tests::a_recovery_link_is_sent_while_it_works`; an undone
  or expired link is not sent either, untested).
- **L5.** A link enrolls one passkey, once. It stops working when it is used,
  when a newer recovery or disabling the account replaces it (even after the
  account is enabled again), when it is undone, and when it expires
  (`a_link_enrolls_one_passkey_and_signs_in_with_it` for use,
  `replaced_undone_or_disabled_links_stop_working` for the rest; an expired
  link's `400` is untested).

## Completion and notices

- **C1.** Finishing the link's ceremony stores the passkey, records
  `RecoveryCompleted` with it, and signs the browser in with it. The session
  records that passkey (`a_link_enrolls_one_passkey_and_signs_in_with_it`).
- **C2.** That sign-in counts as a fresh passkey confirmation, like any passkey
  sign-in. Whoever used the link can therefore make confirmed changes at once,
  such as enrolling another passkey (`undo_takes_back_every_way_in_added_since`).
  The protections and undo below exist because of it.
- **C3.** Completion checks the link again under the account lock, so a link
  replaced while its ceremony runs fails, and the passkey is rolled back
  (`replaced_undone_or_disabled_links_stop_working`).
- **C4.** Every verified address, not only the primary one, is told that a
  recovery added a passkey, how many days it can be undone, and where, and that
  support can undo it for an owner with no passkey from before
  (`a_link_enrolls_one_passkey_and_signs_in_with_it`,
  `deliveries::email::tests::a_recovery_link_is_sent_while_it_works`).

## Windows

- **W1.** An unused link works for 24 hours (`LINK_LIFETIME`). While it works,
  the recovery can be undone and protects what came before it; once it expires,
  neither (`a_link_enrolls_one_passkey_and_signs_in_with_it`,
  `an_expired_link_neither_undoes_nor_protects`).
- **W2.** A used recovery can be undone for 30 days after its link was used
  (`SETTLE_WINDOW`). Then it settles: it can no longer be undone and its
  protections lift (`a_used_recovery_settles_after_its_window`, at 30 days minus
  and plus a minute), and its passkey is an ordinary older passkey for later
  recoveries (untested).
- **W3.** A finish that waits for the account lock past the link's deadline does
  not complete: expiry is checked against the clock, not the transaction's start
  (`crates/database/tests/recoveries.rs:
  a_link_that_expires_while_finishing_does_not_complete`).
- **W4.** The settle window runs while the account is disabled. While it is
  disabled, the owner cannot undo, but support can (untested). Support
  investigating a recovery settles the question within the window.

## Undoing a recovery

The owner undoes a recovery on the undo page *(planned)*, with a passkey
ceremony of its own: `POST /account/recovery/undo/start {recovery_id}`, then
`/finish`.

- **U1.** Only a passkey enrolled before every recovery that can still be undone
  may undo; the recovery's own passkey and a social sign-in never do. The start
  offers only those passkeys, the same list `GET /account/recovery` returns as
  `undo_with`, and the finish checks the asserting passkey again under the lock
  (`only_an_older_passkey_undoes_a_recovery`,
  `a_second_recovery_trusts_only_what_predates_both`).
- **U2.** The undo needs no session, so signing the owner out, which whoever used
  the link can do from their own session, cannot stop it
  (`undo_needs_no_session`).
- **U3.** The undo names the recovery its page showed. It answers `409` if that
  is no longer the account's newest undoable recovery, and `404` when nothing is
  left to undo (`replaced_undone_or_disabled_links_stop_working`,
  `only_an_older_passkey_undoes_a_recovery`).
- **U4.** The owner's undo ends every session and signs the undoing browser in
  with its passkey (`only_an_older_passkey_undoes_a_recovery`).
- **U5.** Support undoes a recovery for an owner with no passkey left from before
  it: `auth-service user undo-recovery <user> --reason "…"`
  (`AdminService::undo_recovery`). It takes back the same rollback, sends the
  same notices, records the reason with every change, sessions included, and
  ends every session and refresh grant (`support_undoes_a_hijacked_recovery`;
  the refresh grants are untested). It is the remedy when whoever used the link
  got in before the owner.
- **U6.** Support's undo removes every passkey added since, even the last, so
  whoever used the link keeps none even if support was talked into removing the
  older passkeys first; the account may be left with no passkey, and support
  starts a new recovery (`support_takes_back_every_passkey_added_since`). The
  owner's undo never removes the last passkey, which never matters: the passkey
  that undoes it predates the recovery and stays.

## What undo takes back, and what it leaves

`GET /account/recovery` returns exactly what an undo would take back
(`rollback`), and the undo page *(planned)* lists it before the owner confirms.

- **T1.** Undo takes back, in one transaction, everything the account gained
  since the recovery started, each change recorded as its own event:
  every passkey enrolled since, the recovery's own included; every identity
  linked since; every OIDC consent given or extended since; and every address
  added or verified since (`undo_takes_back_every_way_in_added_since`).
- **T2.** It makes the primary address the recovery started with primary again,
  or, if that is gone, the oldest address verified before the recovery
  (`undo_takes_back_every_way_in_added_since`,
  `undo_falls_back_to_the_oldest_address_left`). It leaves an unchanged primary
  alone (`only_an_older_passkey_undoes_a_recovery`).
- **T3.** It leaves everything from before the recovery untouched, except a
  consent re-approved since and an address added before but verified since,
  which it withdraws whole (`undo_takes_back_every_way_in_added_since`).
- **T4.** The owner loses what they added themselves meanwhile too; that is the
  price of not having to tell their additions from an attacker's. This follows
  from T1.
- **T5.** It leaves owned OIDC clients, profile edits, passkey names and the
  history: none is a way in. Ending every session ends their refresh grants
  (untested for the owner's undo).
- **T6.** A consent that waited for the account lock while the undo ran is not
  saved after it: approving reads the session again under the lock
  (`oidc::tests::a_consent_whose_session_ended_while_waiting_is_not_saved`).
- **T7.** The removals send their usual notices: a removed verified address is
  told of its removal (`support_undoes_a_hijacked_recovery`), and a replaced
  primary of the change (untested here; it is the primary change's usual
  notice).

## Protections until a recovery settles

`AccountService::keep_older` guards every owner removal of something from
before an undoable recovery.

- **P1.** While a recovery can be undone, a session that does not predate it (no
  passkey enrolled before it signed the session in or confirmed it) cannot
  remove the account's passkeys, linked identities or addresses from before it,
  nor move the primary address away from one. Operators and administrators
  acting through `Subject` still can (`what_predates_a_recovery_is_protected`,
  for operators; administrators are untested).
- **P2.** "From before" is the complement of what undo takes back: a passkey
  enrolled, an identity linked, or an address verified (or, unverified, added)
  before the recovery started. An unverified address from before is protected;
  an address added before but verified after is undo's to take back
  (`what_predates_a_recovery_is_protected`).
- **P3.** Adding a pending address from before again, which replaces it, counts
  as removing it (untested).
- **P4.** A session counts as predating a recovery only through the passkey that
  signed it in or last confirmed it: `sessions.passkey_id`, which a later
  confirmation replaces (`passkey::tests::passkey_sign_in_confirms_the_browsers_session`,
  `crates/database/tests/security.rs: invitation_redemption_and_confirmation_lifecycle`).

## Several recoveries

- **S1.** Every recovery that can still be undone counts. A passkey undoes, and a
  session is trusted, only if it predates all of them; something is protected
  against every one that started after it
  (`a_second_recovery_trusts_only_what_predates_both`).
- **S2.** Recoveries sort in the order they were stored, after taking the
  account lock: `started_at` is the clock then
  (`crates/database/tests/recoveries.rs: the_newest_recovery_is_the_last_stored`).
- **S3.** The owner undoes the newest first, then the next
  (`a_second_recovery_trusts_only_what_predates_both`).
- **S4.** Starting another while one can be undone needs `--despite-undoable`
  (R3), after reviewing the listing (R7).

## Administrators

- **A1.** No account is recovered while it holds administrator rights, even
  from the CLI (`administrators_never_see_the_link`). Whoever used the link
  would hold a fresh passkey confirmation, which meets the admin API's
  requirement, and could grant rights to another account before the owner
  undoes the recovery; that grant would survive the undo.
- **A2.** Revoking the rights is the prerequisite. To recover an administrator,
  support first revokes its rights with `auth-service admin revoke` (granting
  another administrator first if it is the last), recovers the account, then
  grants them again once the owner is confirmed through the [evidence
  policy](#supports-evidence-policy).

## Locking and serialization

- **K1.** Every change to an account's recoveries, and every guarded removal,
  takes the account's row lock (`users` `FOR NO KEY UPDATE`) first, then reads
  what it checks. Starting, completing and undoing a recovery therefore
  serialize with each other, with sign-in and with settings changes. This holds
  by construction; no test races them all.
- **K2.** A completion that loses to an undo, or to a newer recovery, fails and
  rolls its passkey back (`replaced_undone_or_disabled_links_stop_working` for a
  newer recovery; losing to an undo is untested).
- **K3.** The guard reads the passkey of the owner's session on the locked
  session; the undo checks the passkey that just asserted, under the account
  lock, in the transaction that undoes (by construction, untested).

## Key rotation

- **Q1.** A link is checked by its token's SHA-256 against the stored digest,
  with no key, so changing the token digest key never breaks a sent link or
  makes one verify under the wrong key. The recovery tests' links use a key the
  server does not have, and still work
  (`a_link_enrolls_one_passkey_and_signs_in_with_it`).
- **Q2.** The sender derives the token again, under whichever configured key,
  current or accepted, derives the stored digest. A link mailed after a key
  change still works; if no configured key derives it, the delivery fails
  rather than mail a dead link
  (`deliveries::email::tests::a_recovery_link_is_sent_while_it_works`).

## Threat model

The operator path, against #85's threats.

| Threat | What the operator path does |
| --- | --- |
| Remote phishing | Nobody can start a recovery but support, so there is no recovery page to fake for a code. A phished link (one forwarded on request) enrolls only within 24 hours, once, and every verified address hears of it (C4). The owner undoes it with an older passkey (U1), and the attacker cannot remove what undo needs (P1). |
| Channel takeover | The link goes to the primary address (L4), so a taken-over mailbox receives it. Support's evidence policy must never rely on that mailbox alone. The notice reaches every verified address (C4), the attacker cannot move the primary to their own address (P1), and undo, by the owner or by support, takes back every way in they added (T1, U5). A social identity is never a recovery method: it cannot enroll a passkey or undo. |
| Social engineering of the operator | The main way to attack this design. Support follows the [evidence policy](#supports-evidence-policy). The reason is recorded and shown to the owner (R4), a second recovery needs a deliberate flag after reviewing the first (R3, R7), and no account is recovered while it holds administrator rights (A1). |
| Insider or database access | Database access is the root of trust (see [NIST](#nist-sp-800-63b-4)): an operator can do anything. CLI changes record `Actor::Cli` with `$USER` and the host, and the reason where the command takes one; the owner sees that an operator acted, and the reason. Tamper evidence is #31. |
| Close-proximity attacker | A partner with the mailbox can receive a link that support sent. The owner's older passkey undoes it within 30 days (U1, W2), the guard keeps what undo needs (P1), and the notice reaches every address (C4). |
| Harassment | There is no self-service recovery to flood: only support starts one. Each start mails one link to one address (L4). Another start needs `--despite-undoable` only while an earlier recovery can still be undone (R3); once its link expired or it settled, support can start another without it. Dedicated recovery rate limits (#86) are not built yet. |
| Lockout | The path exists for it. An attacker cannot undo the owner's genuine recovery without a passkey from before every undoable one (U1, S1), and support can undo an attacker's (U5). An owner who loses the recovered passkey within the window has support. |

## Decisions that replace #85's sketch

- **Immediate recovery with a 30-day undo, not a 7-day wait.** A wait adds no
  evidence; it only gives the owner time to object. The operator path serves an
  owner who is locked out now, so it starts at once and gives the owner 30 days
  to undo instead. An undo needs a passkey from before the recovery, which is
  stronger than noticing an email. The pending-recovery auto-cancel of the
  sketch becomes this explicit undo, which also takes back what was added.
- **Guarding what came before, and undo taking additions back, instead of an
  account-wide restriction.** A 7-day restriction in `Confirmed` would block the
  genuine owner from adding a second passkey or an address right when they need
  it most. Instead, the recovered owner uses the account normally; whoever used
  the link cannot remove what the owner had before (P1), and undo takes back
  everything added since (T1).
- **A broader rollback.** The sketch rolled back the recovered passkey, sessions,
  refresh families and consents. Because the recovered sign-in counts as a fresh
  confirmation (C2), whoever used the link can also link an identity, add an
  address and make it primary, so undo takes back identities, addresses and the
  primary too (T1, T2).
- **No account is recovered while it holds administrator rights.** The sketch
  let the CLI recover administrators.
  The link's fresh confirmation meets the admin API's requirement, so a
  recovered administrator would be a privilege escalation that survives undo
  (A1).

Other differences: the recovered passkey is recorded on the recovery
(`account_recoveries.passkey_id`) and in its `RecoveryCompleted` event, not in a
`recovered_by` column on the passkey; the link lives 24 hours from its start, not
from the end of a wait.

## NIST SP 800-63B-4

Passkeys with user verification make Piquel accounts AAL2. NIST's recovery rules
at AAL2 ([§4.2.2.2](https://pages.nist.gov/800-63-4/sp800-63b.html#recovery-aal2))
require two recovery codes obtained by different methods, one code plus a bound
single-factor authenticator, or repeated identity proofing.

The operator path meets none of them. It is a **documented departure**: its only
code is the issued link, to one address, and Piquel does no identity proofing, so
the second piece of evidence is support's judgment under the evidence policy,
outside the system. Database access is the root of trust: whoever holds it can
bind any passkey to any account, recovery or not. The compensating controls are
the notice to every verified address (C4), the 30-day undo by a pre-existing
authenticator (U1, W2), the protections (P1), the reason recorded for the owner
(R4), and the rule that no account is recovered while it holds administrator
rights (A1). Sessions a recovered passkey signs in still report its `acr`; an
AAL1-grade `acr` for them is left to do.

## Support's evidence policy

**For the user to review.** Support runs `user recover` and `user undo-recovery`
only on evidence. No single item below is enough on its own, and the items under
"never enough" must not count at all.

Before `user recover`:

1. **Read the account and its history:** `auth-service user show <user>`, then
   `auth-service account <user> history`, which shows each change and sign-in
   with its device and IP. Look for signs the account is already compromised:
   identities linked, addresses added or a primary change in the last 30 days,
   sign-ins from new devices. The link always goes to the current primary, so if
   the primary changed recently, establish the owner through older channels,
   then restore the older primary first with `auth-service account <user> emails
   primary <id> --reason "…"`, or do not run `user recover`.
2. **Read the listing `user recover` prints.** If a recovery can still be undone,
   find out who used it before anything else. If it was not the requester, undo
   it with `user undo-recovery` first, under the rules below, so the next link
   goes to the owner's restored primary. Pass `--despite-undoable` only when the
   requester is that recovery's own owner asking again.
3. **Confirm the request through a second channel that existed before it**, and
   that is not the address the link will go to: another verified address on the
   account, an organization contact known beforehand, or a reply to a message
   the account sent long before.
4. **Ask for what only the owner should know, and check it against the
   history** (`account <user> history`): roughly when the account was created,
   its passkeys' names, the apps it signed in to, where it usually signs in
   from. Treat this as
   supporting evidence: someone close to the owner may know it.
5. **Write the reason as the evidence:** who asked, through which channel, which
   checks passed. The owner sees it.
6. **Prefer the email to the printed link.** Print the link to the requester only
   for an account with no address, and only through the channel confirmed in 3,
   never through the channel the request came from.

Before `user undo-recovery`, on a claim that a recovery was not the owner's:

1. **Establish the owner through evidence from before the recovery:** channels
   and history that predate its start, such as the address the listing says the
   undo restores (or, when it lists none, the current primary, which the
   recovery did not change), not one added since.
2. **Read the rollback in the listing.** The passkeys, identities and addresses
   it lists were added since the recovery; a request coming through any of them
   is a request from whoever used the link.
3. **Write the reason**, as above.

Never enough on its own:

- A request from the account's own email address, or a reply to it: it may be
  the compromised channel, and the link goes there.
- A request from a social identity linked to the account, or a message on that
  provider: social accounts are taken over often.
- Knowledge of the username, display name, email address or anything public.
- Urgency, distress, authority or threats, or a claim to be staff.
- For an undo: a request from any passkey, identity or address the rollback
  lists.

While a recovery can be undone, do not remove a passkey, identity or address
from before it on request: that is what undoing needs, and a request to remove
"my stolen phone's passkey" may come from whoever used the link. Undo the
recovery instead, or wait until the owner is confirmed as above.

## What is left

From #85, not built by this path:

- Self-service recovery: a saved recovery key plus an issued email code, the
  NIST-compliant path, with its pages.
- Passkey backup-state warnings and prompts for a second passkey, in settings
  and the security center: prevention first.
- An AAL1-grade `acr` for sessions of a recovered passkey (#63, #64).
- One-click cancel links in recovery emails, which need no sign-in.
- Dedicated rate limits on recovery endpoints (#86); only the general per-IP
  request budget covers them today.
- The `/recover` page and the undo prompt *(planned, from the pages stream)*.
  The APIs are live, but no page uses a link yet, and `user recover` says so.
