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
lockout that support can fix over takeover that nobody can.

## The idea: a recovered passkey is weaker until it settles

Whoever uses a recovery link may not be the owner. Instead of letting them act
as a fully confirmed owner and then trying to take back everything they did,
**a recovery's passkey signs in like a social login until the recovery
settles**: it never gives a passkey confirmation. Every way into an account
already needs one: adding or removing a passkey, linking an identity, changing
addresses or the primary, managing owned clients, and the admin API. So do
relying parties that ask for `phr`. Whoever used the link can therefore use the
account, but can add no way into it. Undoing the recovery has a short, fixed list
to take back: its passkey, every session and refresh grant, and every app
consent. No list of what changed, and no timestamp comparisons.

A feature added later inherits this by needing a confirmation (P2). Nothing
recovery-specific has to remember it.

The code is `apps/auth-service/src/recovery` (links, the probation passkey,
undo), `AdminService::recover_account`, `recent_recoveries` and `undo_recovery`
(`apps/auth-service/src/admin/service.rs`), the passkey routes
(`apps/auth-service/src/passkey`), migration `0019_account_recoveries`, and the
CLI's `user recover` and `user undo-recovery`. Tests named below live in
`apps/auth-service/src/recovery/tests.rs` unless another file is given;
`crates/database/tests/recoveries.rs` is shortened to `db:`.

## States

`StoredRecovery::state` is the only place auth computes where a recovery
stands, against the database's clock read with the row
(`db: a_recovery_state_follows_its_link_and_probation`):

| State | Meaning |
| --- | --- |
| `Open` | Its link works: not used or cancelled, and not expired (24 hours, `LINK_LIFETIME`). |
| `Probation` | Its link was used less than 15 days ago (`PROBATION`), and it was not undone. |
| `Settled` | Its probation ended. Its passkey is an ordinary passkey. |
| `Ended` | It expired unused, or was cancelled or undone. |

A recovery that is `Open` or in `Probation` can still be undone. An account has
at most one (S2, S4). The migration's `undoable_recovery` is the one SQL copy of
that condition, which the [database backstops](#database-backstops) share.

## Starting a recovery

An operator at the terminal starts one with `auth-service user recover <user>
--reason "…"`. `AdminService::recover_account` also accepts an administrator,
for the dashboard *(planned)*; the admin API has no route for it.

- **S1.** Only an active account is recovered
  (`what_a_start_replaces_and_refuses`).
- **S2.** Starting is refused while a recovery of the account is in probation.
  Support finds out who used it, and undoes it first if needed (U5). An unused
  link, expired or not, is cancelled by the new start: nobody got in with it
  (`what_a_start_replaces_and_refuses`).
- **S3.** Starting ends every session and refresh grant, and removes the
  account's unverified addresses with their verification links. Verifying needs
  only its link's token and can make an address primary, so a link mailed
  before the recovery must not change the account during it. It records
  `RecoveryStarted` with the reason
  (`a_link_enrolls_one_passkey_that_signs_in_without_confirming`).
- **S4.** At most one unused link per account, enforced by a partial unique index
  (`db: one_open_recovery_per_account`).
- **S5.** `user recover --revoke [--keep <passkey-id>…]` is for an account that
  was in someone else's hands: a stolen phone, or a hijacked synced-passkey
  account. Under the account lock, before the recovery exists, it:
  - revokes every passkey not kept, the last one included;
  - unlinks every social identity;
  - withdraws every consent.

  Only a kept passkey (the owner's, by support's evidence) or the link can sign
  in after it. A kept passkey that isn't an active one of the account fails the
  whole start. The link is only printed, never mailed, and every verified address
  is told at once. The notice links to the undo page while a kept passkey can
  cancel the recovery, and says to contact support otherwise. `RecoveryStarted`
  records what was revoked and kept
  (`revoke_takes_back_every_way_in_but_the_kept_passkeys`,
  `support_undoes_and_takes_the_last_passkey`).
- **S6.** Before starting, `user recover` lists the account's recoveries of the
  last 15 days with where each stands, those undone included, so support sees a
  repeated attempt (`AdminService::recent_recoveries`:
  `support_undoes_and_takes_the_last_passkey`; the printout itself is untested).
  Reading them records that an operator viewed the account.

## Administrators

- **A1.** An account with a recovery that can still be undone is never an
  administrator. Starting refuses an administrator: support revokes the rights
  first (`admin revoke`; to recover the last administrator, grant another one
  first). Granting rights, by the admin API or the CLI, is refused while a
  recovery can be undone, with no override. Granted during a probation, they
  would go live for whoever used the link once it settles
  (`what_a_start_replaces_and_refuses`,
  `admin::tests::no_grant_while_a_recovery_can_be_undone`,
  `db: no_grant_while_a_recovery_can_be_undone`).

## The link

- **L1.** The link is `{auth origin}/recover#token=…`, with the token in the
  fragment so it never reaches a server log. The token is an HMAC of the
  recovery's ID under a key derived from the token digest key. Only its SHA-256
  digest is stored, and the email's delivery stores neither, by type:
  `EmailMessage::RecoveryLink` has no token field. The token alone authorizes
  the link: the `/recover` page reads it in-process
  (`AccountService::open_recovery`), and `POST /recovery/start` and `/finish`
  enroll the passkey. No endpoint checks a token without starting the ceremony.
- **L2.** It is mailed only to the primary verified address the account has when
  the recovery starts,
  and printed to the operator at the terminal, which also reaches an owner
  without one. An administrator never sees it, so they may only start a
  recovery that mails it (`a_link_enrolls_one_passkey_that_signs_in_without_confirming`,
  `what_a_start_replaces_and_refuses`). During a probation, the primary changes
  only through a confirmed session (an older passkey), an operator, or the
  verification of an address added during it, which only a confirmed session
  can add. None of these is the link holder choosing an address of their own.
- **L3.** The link enrolls one passkey, once, within 24 hours. It stops working
  when used, cancelled (by a newer recovery, by disabling the account, or by an
  undo), or expired. Expiry is checked against the clock under the account
  lock, so a finish that waits for the lock past the deadline fails. Two
  ceremonies started from one link enroll one passkey: the second finish fails
  and leaves the recovery bound to the first
  (`a_link_enrolls_one_passkey_that_signs_in_without_confirming`,
  `a_link_enrolls_once_however_many_ceremonies_started`,
  `what_a_start_replaces_and_refuses`,
  `db: a_link_that_expires_while_finishing_does_not_complete`).
- **L4.** A change of token digest key never breaks a sent link: a link is
  checked against its stored digest, not re-derived. The sender rebuilds it
  under whichever configured key derives the stored digest, and fails the
  delivery rather than mail a dead link
  (`deliveries::email::tests::a_recovery_link_is_sent_while_it_works`).

## Completion and notices

- **C1.** Finishing the link's ceremony, under the account lock and only while
  the link works, stores the passkey, starts the probation (`completed_at`,
  `settles_at`), records `RecoveryCompleted`, and signs the browser in with a
  new session. Whatever session the browser had, of this account or another, is
  revoked rather than renewed. The session is a probation sign-in: no passkey
  confirmation, `acr` Social
  (`a_link_enrolls_one_passkey_that_signs_in_without_confirming`,
  `a_probation_passkey_signs_in_anew_and_never_confirms`).
- **C2.** Every verified address is told that a recovery added a passkey, for
  how many days it can be undone, with a link to its undo page
  (`/recover/undo#recovery=…`), and that support can undo it. The link email
  carries the undo page too, so an owner who still has a passkey can cancel
  (`a_link_enrolls_one_passkey_that_signs_in_without_confirming`,
  `deliveries::email::tests::a_recovery_link_is_sent_while_it_works`).
- **C3.** `GET /account/recovery` describes the undoable recovery to any session,
  so the settings and sign-in pages can ask "Your account was recovered on …
  Was this you?". An owner with an older passkey learns of it by signing in,
  even when the notice only reached a hijacked mailbox *(the prompt is planned,
  with the pages)*.

## Probation

- **P1.** `update_credential` accepts every passkey assertion under the account
  lock. It returns `Credential::Probation` for the passkey of a recovery in
  probation, which only a recovery in probation can build (`ProbationPasskey`).
  Every consumer handles it:
  - a new session gets no passkey confirmation: `acr` Social, `amr` still says
    a passkey;
  - in a browser already signed in to the account, it renews an unconfirmed
    session without confirming it and records the passkey, and refuses with
    `passkey_required` to downgrade a confirmed one, saying to sign out first;
  - the confirmation ceremony answers `403 recovery_probation {settles_at}`.

  No step-up gate accepts it: no confirmed account change (`step_up_required`),
  no admin API call, no relying party that asks for `phr`. After `settles_at`,
  the same passkey confirms as usual
  (`a_link_enrolls_one_passkey_that_signs_in_without_confirming`,
  `a_probation_passkey_signs_in_anew_and_never_confirms`). The database backs
  it for every writer (B1).
- **P2.** **Every feature must keep this:** anything that adds a way into an
  account, grants something that outlives a session, or ends the owner's
  ability to undo (a future account deletion, for example) needs a passkey
  confirmation. App consents are the one exception, and undo withdraws all of
  them (U2).
- **P3.** What a probation session can still do, which undo does not revert
  because none of it is a way in: rename passkeys (pages name the recovery's
  passkey by ID and enrollment time, never by name), sign sessions out, report a
  sign-in as not theirs, verify an address added during the probation, and sign
  in to apps that don't ask for `phr`, approving their consent.
- **P4.** A relying party that asks for `phr` doesn't loop a probation user
  through sign-in. Once such a passkey signed in during the request, authorize
  answers the client `unmet_authentication_requirements` (OpenID Connect Unmet
  Authentication Requirements 1.0). A social sign-in, which a passkey could still
  step up, goes to sign in as before
  (`oidc::tests::a_probation_sign_in_short_of_the_target_answers_the_client`).
  `Acr::select`'s documentation says an account may not reach every class.
- **P5.** Probation lasts 15 days. A session lasts up to 30, so the session the
  link signed in can outlive it: it stays unconfirmed until the recovery's passkey
  confirms it again, once the recovery settled. Codes and refresh grants keep the
  `acr` they were issued with, so only an authorization after settling reports
  `phr`.

## Undoing a recovery

The owner undoes a recovery on its undo page *(planned)*, with a passkey ceremony
of its own: `POST /account/recovery/undo/start {recovery_id}`, then `/finish`.

- **U1.** Any active passkey of the account but the recovery's own may undo it:
  the start challenges every other one, and the finish refuses the recovery's
  own again under the lock. During a probation only a confirmed session (an
  older passkey) can enroll a passkey, and operators never do, so every other
  passkey belongs to someone who held the account before the recovery. A passkey
  enrolled during the probation that way may undo too. The undo takes a
  `VerifiedRecoveryUndo`, which only consuming the undo ceremony and verifying
  its assertion under the account lock builds. It binds the account, the
  recovery the ceremony named and the passkey, so an undo started for a
  recovery that a newer one replaced undoes nothing
  (`only_another_passkey_undoes_a_recovery`,
  `undoing_an_unused_link_only_cancels_it`).
- **U1a.** **Nothing takes away the owner's undo mid-recovery.** While a
  recovery can be undone, no passkey but its own is removed, by anyone: not a
  probation session (P1), not a session an older passkey confirmed, not an
  operator or administrator. Otherwise a link holder could ask support to
  "remove my stolen phone's passkey", one by one. For a stolen older passkey
  mid-recovery, support undoes the recovery and starts again with `--revoke`
  (`nothing_removes_an_older_passkey_mid_recovery`; the database backs it, B3).
- **U2.** Undoing a recovery in probation, in one transaction under the account
  lock, removes its passkey, revokes every refresh grant, withdraws every
  consent and ends every session, each change recorded, then `RecoveryUndone`.
  That is the whole list: P1 left nothing else that lets anyone back in. The
  owner gives each app its consent again at their next sign-in to it
  (`undo_takes_back_the_passkey_sessions_grants_and_consents`). The grants go
  before the consents, the order a client's deletion locks them in, so the two
  never deadlock; `--revoke` withdraws consents the same way
  (`an_undo_and_a_client_deletion_never_deadlock`).
- **U3.** Undoing a recovery whose link was not used only cancels the link:
  nobody got in with it (`undoing_an_unused_link_only_cancels_it`).
- **U4.** The undo needs no session, so signing the owner out cannot stop it. It
  signs the undoing browser in with a normal session and answers `200
  {signed_in: true}`. It answers `404 nothing_to_undo` for a recovery that is
  not the account's undoable one, a settled one included
  (`undo_takes_back_the_passkey_sessions_grants_and_consents`,
  `only_another_passkey_undoes_a_recovery`).
- **U4a.** **The undo works on a disabled account**, so asking support to "lock
  my account" cannot outlast it. It signs nobody in (`200 {signed_in: false}`),
  and the account stays disabled. This is the one place a disabled account's
  passkey is accepted: the undo's own entry point gets `Accepted::Disabled`,
  which carries no credential to sign in with, while sign-in and confirmation
  still refuse a disabled account. A disable written by a release older than
  this one doesn't change that (`the_owner_undoes_a_disabled_accounts_recovery`,
  `passkey::tests::only_an_undo_accepts_a_disabled_accounts_passkey`). Disabling
  still cancels an unused link (`what_a_start_replaces_and_refuses`).
- **U5.** Support undoes for an owner with no passkey left from before it, or
  whose account is disabled: `auth-service user undo-recovery <user> --reason
  "…"`. It is the same U2 or U3, recorded with the reason, and it removes the
  recovery's passkey even if it is the last one; support then starts another
  recovery. Undoing a `--revoke` recovery restores nothing it revoked
  (`support_undoes_and_takes_the_last_passkey`).
- **U6.** A consent, code exchange or refresh that waited for the account lock
  while an undo ran doesn't survive it: each re-reads its session under the lock
  (`oidc::tests::a_consent_whose_session_ended_while_waiting_is_not_saved`, and
  the code exchange's and rotation's own session checks).

What undo doesn't reach: what the link holder did inside apps that don't ask for
`phr` (app data, accounts of their own inside an app, app sessions of clients
without back-channel logout); access tokens already issued, which live up to 5
minutes; a linked social identity whose provider account is also hijacked, which
support unlinks (the owner can't during a probation); and the P3 edits.

## Stolen older passkeys

- **X1.** A recovery doesn't defend against a passkey from before it: whoever
  holds one can sign in and do anything without any recovery, so letting them
  undo gives them nothing new. When an older passkey may be in someone else's
  hands, support confirms the owner under the evidence policy and starts the
  recovery with `--revoke`, keeping only the passkeys the owner vouches for
  (S5). Only then does it remove the addresses the owner doesn't recognize, and
  review owned clients, before handing the link over: done first, that would warn
  the thief, who would still hold a way in.

## Database backstops

The rules above live in Rust, which gives the typed answer and the right error.
Three triggers in migration `0019` hold the ones a way in depends on for every
writer, including a replica of the previous release during a deploy, a release
rolled back below this one (migrations aren't reverted), and any future code
path. Each runs as its owner (`SECURITY DEFINER`, `search_path` ending in
`pg_temp`, executable by its owner only), because the previous release fires it
before the runtime role is granted `account_recoveries`. Each test below runs
as a role with no grant on that table.

- **B1.** `sessions_no_probation_confirmation` clears a session's passkey
  confirmation when the passkey it names is a probation passkey, or when it
  names none while the account is in probation. An older passkey still confirms
  (`db: a_probation_passkey_never_confirms_a_session`).
- **B2.** `administrators_no_grant_mid_recovery` refuses a grant while a recovery
  can be undone (`db: no_grant_while_a_recovery_can_be_undone`).
- **B3.** `passkeys_kept_mid_recovery` refuses revoking any passkey but the
  recovery's own while it can be undone
  (`db: only_the_recoverys_own_passkey_is_revoked_mid_recovery`).

Their functions pin `search_path` with `pg_temp` last, so a temporary table
cannot shadow `account_recoveries`
(`crates/database/src/connection/tests.rs: functions_pin_their_search_path`).

## Locking and time

- **K1.** Start, completion, undo, every passkey assertion and every confirmed
  change take the account's row lock first, so they serialize. This holds by
  construction; no test races them all.
- **K2.** No rule compares two rows' timestamps. The undo compares passkey
  identity; the probation decision reads one recovery row when the passkey
  asserts. Only a link's expiry and `settles_at` read the clock, each against
  one row, and `settles_at` is stored, computed from `PROBATION`, so SQL never
  repeats the constant.

## Deploys and rollbacks

- A rollback to this release's predecessor keeps every way-in property and the
  owner's ability to undo: the backstops hold, and the predecessor already
  needs a confirmation for every owned-client change and re-reads a consent's
  session under the lock (the prerequisite PR). Never roll back below that
  predecessor while a recovery can be undone.
- What a rollback loses is availability: the undo page, P4 and the typed errors,
  until the release is back. This release's CLI still runs `user
  undo-recovery` against the same schema.
- Start recoveries only once a rollout is over. A replica of the previous release
  can't decode the new recovery emails, and marks them failed; resend them with
  `auth-service deliveries retry <id>`.

## Threat model

The operator path, against #85's threats.

| Threat | What the operator path does |
| --- | --- |
| Remote phishing | Only support starts recoveries. A link phished out of the owner gives a probation sign-in: it can use the account and apps, but can't keep a way in (P1, P2). Undo takes back its passkey, sessions, refresh grants and consents (U2). |
| Channel takeover | The link goes to the primary (L2), so a hijacked mailbox gets it; the evidence policy never relies on that mailbox alone. The link holder can't change addresses, add a way in or redirect the next link (P1, L2). Every verified address hears of it (C2), and so does the owner the next time they sign in with an older passkey (C3). A social identity is never a recovery method. |
| Social engineering of the operator | The main way to attack this design. A plain recovery gets the attacker a probation sign-in at most, which the owner's older passkey undoes (U1) or support does (U5), and support can't be talked into removing older passkeys meanwhile (U1a), nor into outlasting the undo by disabling the account (U4a). A `--revoke` recovery takes the owner's own undo away, so it needs a higher bar of evidence, and it notifies every verified address at once, so a kept passkey can cancel it (S5). A second recovery needs the first undone (S2), the listing shows earlier attempts (S6), and administrators are never recovered or made mid-recovery (A1). |
| Stolen older passkey | It grants everything with or without a recovery (X1). Support recovers with `--revoke` (S5). |
| Insider or database access | Database access is the root of trust (see [NIST](#nist-sp-800-63b-4)): an operator can do anything. CLI changes record `Actor::Cli` with `$USER` and the host, and the reason; the owner sees that an operator acted. Tamper evidence is #31. |
| Close-proximity attacker | As for a mailbox: a probation sign-in, notices to every address, the sign-in prompt, and undo by an older passkey. |
| Harassment | Only support starts recoveries, and each mails one link to one address. Dedicated recovery rate limits (#86) are not built yet. |
| Lockout | The path exists for it. With only the recovered passkey, the owner can't change security settings or add a second passkey for 15 days; if they lose the recovered passkey meanwhile, support undoes the recovery and starts another (U5, S2). |

## Decisions that replace #85's sketch

- **Immediate recovery with a 15-day probation, not a 7-day wait.** A wait adds no
  evidence; it only gives the owner time to object. The operator path serves an
  owner who is locked out now, so it signs them in at once. For 15 days, the
  owner can undo it with a passkey from before it, which is stronger than
  noticing an email.
- **#85's restriction, at the credential.** #85 sketched sessions from the
  recovered passkey reporting an AAL1-grade `acr`, and a restriction checked in
  `Confirmed`. This path does it where the passkey is accepted: the recovered
  passkey never confirms, so it reports `acr` Social and every confirmation gate
  refuses it, the admin API and relying parties included. It needs no new `acr`
  value, which older releases and SDKs would not know.
- **A fixed undo.** The sketch rolled back the recovered passkey, sessions,
  refresh families and consents. That is the whole list here too, because the
  probation leaves nothing else to take back. A consent is withdrawn whatever
  its age, which needs no record of when it was given.
- **No account is recovered while it holds administrator rights,** and none
  becomes an administrator mid-recovery. The sketch let the CLI recover
  administrators.

Other differences: the recovered passkey is recorded on the recovery
(`account_recoveries.passkey_id`) and in its `RecoveryCompleted` event, not in a
`recovered_by` column on the passkey; the link lives 24 hours from its start.

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
the probation (P1), which also keeps the assurance claim honest: a recovered
passkey reports `acr` Social, not `phr`, until it settles. Then the notice to
every verified address (C2), the 15-day undo by a pre-existing authenticator
(U1), the rule that nothing takes that undo away (U1a, U4a), the reason recorded
for the owner (S3), and the administrator rules (A1).

## Support's evidence policy

**For the user to review.** Support runs `user recover` and `user undo-recovery`
only on evidence. No single item below is enough on its own, and the items under
"never enough" must not count at all.

**Write every reason without the evidence.** Every reason an operator or
administrator records with a recovery, an undo or a cleanup shows in the
account's history, which whoever used the link can read. Say what was asked and
that the evidence policy was followed; keep the evidence itself (channels,
questions, answers) in support's own record.

Before `user recover`:

1. **Read the account and its history:** `auth-service user show <user>`, then
   `auth-service account <user> history`, which shows each change and sign-in
   with its device and IP. Look for signs the account is already compromised:
   identities linked, addresses added or a primary change recently, sign-ins
   from new devices. The link goes to the current primary verified address. If
   the primary changed recently, establish the owner through older channels and
   restore the older primary first with `auth-service account <user> emails
   primary <id> --reason "…"`, or use `--revoke`, which only prints the link.
2. **Read the listing `user recover` prints.** If a recovery is in probation,
   find out who used it before anything else; `user recover` refuses until it is
   undone or settles. If it was not the requester, undo it with `user
   undo-recovery` under the rules below. A recovery undone recently by its owner
   means someone asked before: treat a new request with suspicion.
3. **Confirm the request through a second channel that existed before it**, and
   that is not the address the link will go to: another verified address on the
   account, an organization contact known beforehand, or a reply to a message
   the account sent long before.
4. **Ask for what only the owner should know, and check it against the
   history:** roughly when the account was created, its passkeys' names, the
   apps it signed in to, where it usually signs in from. Treat this as
   supporting evidence: someone close to the owner may know it.
5. **Prefer the email to the printed link.** Print the link to the requester only
   when the recovery has no address to mail, and only through the channel
   confirmed in 3, never through the channel the request came from.

Before `user recover --revoke`, which takes the owner's own undo away:

1. **Hold it to a higher bar:** two independent channels that existed before the
   request, never a channel the account lists now.
2. **Keep every passkey the owner vouches for** with `--keep`, so they can still
   undo it. Revoke only what may be in someone else's hands.
3. **Run it before any cleanup,** then remove the addresses the owner does not
   recognize and review owned clients, and only then hand the link over through
   the confirmed channel.

Before `user undo-recovery`, on a claim that a recovery was not the owner's:

1. **Establish the owner through evidence from before the recovery:** channels
   and history that predate its start.
2. **A request coming through the recovery's passkey** is a request from whoever
   used the link. Anything added during its probation postdates the recovery, so
   it is no evidence for the first rule; a passkey added then can undo the
   recovery itself (U1).

Before disabling an account that has a recovery in probation, at its user's
request: treat it like an undo request, and prefer `user undo-recovery`.
Disabling does not stop the owner's undo (U4a).

Never enough on its own:

- A request from the account's own email address, or a reply to it: it may be
  the compromised channel, and the link goes there.
- A request from a social identity linked to the account, or a message on that
  provider: social accounts are taken over often.
- Knowledge of the username, display name, email address or anything public.
- Urgency, distress, authority or threats, or a claim to be staff.

Mid-recovery, nobody may remove an older passkey (U1a). A request to remove
"my stolen phone's passkey" during a recovery may come from whoever used the
link. If the owner is confirmed, undo the recovery and start again with
`--revoke`.

## What is left

From #85, not built by this path:

- Self-service recovery: a saved recovery key plus an issued email code, the
  NIST-compliant path, with its pages. It would create the same
  `account_recoveries` row with other evidence, and get the same probation.
- Passkey backup-state warnings and prompts for a second passkey, in settings
  and the security center: prevention first.
- Dedicated rate limits on recovery endpoints (#86); only the general per-IP
  request budget covers them today.
- The `/recover` and `/recover/undo` pages, and the "Was this you?" prompt
  *(planned, from the pages stream)*. The APIs are live, but no page uses a link
  yet, and `user recover` says so.
