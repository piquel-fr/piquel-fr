# Undo a recovery

If SourceOrigin support recovered your account and it wasn't you, undo the recovery
with a passkey you had before it. Undoing takes back the passkey the recovery
added, and signs everyone out. You can undo a recovery for 15 days after its
link was used, or cancel it before.

## Before you start

You need a passkey your account had before the recovery. The passkey the
recovery added can't undo it. Without an older passkey, see
[no passkey from before](#no-passkey-from-before).

## The notices you receive

A recovery tells you in several ways:

- **"Recover your Origin Account"**, sent to your primary email address when
  support starts the recovery. It holds the recovery link, and a second link to
  cancel the recovery if you still have a passkey.
- **"A recovery added a passkey to your account"**, sent to every confirmed
  email address of the account once the link is used. It links to the page that
  undoes the recovery.
- **"SourceOrigin support secured your account"**, sent to every confirmed address
  when support removed your other ways to sign in first. It links to the undo
  page only if support kept one of your passkeys.
- **"Was this you?"**, asked on every settings and developer console page, and
  when you sign in to an app with your account.

The second and third notices also appear in your settings, under
**Notifications**.

## Undo it

1. Open the undo link from one of the emails, or select **No, undo it** where
   your account asks "Was this you?". Before the recovery link is used, the
   question offers **No, cancel it** instead. Signed in, you can also open
   `auth.sourceorigin.dev/recover/undo`.
2. If the page asks, select **Continue**. It then says what the recovery did,
   until when it can be undone, and what undoing takes back.
3. Select **Undo it with a passkey**, or **Cancel it with a passkey** before the
   link is used.
4. Use a passkey you had before the recovery.

You are signed in with that passkey, and your settings say "The recovery is
undone." The undo page works even when you are signed out, so whoever used the
link can't stop you by signing you out.

## What undoing takes back

Undoing a recovery whose link was used:

- removes the passkey the recovery added,
- signs every device out,
- withdraws every app's access to your account. Each app asks for your consent
  again the next time you sign in to it.

Cancelling a recovery whose link wasn't used yet makes the link stop working.

Undoing doesn't reach everything. Whoever used the link could, during those
days, change your display name or profile picture, and use apps that don't ask
for a passkey confirmation. Undoing doesn't revert any of this, and an app may
keep them signed in on its own side. Check your **Security history** in your
settings, and each app you use.

## No passkey from before

If you have no passkey from before the recovery, the undo page says "You have no
passkey from before this recovery, so only SourceOrigin support can undo it."

Email [contact@sourceorigin.dev](mailto:contact@sourceorigin.dev). Support checks that you own
the account, with evidence from before the recovery, as they do for
[a recovery](recover-your-account.md#ask-support). A request sent from the
account itself while it is being recovered doesn't count: it may come from
whoever used the link. Support can then undo the recovery, and start a new one
for you.

While a recovery can be undone, nobody can remove the passkeys your account had
before it, not even support. That keeps your ability to undo it.

## Troubleshooting

- **"There's nothing to undo."** The recovery was already undone or cancelled,
  or its 15 days ended, or the link is wrong. After the 15 days, contact
  support.
- **"Use a passkey you had before this recovery to undo it, or ask SourceOrigin
  support."** You used the passkey the recovery added. Use an older one.
- **"Your account is disabled, so you're not signed in."** The undo worked, but
  your account is disabled. Contact support to enable it.
- **Your account is scheduled for deletion.** Restore it first, by signing in
  with a passkey you had before (see
  [delete your account](delete-your-account.md#restore-your-account)), then
  undo the recovery.
- **An older passkey was stolen.** You can't remove it while the recovery can
  be undone. Contact support, who can undo the recovery and secure your account.
