# Recover your account

If you lost every passkey of your account, SourceOrigin support can help you add a
new one. This page explains how to ask, and what happens once support starts
the recovery.

## Before you start

- If you still have one passkey, you don't need a recovery. Sign in with it,
  then add a new passkey in **Sign-in methods**.
- You need access to your account's primary email address: support emails the
  recovery link there.

## Ask support

Email [contact@sourceorigin.dev](mailto:contact@sourceorigin.dev) with your handle, and say
that you lost every passkey.

Support then checks that you own the account. They confirm your request through
a channel that existed before you asked, and may ask you questions about your
account. Support never accepts these as proof:

- an email from the account's own address, which may be the one someone else
  took over,
- a message from a GitHub or Google account linked to it,
- anything public about the account, such as its handle.

This can take some time. It is what stops someone else from recovering your
account by pretending to be you.

## Add your new passkey

When support starts the recovery, every device is signed out of your account,
and email addresses you hadn't confirmed are removed. Support emails a link to
your primary email address, with the subject "Recover your Origin Account". If
your account has no confirmed address, support gives you the link through the
channel they confirmed.

1. Open the link from the email. It works once, for 24 hours.
2. Select **Continue**. The page names your account and says until when the
   link works.
3. Enter a **Passkey name**, such as the name of your device.
4. Select **Create a passkey**, then follow your device's steps.

You are signed in, and your settings say "Your account is recovered. Your new
passkey signs you in."

## The first 15 days

For 15 days after you used the link, your new passkey signs you in, but it gives
no [passkey confirmation](../account/signing-in.md#passkey-confirmation). So, until
then, you can't:

- add or remove a passkey,
- link or unlink GitHub or Google sign-in,
- add or remove an email address, or change the primary one,
- change your handle,
- register or change apps in the developer console,
- [download your data](export-your-data.md) or
  [delete your account](delete-your-account.md),
- use apps that ask for a passkey confirmation.

You can still use your account and sign in to other apps. Your settings show,
until the date it ends, that the passkey the recovery added can't confirm
changes.

These 15 days protect you if the link reached someone else: they could use the
account, but not keep a way into it, and you could
[undo the recovery](undo-a-recovery.md) with a passkey you had before.

After 15 days, your new passkey works like any other. Add a second passkey then,
so you can always get back in.

## "Was this you?"

While a recovery can be undone, every settings and developer console page asks
"Your account was recovered on \<date>. Was this you?". Before the link is
used, it says "SourceOrigin support started a recovery of your account on \<date>"
instead.

- Select **Yes, it was me** to hide the question in this browser.
- Select **No, undo it** if you didn't recover your account. See
  [undo a recovery](undo-a-recovery.md).

Signing in to an app asks the same question. Select **Yes, continue** to go on
to the app.

## If someone else had your account

If someone else got into your account, for example with your stolen phone,
support may secure it before recovering it. Because this takes away your own
way to undo the recovery, support asks for stronger proof first. They:

- sign every device out,
- remove every passkey, except those you tell them are yours,
- unlink GitHub and Google sign-in,
- withdraw every app's access to your account.

Every confirmed email address of the account receives "SourceOrigin support secured
your account". Support then gives you the recovery link themselves, through the
channel they confirmed, rather than emailing it. Undoing this recovery later
doesn't bring back what support removed.

## Troubleshooting

- **"This recovery link no longer works."** The link was used, expired after 24
  hours, or was cancelled. Ask support for a new one.
- **"This link is incomplete."** Open the link again from the email, without
  changing it.
- **"Opening this link needs scripts allowed."** Allow JavaScript for
  auth.sourceorigin.dev, then open the link again.
- **You lost the new passkey within the 15 days.** It can't add a second
  passkey yet, so contact support. They can undo the recovery and start another.
