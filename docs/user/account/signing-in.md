# Signing in

Sign in to your piquel.fr account with a passkey, or with a GitHub or Google
account you linked. This page also explains passkey confirmations, which
sensitive changes ask for even while you are signed in.

## Before you start

You need a piquel.fr account. If you don't have one yet, see
[creating an account](creating-an-account.md).

## Sign in with a passkey

1. Open `auth.piquel.fr/login`. Opening your settings, or an app that signs
   in with Piquel, while signed out brings you here too.
2. Select **Sign in with a passkey**.
3. Your browser lists the passkeys it can use. Choose your account, then
   unlock the passkey with your fingerprint, face or PIN.

Piquel signs you in and goes on to where you were headed: the app, or your
settings.

If your browser doesn't list your passkey, as with a passkey on a security key
or another device, sign in with your handle:

1. Select **Use a handle instead**.
2. Type your handle under **Handle**, then select **Sign in with a passkey**.
3. Your browser asks for one of that account's passkeys.

## Sign in with GitHub or Google

Once you have [linked](sign-in-methods.md#link-github-or-google) GitHub or
Google to your account, select **GitHub** or **Google** on the sign-in page,
under **or continue with**, and sign in there.

An app can ask for a passkey sign-in. Its sign-in page then says **This app
asks you to sign in with a passkey.** and offers no provider.

## Sign out

In your settings, select **Sign out** at the bottom of the sidebar. This ends
your session in this browser, and the apps you used through it may sign you
out too.

An app that signs you out sends you to **Ready to sign out?**: select **Sign
out**, or **Keep my session** to stay signed in.

To sign out a device you don't have with you, use [devices](devices.md).

## Passkey confirmation

Some changes need you to have used your passkey in this browser within the last
five minutes, even though you are signed in:

- changing your handle,
- adding or removing a passkey,
- linking or unlinking GitHub or Google,
- adding an email address, choosing your primary address, or removing one,
- registering an app in the developer console, or changing one.

Signing in with a passkey counts. Signing in with GitHub or Google never does.

If you haven't used your passkey in the last five minutes, your browser asks
for it as soon as you select the change's button, which says **Waiting for
your passkey…** meanwhile. Once you unlock it, the change goes ahead. The
confirmation lasts five minutes from then, and only in this browser: using
Piquel doesn't extend it.

Renaming a passkey, changing your display name or profile picture, signing out
devices and removing an app's access need no confirmation.

## Troubleshooting

- **"No active account has this handle."** Check the handle's spelling. It may
  have changed: you sign in with the handle the account has now.
- **"This passkey was removed from your account."** Use another of your
  passkeys.
- **"You last confirmed this session with a passkey. Use your passkey to sign
  in again."** This browser's session was confirmed with a passkey, so signing
  in again with GitHub or Google would weaken it. Sign in with your passkey.
- **"The Piquel account linked to this provider account is disabled or has no
  passkey."** The account can't be signed in to. Write to
  [contact@piquel.fr](mailto:contact@piquel.fr).
- **The passkey button stays disabled.** Your browser can't use passkeys here.
  Open the page in a browser that supports them, with scripts allowed.
