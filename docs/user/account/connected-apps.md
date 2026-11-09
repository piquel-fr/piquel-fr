# Connected apps

The **Connected apps** tab of your settings, at `auth.sourceorigin.dev/settings/apps`,
lists the apps you signed in to with Origin Auth that keep access to your account,
and what each can see. Remove any you no longer use.

## Before you start

You need to be [signed in](signing-in.md). Removing an app's access needs no
passkey confirmation.

## How an app gets access

The first time an app signs you in, Origin Auth asks **Continue to** the app, names
the site it sends you back to, and lists what the app will receive:

- **Your account identifier**,
- **Your username, display name and profile picture**: your
  [profile](profile.md),
- **Your verified email address**: your
  [primary address](email-addresses.md#what-apps-receive),
- **Access your account while you’re away**, for an app that keeps working
  when you aren't using it.

An app never sees your passkeys, and can't change your account. An app that
another Origin Account registered is marked **Unverified app, registered by**
the handle of whoever registered it: SourceOrigin hasn't checked who runs it, so
continue only if you trust it.

Select **Continue** to allow it, or **Cancel** to refuse. Once you allow it,
the app doesn't ask again unless it asks for more. To sign in to the app with
another account, select **Not you? Switch account**.

Apps that SourceOrigin makes don't ask: they are marked **Made by SourceOrigin**.

## Read the list

Each app shows what it **Sees**, and whether it **Can use your account while
you’re away** or **Can use your account only while you’re signed in to it**.

## Remove an app's access

1. Select **Remove access** beside the app.
2. Select **Remove access** again to confirm.

The page says **The app no longer has access to your account.** The app can
no longer refresh its access, and needs your approval again before it signs
you in. Access it already has can last up to 5 minutes.

An app made by SourceOrigin gets its access back, without asking, the next time you
sign in to it.

Removing an app's access doesn't sign out your devices: other apps share them.
To sign a device out, see [devices](devices.md).
