# Download your data

You can download everything SourceOrigin keeps about your account, in one JSON file,
from your settings.

## Before you start

You need one of your account's passkeys: downloading needs a
[passkey confirmation](../account/signing-in.md#passkey-confirmation). A passkey
added by a [recovery](recover-your-account.md#the-first-15-days) can't download
your data during its first 15 days.

## Download it

1. In your settings, open **Your data**.
2. Select **Download your data**.
3. If Origin Auth asks, confirm with your passkey.

![The Your data tab: Download your data, and Delete your account](../../images/account/data.png)

Your browser saves a file named `sourceorigin-account-<handle>-<date>.json`. The
download is recorded in your **Security history**, as "Account data
downloaded".

## What the file holds

- your profile: account ID, handle, display name, and when the account was
  created,
- your profile picture,
- every handle the account holds or held, with their dates,
- your email addresses, confirmed or not,
- your passkeys: their names, when they were added and last used, and whether
  they sync between devices,
- the GitHub or Google accounts linked to it,
- the devices signed in to your account, with their IP addresses, and, if you
  are an administrator, the admin dashboards signed in through each,
- the apps you gave access to, with what each may read, and their access
  grants,
- the apps you registered in the developer console,
- the recoveries support started for your account,
- your security history and your notifications, with which kinds of
  notifications you receive by email,
- whether you are an administrator.

## What it doesn't hold

- **Secrets.** It holds no passkey keys, no tokens and no recovery links.
- **What apps keep.** Apps you signed in to keep their own records of you. Ask
  each app for its data.

Only you can download your data. SourceOrigin support can't download it for you.
