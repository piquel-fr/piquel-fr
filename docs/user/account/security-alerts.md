# Security alerts

SourceOrigin alerts you when something changes how your account can be used: a
new device signs in, a sign-in method or address is added or removed, or
support acts on your account. Use the alerts to catch someone else using your
account early.

## Before you start

You need an Origin Account. To receive alerts by email, you need a
[confirmed email address](email-addresses.md).

## What SourceOrigin alerts you about

- **A new device signed in.** A browser that never signed in to your account
  did. Each browser stays known for 400 days after its last sign-in, even once
  you sign out of it. The browsers that create your account, or that add a
  passkey from a recovery link, become known without an alert.
- **A passkey was added or removed.**
- **GitHub or Google was linked or unlinked.**
- **An email address was added**, including one that came from GitHub or Google
  when you linked it. A change of primary address and a removed address are
  told too, at the address concerned: see [notifications](notifications.md#emails).
- **An app's sign-in token was used twice.** That happens when a token is
  stolen, so Origin Auth signs that app out.
- **SourceOrigin support started a recovery of your account**, or someone used
  its link to add a passkey. Both reach every confirmed address, so one lost
  mailbox can't hide them. You're also told when a recovery is undone.
- **SourceOrigin support changed your account**: disabled, enabled, scheduled
  for deletion or restored it, changed your handle or display name, renamed one
  of your passkeys, removed your picture, or signed your devices out.
- **A copy of one of your passkeys was refused.** Its signature showed it may
  have been copied.
- **A sign-in to your disabled account was refused**, which means someone holds
  one of your passkeys or social sign-ins.
- **You reported activity that wasn't you**, as a confirmation.

Sign-ins on an app's own page with your passkey never alert: they already
needed the passkey itself. A sign-in from a new country, on a browser you
already used, doesn't alert either.

## Answer an alert in your settings

The bell at the top of every settings page counts your unread notifications.
If you administer Origin Auth, the admin dashboard's top bar has it too.

![The settings' top bar, with the bell counting one unread notification beside the avatar](../../images/account/notification-bell.png)

1. Select the bell. Your [notifications](notifications.md) open, unread ones
   in bold.
2. Select the alert. Opening it marks it read on every device. If it was you,
   you're done.
3. If it wasn't you, select **This wasn’t me** on the alert's page. It asks
   **Secure your account?**
4. Select **Sign out everywhere else**. Every other device and every app is
   signed out. Your [security history](security-history.md) then offers to undo
   what was added, such as removing a passkey.

Some alerts, such as support disabling your account, can't be reported: their
page has no **This wasn’t me**.

## Answer an alert by email

Every alert is also emailed, and you can't turn these emails off. The email
says what happened, and links the alert in your notifications.

If the alert wasn't you and you can't sign in to secure your account, use the
email's last link, **sign it out of every device and app**:

1. Open the link. It opens a page that asks **Sign out everywhere?** Opening it
   changes nothing.
2. Select **Sign out everywhere**. Every device and every app signed in to your
   account is signed out.
3. Sign in again with your passkey, then review your
   [security history](security-history.md). It lists the link's use as
   **Signed out everywhere with a security email's link**, with the device and
   place it was used from.

The link signs you out without signing in, so it works even if someone else is
signed in as you. It never removes a passkey or sign-in method: the worst
anyone who finds the link can do is sign you out.

## Check that it works

The **Devices** tab lists your **Known browsers**: those whose sign-in won't
alert you. See [devices](devices.md#known-browsers).

## Troubleshooting

- **An alert for a device you use.** The browser forgot its cookies, as a
  private window or clearing your browsing data does, or you didn't sign in
  with it for 400 days. Open the alert to mark it read.
- **No alert email arrives.** Alerts go to your primary confirmed address, or
  for a recovery to every confirmed one. Without a confirmed address, they
  only reach your notifications.
- **The sign-out page says "This link doesn’t work".** Each link works once,
  within 7 days of its email. Sign in and sign your other devices out from
  [devices](devices.md#sign-out-a-device), or use the link of a newer alert.
