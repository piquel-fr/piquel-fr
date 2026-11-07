# Creating an account

A piquel.fr account is a handle and a passkey. This page shows how to create
one, with an invitation, and how to start from a GitHub or Google account
instead.

## Before you start

- A browser that supports passkeys, such as a recent Safari, Chrome, Firefox or
  Edge, with scripts allowed.
- A device or password manager that keeps passkeys: your phone or computer,
  a password manager, or a security key.
- An invitation link. piquel.fr only lets people sign up with an invitation
  for now. To ask for one, write to [contact@piquel.fr](mailto:contact@piquel.fr).

## Create an account with a passkey

1. Open the invitation link you received. It opens **Create your account** at
   `auth.piquel.fr/register`, with the **Invitation** field already filled in.
2. Under **Handle**, choose your [handle](profile.md#your-handle): 3 to 32
   lowercase letters, numbers, or single hyphens between them.
3. Under **Passkey name**, name the passkey after where it is kept, such as
   `iPhone` or `1Password`. You can rename it later.
4. On Android, choose where to save the passkey under **Save this passkey
   with**. Keep **Passkey or security key** unless you want **Google Password
   Manager on this device**.
5. Select **Create account with a passkey**, then follow your browser's
   prompt to create the passkey.

Piquel creates the account, signs you in and opens your settings. Your display
name starts as your handle; you can change it on the
[Profile](profile.md) tab.

An invitation works once. After it creates an account, or once it expires, it
no longer works.

## Create an account with GitHub or Google

You can start from a GitHub or Google account. Your Piquel account still needs
a passkey: it is created only once you add one.

1. Open `auth.piquel.fr/login` and select **GitHub** or **Google**.
2. Sign in at the provider and allow Piquel.
3. Back on Piquel, **Create your account** says **Finish creating your account
   to add GitHub sign-in** (or Google). Fill in **Handle**, **Passkey name**
   and **Invitation** as above, then select **Create account with a
   passkey**.

The account is created with its passkey, and GitHub or Google is linked to it,
so either signs you in from then on. Your profile picture there becomes your
Piquel picture, when Piquel can fetch it. If the provider shares your email
address, Piquel adds it:
an address the provider hosts, such as a Gmail address, arrives confirmed, and
any other gets a [confirmation link](email-addresses.md#confirm-an-address)
first.

Finish in the same browser within 10 minutes. After that, the provider's
sign-in is forgotten and you start again.

## Check that it works

Your settings open at `auth.piquel.fr/settings`. The
[Sign-in methods](sign-in-methods.md) tab lists your passkey, and GitHub or
Google if you started with it. Next, [sign in](signing-in.md) from another
device, or add a [second passkey](sign-in-methods.md#add-a-passkey) so you
can always get back in.

## Troubleshooting

- **The Create account button stays disabled.** The page says your browser
  can't use passkeys here. Open it in a browser that supports passkeys, with
  scripts allowed, over `https://`.
- **"A valid invitation is required."** The **Invitation** field is empty or
  wrong. Open the invitation link again rather than typing the invitation.
- **"This invitation has expired or has already been used."** Ask for a new
  invitation.
- **"This handle is taken. Choose another one."** Another account has it.
  Handles that [look alike](profile.md#handle-rules), or that belonged to
  another account, are refused too, and the page says which.
- **The provider sends you to "Add this sign-in method?" instead.** Your
  GitHub or Google email address belongs to an existing Piquel account. Sign
  in to that account with its passkey to link the provider, or select
  **Cancel linking**.
