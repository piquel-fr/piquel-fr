# Creating an account

An Origin Account is a handle and a passkey. This page shows how to create
one, with an invitation, and how to start from a GitHub or Google account
instead.

## Before you start

- A browser that supports passkeys, such as a recent Safari, Chrome, Firefox or
  Edge, with scripts allowed.
- A device or password manager that keeps passkeys: your phone or computer,
  a password manager, or a security key with room to store one.
- An invitation link. SourceOrigin only lets people sign up with an invitation
  for now. To ask for one, write to [contact@sourceorigin.dev](mailto:contact@sourceorigin.dev).
  The invitation may come by email, from SourceOrigin, or as a link someone
  sends you.

## Create an account with a passkey

1. Open the invitation link you received, or select **Create your account** in
   the invitation email. It opens **Create your account** at
   `auth.sourceorigin.dev/register`, with the **Invitation** field already filled
   in. If the invitation was emailed to you, the page names your address.
2. Under **Handle**, choose your [handle](profile.md#your-handle): 3 to 32
   lowercase letters, numbers, or single hyphens between them.
3. Under **Passkey name**, name the passkey after where it is kept, such as
   `iPhone` or `1Password`. You can rename it later.
4. On Android, choose where to save the passkey under **Save this passkey
   with**. Keep **Passkey or security key** unless you want **Google Password
   Manager on this device**.
5. Select **Create account with a passkey**, then follow your browser's
   prompt to create the passkey.

SourceOrigin creates the account, signs you in and opens your settings. Your display
name starts as your handle; you can change it on the
[Profile](profile.md) tab.

If the invitation was emailed to you, your account starts with that address,
already confirmed, as its primary address. You can add others, or remove it, on
the [Email addresses](email-addresses.md) tab.

An invitation works once. After it creates an account, or once it expires, it
no longer works.

## Create an account with GitHub or Google

You can start from a GitHub or Google account. Your Origin Account still needs
a passkey: it is created only once you add one.

1. Open `auth.sourceorigin.dev/login` and select **GitHub** or **Google**.
2. Sign in at the provider and allow SourceOrigin.
3. Back on SourceOrigin, **Create your account** says **Finish creating your account
   to add GitHub sign-in** (or Google). Fill in **Handle** and **Passkey name**
   as above. The **Invitation** field is empty on this path: paste the code
   from your invitation link, the part after `invitation=`. Then select
   **Create account with a passkey**.

The account is created with its passkey, and GitHub or Google is linked to it,
so either signs you in from then on. Your profile picture there becomes your
SourceOrigin picture, when SourceOrigin can fetch it. If the provider shares your email
address, SourceOrigin adds it:
an address the provider hosts, such as a Gmail address, arrives confirmed, and
any other gets a [confirmation link](email-addresses.md#confirm-an-address)
first.

Finish in the same browser within 10 minutes. After that, the provider's
sign-in is forgotten and you start again.

## Check that it works

Your settings open at `auth.sourceorigin.dev/settings`. The
[Sign-in methods](sign-in-methods.md) tab lists your passkey, and GitHub or
Google if you started with it. Next, [sign in](signing-in.md) from another
device, or add a [second passkey](sign-in-methods.md#add-a-passkey) so you
can always get back in.

## Troubleshooting

- **The Create account button stays disabled.** The page says your browser
  can't use passkeys here. Open it in a browser that supports passkeys, with
  scripts allowed, over `https://`.
- **"A valid invitation is required."** The **Invitation** field is empty or
  wrong. Open the invitation link again rather than typing the invitation. If
  you started with GitHub or Google, paste only the code after `invitation=`
  instead: opening the link would start a new account without them.
- **"This invitation has expired or has already been used."** Ask for a new
  invitation. The page says so as soon as it opens, too.
- **Your account doesn't have the address the invitation was emailed to.**
  Another account confirmed it before you signed up. Use another address, or
  contact SourceOrigin support.
- **"This handle is taken. Choose another one."** Another account has it.
  Handles that [look alike](profile.md#handle-rules), or that belonged to
  another account, are refused too, and the page says which.
- **The provider sends you to "Add this sign-in method?" instead.** Your
  GitHub or Google email address belongs to an existing Origin Account. Sign
  in to that account with its passkey to link the provider, or select
  **Cancel linking**.
