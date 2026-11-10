# Passkey sign-in on your own pages

Let a trusted app's own pages sign users in with their Origin Account passkeys, without
sending them to auth.sourceorigin.dev. Browsers allow this through WebAuthn related
origins (WebAuthn Level 3 §5.11), once SourceOrigin approves the page's origin.

## Before you start

- The app must be trusted: one of SourceOrigin's own apps, which skip the consent
  page. Apps registered in the developer console are never trusted, so their
  pages send users to auth's pages instead.
- The origin must be the origin of one of the app's redirect URIs, over HTTPS,
  such as `https://blog.example`.
- An administrator approves the origin. Only they can.

## Approve the origin

On the admin dashboard:

1. Open the app on the **Clients** page.
2. Under **Passkey sign-in**, select **Add approved origin**, enter the origin,
   and select **Add**.

**Remove** next to an origin stops its sign-ins at once. With the CLI:

```sh
just auth client origin add blog https://blog.example --reason "Blog sign-in"
just auth client origin list         # --json for scripts
just auth client origin remove blog https://blog.example --reason "Blog moved"
```

Deleting an app removes its origins.

## Sign in with the TypeScript SDK

The browser client of [`@sourceorigin/auth/browser`](browser-apps.md)
runs the whole flow, falling back to auth's pages whenever it must:

```ts
const session = await auth.signInWithPasskey({ scopes: ['profile'] });
```

## Sign in without the SDK

1. Push an authorization request with PKCE, from the page's own origin, to
   `/oauth/par`.
2. Post its `request_uri` as `{"request_uri": …}` to `/webauthn/related/start`,
   with `content-type: application/json` and `x-sourceorigin-csrf: 1`.
3. Run the WebAuthn assertion the answer describes.
4. Post `{"ceremony_id": …, "credential": …}` to `/webauthn/related/finish`. It
   answers `{code, state, iss}` as JSON, instead of redirecting.
5. Check `state` and `iss`, and redeem the code with your PKCE verifier as
   usual.

These calls send no cookies and get none. The sign-in creates a session that
only the app's tokens use, and the user's security history records it with the
page's origin.

Send the browser to auth's pages, at
`/oauth/authorize?client_id=…&request_uri=…`, instead:

- **When start answers `interaction_required`**, with the same request. Start
  refuses a request sent with `prompt=consent` or `prompt=none`, or with an
  `id_token_hint` naming an account without passkeys, and leaves it unclaimed.
- **When finish answers `interaction_required`**, with a newly pushed request,
  since start claimed the first. Finish refuses a sign-in that falls short of
  the request, such as a passkey added by account recovery against
  `acr_values=phr`, and an account scheduled for deletion, which only auth's
  pages restore.
- **When the browser lacks related origins**: `PublicKeyCredential.getClientCapabilities()`
  has no `relatedOrigins`.
- **When start or the passkey prompt failed**, with a newly pushed request,
  since auth may have claimed the first.

## Check that it works

1. `https://auth.sourceorigin.dev/.well-known/webauthn` lists the approved origin. It
   may take five minutes to appear, since browsers may cache the list that long.
2. On the page, sign in. The browser offers your Origin Account passkeys without leaving
   the page, and the page receives a code.

## Troubleshooting

- **Approving the origin is refused.** The app isn't trusted, the origin isn't
  one of its redirect URIs' origins, or approved origins would span more than 5
  registrable domains (see [limits](#limits)).
- **The browser sends the user to auth's pages instead.** The browser doesn't
  support related origins, or auth answered `interaction_required`: see
  [troubleshooting](troubleshooting.md#interaction_required).

## Limits

Browsers honour only a few distinct domains in the list, so approved origins,
across every app, span at most 5 registrable domains: `example` counts once for
`app.example.co.uk` and `www.example.co.uk`. Browsers count origins within
auth's own domain too, as `sourceorigin`. A host without a registrable domain, such as
`localhost`, counts none, and is accepted only within auth's domain.
