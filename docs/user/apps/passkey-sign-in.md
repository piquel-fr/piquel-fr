# Passkey sign-in on your own pages

A trusted client's pages can sign users in with their auth passkeys without
leaving for auth's pages, through WebAuthn related origins (WebAuthn Level 3
§5.11).

## Approve the origin

An administrator approves each origin on the dashboard's Clients page,
which lists them, or with the CLI:

```sh
just auth client origin add blog https://blog.example
just auth client origin list         # --output json for scripts
just auth client origin remove blog https://blog.example
```

The client must be trusted, since this sign-in skips the consent page, and the
origin must be the origin of one of its redirect URIs. Browsers honour only a few
distinct domains in the list, so approved origins may span at most 5 registrable
domains (`example` counts once for `app.example.co.uk` and `www.example.co.uk`).
Browsers count origins within auth's own domain too, as `piquel`; a host without a
registrable domain, such as `localhost`, counts none and is accepted only within
auth's domain. `/.well-known/webauthn` lists the approved origins, cacheable for
five minutes and readable from any origin. Auth refuses a removed origin's
sign-ins at once, and deleting a client removes its origins.

## Sign in

The page pushes an authorization request with PKCE, from its own origin, then posts
its `request_uri` as `{"request_uri": …}` to `/webauthn/related/start`, with
`content-type: application/json` and `x-piquel-csrf: 1`. It runs the WebAuthn
assertion the answer describes, then posts `{"ceremony_id": …, "credential": …}`
to `/webauthn/related/finish`, which answers `{code, state, iss}` as JSON instead
of redirecting. The page checks `state` and `iss`, and redeems the code with its
verifier as usual. These calls send no cookies and get none: the sign-in creates a
session that only the client's tokens use, recorded with the page's origin in the
user's security history. A request with `prompt=consent` or `prompt=none`, or an
`id_token_hint` naming an account without passkeys, is refused at start with
`interaction_required` and left unclaimed, so the page can send the browser to
`/oauth/authorize?client_id=…&request_uri=…` with it instead. Finish answers
`interaction_required` when the sign-in falls short of the request, such as a
recovered passkey during its probation against `acr_values=phr`, or when the
account is scheduled for deletion, which only auth's pages restore; the request was
claimed at start, so the page pushes a fresh one before sending the browser to
auth with it. The page should also redirect when the browser lacks related origins
(`PublicKeyCredential.getClientCapabilities()` has no `relatedOrigins`), and push a
fresh request first when a start or the passkey prompt failed, since auth may have
claimed the first one. The TypeScript SDK's browser client runs this flow with every fallback
(`signInWithPasskey` in [`@piquel/auth/browser`](https://github.com/piquel-fr/piquel-fr/blob/main/packages/auth/README.md#browser-apps)).
