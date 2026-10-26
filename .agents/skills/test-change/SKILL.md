---
name: test-change
description: >
  Test a change end to end on a piqueld preview, then hand the running preview
  to the user so they can try it too. Use after changing auth, the web
  frontends, the database, or infra/, before reporting the work as done, and
  whenever asked to test, verify, or QA a change.
---

# Test a change

Passing unit tests is not the same as working. Test the change where it will
run, against real PostgreSQL behind real HTTPS, then let the user try it.

## 1. Check locally first

Run only the checks for what changed: `just test -p <crate>`, `just rust lint`
or `just web lint`, and `just web check`. For changes to
`infra/piqueld.toml`, run `piquelctl app validate --file infra/piqueld.toml`.
Fix failures before deploying: a preview build costs minutes.

## 2. Deploy a preview

Follow the `preview` skill: `just preview` in the background, then note the
URLs it prints. Below, `$auth` is `https://auth-<slug>.dev.piquel.fr`, which
serves the settings at `/settings`. `$web`, `https://<slug>.dev.piquel.fr`, only
redirects to it.

## 3. Smoke-test the deployment

```sh
curl -fsS "$auth/health/ready"
curl -fsS -o /dev/null -D - "$auth/settings"   # content-security-policy: default-src 'none'; ...; connect-src 'self'; ...
curl -sSI "$web/settings?x=1"                  # 307, location: $auth/settings?x=1
piquelctl preview logs piquel-fr "$(git branch --show-current)" --tail 200
```

Look for errors and panics in the logs even when everything answers.

## 4. Exercise the change like a user

Plan the checks from the change itself: the flow it adds or fixes, its error
paths (bad input, expired or replayed links, missing permissions), and the
flows next to it that it could break. Signing up, signing in and loading
settings are always worth one pass.

- **Pages and layout:** open `$auth`, or `$auth/settings`, in T3 Code's preview
  browser (`preview_open`), and take screenshots of what changed.
- **Passkeys:** the preview browser cannot create passkeys. Drive Chromium
  with Playwright and its virtual authenticator instead, as
  `tests/browser/settings.spec.ts` does (`WebAuthn.enable`, then
  `WebAuthn.addVirtualAuthenticator`). For a one-off check, run a script from
  the repository root so it resolves `@playwright/test`, e.g.
  `node --input-type=module -e "import { chromium } from '@playwright/test'; ..."`.
  Set `CHROMIUM_EXECUTABLE` (or `executablePath`) to a Chromium binary; on
  NixOS, `$(nix build --no-link --print-out-paths nixpkgs#chromium)/bin/chromium`.
- **APIs:** `curl` the auth API directly. State-changing requests need
  `origin: $auth`, `content-type: application/json` and `x-piquel-csrf: 1`; any
  other origin is refused. A settings form's post needs only `origin: $auth`.
  Account endpoints and settings also need a session cookie, so those checks are
  usually simpler from Playwright.
- **Lasting coverage:** if the change deserves a regression test, add a focused
  spec to `tests/browser`. `oidc.spec.ts` also needs the `browser-e2e` OIDC
  client, which previews don't register. When consent or OIDC changes, run the
  suite as `tests/browser/README.md` describes.

After fixing anything, run `just preview` again and repeat the checks the fix
could affect.

## 5. Hand it to the user

Leave the preview running and tell the user, in chat:

- the auth URL and its `/settings`, as links;
- that they work from any device on their tailnet, so they can register a real
  passkey from their phone or laptop, and that registration needs no
  invitation;
- what to try: concrete steps for the changed behaviour;
- what you verified and how, and what you could not (real devices, Google or
  GitHub sign-in, production-only configuration);
- that `just preview-delete` removes the preview once they are done.

Report failures as failures, with the command and its output. Don't present a
partially working preview as done.
