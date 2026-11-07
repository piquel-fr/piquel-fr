# Sign-in providers

GitHub and Google are optional ways to sign up and sign in. Each environment
enables them with an OAuth app of its own.

Provider callback URLs are `/login/github/callback` and `/login/google/callback`
on the auth origin. GitHub uses `read:user user:email`; Google uses `openid email profile`.
To add another provider, see [adding a federation provider](../extending/federation-providers.md).
Never put provider secrets or confidential-client secrets in frontend configuration.
Enabled provider secrets are loaded and validated at startup; restart the service
after rotating their referenced values.

## Environments

Production and staging each have their own GitHub and Google OAuth apps, so a
staging secret never signs anyone in to production. Previews have none: a
provider only redirects back to the callback URLs registered with it, and a
preview's host is new each time. An environment turns a provider off with an
empty client ID variable, the default; auth then ignores its secret, and the
manifest mounts the generated `no-provider-secret` in its place.

| Environment | Callback URLs | Client ID variables | Stored secrets |
| --- | --- | --- | --- |
| production | `https://auth.piquel.fr/login/github/callback`, `https://auth.piquel.fr/login/google/callback` | `github_client_id`, `google_client_id` | `github-production`, `google-production` |
| staging | `https://auth.staging.piquel.fr/login/github/callback`, `https://auth.staging.piquel.fr/login/google/callback` | `github_client_id`, `google_client_id` | `github-staging`, `google-staging` |

## Enable a provider

To enable a provider in an environment:

1. Register the app, with the environment's callback URL.
   - **GitHub**: an OAuth app (not a GitHub App) of the `piquel-fr`
     organization, under Settings > Developer settings > OAuth Apps. Its
     homepage is the environment's web origin. Generate a client secret.
   - **Google**: in a Google Cloud project, configure the Google Auth Platform
     (branding, audience External, data access `openid`, `email` and `profile`),
     then add an OAuth client of type Web application, with the callback URL as
     its only authorized redirect URI. Branding links to `https://piquel.fr`,
     `https://piquel.fr/privacy` and `https://piquel.fr/terms`, on the
     authorized domain `piquel.fr`, verified in Search Console. Until the app
     is published, only its test users can sign in; these scopes need no
     verification to publish.
2. Store the secret, mountable by that environment only, before the deploy that
   mounts it:

   ```sh
   piquelctl app secret piquel-fr set github-production --stdin --environments production --no-previews
   ```

3. In `infra/piqueld.toml`, set the environment's client ID variable, and its
   `github_secret` or `google_secret` to the stored secret's name. Production
   uses them from its next promotion.

## Rotate a client secret

To rotate a client secret, create a second one with the provider, store it under
the same name, deploy (staging) or promote (production), then delete the old one
with the provider.
