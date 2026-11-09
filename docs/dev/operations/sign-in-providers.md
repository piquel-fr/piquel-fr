# Sign-in providers

This page helps you turn GitHub and Google sign-in on or off in an environment,
and rotate their client secrets.

GitHub and Google are optional ways to sign up and sign in. Each environment
enables them with OAuth apps of its own, so a staging secret never signs anyone
in to production. Previews have none: a provider only redirects back to the
callback URLs registered with it, and a preview's host is new each time. To add
another provider, see
[adding a federation provider](../extending/federation-providers.md).

## Enable a provider

1. Register an OAuth app for the environment, with its
   [callback URL](#environments).
   - **GitHub**: an OAuth app, not a GitHub App, of the `piquel-fr`
     organization, under **Settings** > **Developer settings** > **OAuth
     Apps**. Its homepage is the environment's web origin. Generate a client
     secret.
   - **Google**: in a Google Cloud project, configure the Google Auth Platform:
     branding, audience External, and data access `openid`, `email` and
     `profile`. Then add an OAuth client of type Web application, with the
     callback URL as its only authorized redirect URI. Branding links to
     `https://piquel.fr`, `https://piquel.fr/privacy` and
     `https://piquel.fr/terms`, on the authorized domain `piquel.fr`, verified
     in Search Console. Until the app is published, only its test users can
     sign in. These scopes need no verification to publish.
2. Store the client secret, mountable by that environment only:

   ```sh
   piquelctl app secret piquel-fr set github-production --stdin --environments production --no-previews
   ```

3. In `infra/piqueld.toml`, set the environment's client ID variable,
   `github_client_id` or `google_client_id`, and its `github_secret` or
   `google_secret` to the stored secret's name.
4. Merge the change. Staging uses it from the deployment that follows, and
   production from its next [promotion](deploying.md#promote-to-production).
5. Check that the environment's sign-in page offers **GitHub** or **Google**
   under "or continue with", and that it signs in.

## Rotate a client secret

1. Create a second client secret with the provider, keeping the old one.
2. Store it under the same name, with the same access:

   ```sh
   piquelctl app secret piquel-fr set github-production --stdin --environments production --no-previews
   ```

3. Deploy the environment: `piquelctl --timeout 30m env deploy piquel-fr staging`
   for staging, or [production's own release again](deploying.md#pick-up-a-changed-secret-in-production)
   for production. Auth reads and checks the secret at startup only.
4. Sign in with the provider on the environment, to check the new secret works.
5. Delete the old secret with the provider.

## Turn a provider off

1. In `infra/piqueld.toml`, remove the environment's client ID variable, or set
   it to `""`, and set its secret variable back to `no-provider-secret`.
2. Merge the change, and promote it to production if it's production's.

Auth then ignores the provider's secret, and its sign-in pages no longer offer
the provider.

## Environments

| Environment | Callback URLs | Client ID variables | Stored secrets |
| --- | --- | --- | --- |
| production | `https://auth.piquel.fr/login/github/callback`, `https://auth.piquel.fr/login/google/callback` | `github_client_id`, `google_client_id` | `github-production`, `google-production` |
| staging | `https://auth.staging.piquel.fr/login/github/callback`, `https://auth.staging.piquel.fr/login/google/callback` | `github_client_id`, `google_client_id` | `github-staging`, `google-staging` |

An empty client ID variable, the default, turns a provider off. The manifest
then mounts the generated `no-provider-secret` in its place, which auth never
reads.

GitHub asks for `read:user user:email`, and Google for `openid email profile`.
Never put a provider's secret, or a confidential client's, in frontend
configuration.
