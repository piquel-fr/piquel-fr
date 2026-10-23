<script lang="ts">
  import { page } from '$app/state';
  import Copy from '$lib/Copy.svelte';
  import { ManagedClient } from '$lib/clients.svelte';
  const managed = ManagedClient.current();
  const issuer = page.data.authOrigin;
  const client = $derived(managed.client);
  const confidential = $derived(client?.kind === 'confidential');
  // The settings any OpenID Connect library needs.
  const settings = $derived(
    client
      ? [
          { label: 'Issuer', value: issuer },
          { label: 'Discovery URL', value: `${issuer}/.well-known/openid-configuration` },
          { label: 'Client ID', value: client.id },
          {
            label: 'Client authentication',
            value: confidential ? 'client_secret_basic' : 'none'
          },
          { label: 'Scopes', value: client.allowed_scopes.join(' ') },
          ...(client.backchannel_logout_uri
            ? [{ label: 'Back-channel logout URI', value: client.backchannel_logout_uri }]
            : [])
        ]
      : []
  );
  // Never the secret itself: the app reads it from its environment.
  const rust = $derived(
    client
      ? `// Cargo.toml: piquel-auth = { git = "https://github.com/piquel-fr/piquel-fr", features = ["axum"] }
use axum::{Router, routing::get};
use piquel_auth::axum::{LoginRoutes, MemoryBackend, SignedIn};
use piquel_auth::{ClientConfig, Credentials, Issuer};

async fn home(user: SignedIn) -> String {
    format!("Hello {}", user.name())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = Issuer::discover("${issuer}").await?;
    let config = ClientConfig {
        client_id: "${client.id}".parse()?,
        credentials: ${confidential ? 'Credentials::Secret(std::env::var("PIQUEL_CLIENT_SECRET")?.into())' : 'Credentials::None'},
        // The login routes' callback, nested at /auth below: register it as a redirect URI.
        redirect_uri: "${client.redirect_uris[0] ?? 'https://app.example/auth/callback'}".parse()?,
    };
    // Sessions in memory, lost on restart: implement SessionBackend to keep them.
    let auth = LoginRoutes::new(issuer.client(config), MemoryBackend::default())
        .scopes("${client.allowed_scopes.filter((scope) => scope !== 'openid').join(' ')}".parse()?);
    let app = Router::new()
        .route("/", get(home))
        .nest("/auth", auth.router())
        .layer(auth.layer());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}`
      : ''
  );
</script>

<svelte:head><title>{client?.display_name ?? 'App'} · Piquel</title></svelte:head>
{#if client}
  {#if client.suspended_at}<p class="notice error">
      An administrator suspended this app on {new Date(client.suspended_at).toLocaleDateString()}:
      it cannot sign users in. Contact them to restore it.
    </p>{:else if !client.enabled}<p class="notice">
      This app is disabled: it cannot sign users in until you enable it in its settings.
    </p>{/if}
  <section class="card" aria-labelledby="oidc-heading">
    <h2 id="oidc-heading">OpenID Connect settings</h2>
    <p class="help">
      For any OpenID Connect library. Use the authorization code flow with PKCE (S256){confidential
        ? ', and send the client secret with HTTP Basic authentication'
        : ''}.
    </p>
    <dl class="settings-list">
      {#each settings as setting (setting.label)}<div>
          <dt>{setting.label}</dt>
          <dd class="row between code-line">
            <code>{setting.value}</code><Copy value={setting.value} label={setting.label} />
          </dd>
        </div>{/each}
      <div>
        <dt>Redirect URIs</dt>
        <dd>
          {#each client.redirect_uris as uri (uri)}<code class="block">{uri}</code>{/each}
        </dd>
      </div>
    </dl>
    {#if confidential}<p class="help">
        Keep the client secret on your server, for example in a <code>PIQUEL_CLIENT_SECRET</code>
        environment variable. Lost it? Rotate it on the
        <a href={`${page.url.pathname}/secrets`}>Secrets</a> tab.
      </p>{/if}
  </section>
  <section class="card stack" aria-labelledby="rust-heading">
    <div class="row between">
      <h2 id="rust-heading">Rust with axum</h2>
      <Copy value={rust} label="Rust example" />
    </div>
    <p class="help">
      The <a href="https://github.com/piquel-fr/piquel-fr/tree/main/crates/auth-sdk">Rust SDK</a>
      signs users in on your server and keeps their tokens there.
    </p>
    <pre><code>{rust}</code></pre>
  </section>
  <section class="card stack" aria-labelledby="step-up-heading">
    <h2 id="step-up-heading">Sensitive actions</h2>
    <p>
      Before an action that needs a fresh passkey, such as deleting data, your app can ask users to
      sign in again with one. <a
        href="https://github.com/piquel-fr/piquel-fr/blob/main/docs/guides/step-up-authentication.md"
        >The step-up guide</a
      > explains how.
    </p>
  </section>
{/if}
