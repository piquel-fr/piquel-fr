<script lang="ts">
  import { onMount } from 'svelte';
  import {
    AuthApi,
    errorMessage,
    providerName,
    type Configuration,
    type Provider,
    type Session
  } from '@piquel/auth-client';
  // Local builds set VITE_AUTH_ORIGIN. Deployed images serve every environment, so they
  // read it from /config.json, which the container serves from its AUTH_ORIGIN (see infra/).
  let authOrigin = $state('');
  let api = new AuthApi();
  type Passkey = {
    id: string;
    friendly_name: string;
    created_at?: string;
    last_used_at?: string | null;
  };
  let config = $state<Configuration | null>(null);
  let session = $state<Session | null>(null);
  let passkeys = $state<Passkey[]>([]);
  let identities = $state<{ provider: Provider; linked_email?: string }[]>([]);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state('');
  let now = $state(Date.now());
  let editing = $state<string | null>(null);
  let name = $state('');
  let removing = $state<string | null>(null);
  const remaining = $derived(
    Math.max(
      0,
      Math.ceil(
        ((session?.management_expires_at ? Date.parse(session.management_expires_at) : 0) - now) /
          1000
      )
    )
  );
  const unlocked = $derived(remaining > 0);
  onMount(() => {
    void load();
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => {
      clearInterval(timer);
    };
  });
  async function load() {
    try {
      authOrigin = (
        import.meta.env.VITE_AUTH_ORIGIN ??
        (await api.request<{ auth_origin: string }>('/config.json')).auth_origin
      ).replace(/\/$/, '');
      api = new AuthApi(authOrigin);
      config = await api.request('/config');
      session = await api.request('/session');
      [passkeys, identities] = await Promise.all([
        api.request<Passkey[]>('/account/passkeys'),
        api.request<{ provider: Provider; linked_email?: string }[]>('/account/social-identities')
      ]);
    } catch (cause) {
      error = errorMessage(cause);
    } finally {
      loading = false;
    }
  }
  function authPage(page: string) {
    return `${authOrigin}/${page}?return_to=${encodeURIComponent(config?.settings_url ?? window.location.href)}`;
  }
  async function run(action: () => Promise<void>) {
    busy = true;
    error = '';
    try {
      await action();
    } catch (cause) {
      error = errorMessage(cause);
    } finally {
      busy = false;
    }
  }
  async function rename(passkey: Passkey) {
    await run(async () => {
      await api.request(`/account/passkeys/${passkey.id}`, 'PATCH', { friendly_name: name.trim() });
      passkey.friendly_name = name.trim();
      editing = null;
    });
  }
  async function remove(passkey: Passkey) {
    await run(async () => {
      await api.request(`/account/passkeys/${passkey.id}`, 'DELETE');
      passkeys = passkeys.filter((key) => key.id !== passkey.id);
      removing = null;
    });
  }
  async function link(provider: Provider) {
    await run(async () => {
      if (!config) throw new Error('Account settings are still loading. Please try again.');
      const result = await api.request<{ redirect_url: string }>(
        `/login/${provider}/start`,
        'POST',
        { mode: 'link', return_to: config.settings_url }
      );
      window.location.assign(result.redirect_url);
    });
  }
  async function unlink(provider: Provider) {
    await run(async () => {
      await api.request(`/account/social-identities/${provider}`, 'DELETE');
      identities = identities.filter((identity) => identity.provider !== provider);
      removing = null;
    });
  }
  async function logout() {
    await run(async () => {
      await api.request('/session/logout', 'POST', {});
      session = null;
      passkeys = [];
      identities = [];
    });
  }
</script>

<svelte:head
  ><title>Account security · Piquel</title><meta
    name="description"
    content="Manage the passkeys and social sign-in methods for your Piquel account."
  /></svelte:head
>
<section class="settings">
  <div class="settings-header">
    <p class="eyebrow">Your account</p>
    <h1>Security, made personal.</h1>
    <p>Manage how you sign in to Piquel and keep your account in your hands.</p>
  </div>
  {#if error}<p class="notice error" role="alert">{error}</p>{/if}
  {#if loading}<p role="status">Loading account settings…</p>
  {:else if !session}<div class="card stack">
      <h2>Sign in to see your settings</h2>
      <p>Use your Piquel account to manage your passkeys and linked providers.</p>
      <a class="button" href={authPage('login')}>Sign in</a>
    </div>
  {:else}
    <div class="row between">
      <div>
        <strong>{session.user.display_name}</strong>
        <p class="help">@{session.user.username}</p>
      </div>
      <button class="text-button" disabled={busy} onclick={logout}>Sign out</button>
    </div>
    <div class="notice row between">
      <div>
        {#if unlocked}<strong>Security settings unlocked</strong>
          <p class="help">
            {Math.floor(remaining / 60)}:{String(remaining % 60).padStart(2, '0')} remaining. Your passkey
            verification expires automatically.
          </p>{:else}<strong>Your settings are protected</strong>
          <p class="help">Verify a passkey to make changes for two minutes.</p>{/if}
      </div>
      {#if !unlocked}<a class="button secondary" href={authPage('manage')}>Unlock with a passkey</a
        >{/if}
    </div>
    <section class="card" aria-labelledby="passkeys-heading">
      <div class="row between">
        <h2 id="passkeys-heading">Passkeys</h2>
        <span class="badge">{passkeys.length} registered</span>
      </div>
      <p class="help">
        Saved securely with your device or password manager. Keep a second passkey so you can always
        get back in.
      </p>
      <ul class="list">
        {#each passkeys as passkey (passkey.id)}<li>
            {#if editing === passkey.id}<form
                onsubmit={(event) => {
                  event.preventDefault();
                  void rename(passkey);
                }}
              >
                <label>Passkey name<input bind:value={name} maxlength="80" required /></label>
                <div class="row actions">
                  <button disabled={busy || !unlocked}>Save name</button><button
                    class="secondary"
                    type="button"
                    onclick={() => (editing = null)}>Cancel</button
                  >
                </div>
              </form>
            {:else if removing === passkey.id}<div class="stack">
                <strong>Remove “{passkey.friendly_name}”?</strong>
                <p class="help">You won’t be able to use this passkey to sign in again.</p>
                <div class="row actions">
                  <button
                    class="danger"
                    disabled={busy || !unlocked}
                    onclick={() => remove(passkey)}>Confirm removal</button
                  ><button class="secondary" onclick={() => (removing = null)}>Cancel</button>
                </div>
              </div>
            {:else}<div class="row between">
                <div>
                  <strong>{passkey.friendly_name}</strong>{#if passkey.created_at}<p class="help">
                      Added {new Date(passkey.created_at).toLocaleDateString()}
                    </p>{/if}
                </div>
                <div class="row">
                  <button
                    class="text-button"
                    disabled={!unlocked || busy}
                    aria-label={`Rename ${passkey.friendly_name}`}
                    onclick={() => {
                      editing = passkey.id;
                      name = passkey.friendly_name;
                    }}>Rename</button
                  ><button
                    class="text-button"
                    disabled={!unlocked || busy || passkeys.length < 2}
                    aria-label={`Remove ${passkey.friendly_name}`}
                    onclick={() => (removing = passkey.id)}>Remove</button
                  >
                </div>
              </div>{/if}
          </li>{/each}
      </ul>
      {#if !passkeys.length}<p class="empty">
          Add your first passkey to protect your account and unlock security settings.
        </p>{/if}
      <a class="button secondary full" href={authPage('enroll')}>Add a passkey</a>
      <p class="help">Your last passkey cannot be removed.</p>
    </section>
    <section class="card" aria-labelledby="social-heading">
      <h2 id="social-heading">Social sign-in</h2>
      <p class="help">
        Linked providers can sign you in. Only a passkey can authorize changes to these settings.
      </p>
      <ul class="list">
        {#each config?.providers ?? [] as provider (provider)}{@const identity = identities.find(
            (value) => value.provider === provider
          )}
          <li>
            <div class="row between">
              <div>
                <strong>{providerName(provider)}</strong>
                <p class="help">
                  {identity ? (identity.linked_email ?? 'Linked to your account') : 'Not linked'}
                </p>
              </div>
              {#if identity}<button
                  class="secondary"
                  disabled={!unlocked || busy}
                  onclick={() => (removing = provider)}>Unlink</button
                >{:else}<button
                  class="secondary"
                  disabled={!unlocked || busy}
                  onclick={() => link(provider)}>Link {providerName(provider)}</button
                >{/if}
            </div>
            {#if removing === provider}<div class="notice stack">
                <p>Remove {providerName(provider)} sign-in? Your passkeys will still work.</p>
                <div class="row actions">
                  <button
                    class="danger"
                    disabled={busy || !unlocked}
                    onclick={() => unlink(provider)}>Confirm unlink</button
                  ><button class="secondary" onclick={() => (removing = null)}>Cancel</button>
                </div>
              </div>{/if}
          </li>{/each}
      </ul>
      {#if !config?.providers.length}<p class="empty">Social sign-in is not available yet.</p>{/if}
    </section>
  {/if}
</section>
