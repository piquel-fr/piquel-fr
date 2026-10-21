<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import {
    Passkeys,
    StepUp,
    errorMessage,
    providerName,
    type Configuration,
    type Provider,
    type Session
  } from '@piquel/auth-sdk';
  import { Account, Task, type Identity, type Passkey } from '$lib/account.svelte';
  // Each environment has its own auth origin, which the server sets at runtime.
  const account = new Account(page.data.authOrigin);
  const task = new Task();
  let config = $state<Configuration | null>(null);
  let session = $state<Session | null>(null);
  let passkeys = $state<Passkey[]>([]);
  let identities = $state<Identity[]>([]);
  let loading = $state(true);
  let editing = $state<string | null>(null);
  let name = $state('');
  let removing = $state<string | null>(null);
  // Removing a passkey or unlinking a provider needs a recent passkey confirmation.
  // When the session has none, auth confirms it and sends the user back to finish.
  const stepUp = new StepUp(new Passkeys(account.api), () => session?.user.id, {
    remove: async (id) => {
      await account.removePasskey(id);
      passkeys = passkeys.filter((key) => key.id !== id);
      removing = null;
    },
    unlink: async (provider) => {
      await account.unlinkIdentity(provider);
      identities = identities.filter((identity) => identity.provider !== provider);
      removing = null;
    }
  });
  const configured = (provider: Provider) => config?.providers.includes(provider) ?? false;
  // Identities of since-disabled providers stay listed so they can still be unlinked.
  const providers = $derived([
    ...(config?.providers ?? []),
    ...identities.map((identity) => identity.provider).filter((provider) => !configured(provider))
  ]);
  onMount(() => {
    void load();
  });
  async function load() {
    try {
      config = await account.api.request('/config');
      session = await account.api.request('/session');
      [passkeys, identities] = await Promise.all([account.passkeys(), account.identities()]);
      await stepUp.resume();
    } catch (cause) {
      task.error = errorMessage(cause);
    } finally {
      loading = false;
    }
  }
  function authPage(page: string) {
    return account.page(page, config?.settings_url ?? window.location.href);
  }
  async function rename(passkey: Passkey) {
    await task.run(async () => {
      await account.api.request(`/account/passkeys/${passkey.id}`, 'PATCH', {
        friendly_name: name.trim()
      });
      passkey.friendly_name = name.trim();
      editing = null;
    });
  }
  async function link(provider: Provider) {
    await task.run(async () => {
      if (!config) throw new Error('Account settings are still loading. Please try again.');
      const result = await account.api.request<{ redirect_url: string }>(
        `/login/${provider}/start`,
        'POST',
        { mode: 'link', return_to: config.settings_url }
      );
      window.location.assign(result.redirect_url);
    });
  }
  async function logout() {
    await task.run(async () => {
      await account.api.request('/session/logout', 'POST', {});
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
  {#if task.error}<p class="notice error" role="alert">{task.error}</p>{/if}
  {#if loading}<p role="status">Loading account settings…</p>
  {:else if !config}<div class="card stack">
      <h2>Account settings are unavailable</h2>
      <p>Piquel's sign-in service could not be reached.</p>
      <button
        class="button"
        onclick={() => {
          window.location.reload();
        }}>Try again</button
      >
    </div>
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
      <button class="text-button" disabled={task.busy} onclick={logout}>Sign out</button>
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
                  <button disabled={task.busy}>Save name</button><button
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
                    disabled={task.busy}
                    onclick={() => task.run(() => stepUp.run('remove', passkey.id))}
                    >Confirm removal</button
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
                    disabled={task.busy}
                    aria-label={`Rename ${passkey.friendly_name}`}
                    onclick={() => {
                      editing = passkey.id;
                      name = passkey.friendly_name;
                    }}>Rename</button
                  ><button
                    class="text-button"
                    disabled={task.busy || passkeys.length < 2}
                    aria-label={`Remove ${passkey.friendly_name}`}
                    onclick={() => (removing = passkey.id)}>Remove</button
                  >
                </div>
              </div>{/if}
          </li>{/each}
      </ul>
      {#if !passkeys.length}<p class="empty">
          Add your first passkey to protect your account.
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
        {#each providers as provider (provider)}{@const identity = identities.find(
            (value) => value.provider === provider
          )}
          <li>
            <div class="row between">
              <div>
                <strong>{providerName(provider)}</strong>
                <p class="help">
                  {identity ? (identity.linked_email ?? 'Linked to your account') : 'Not linked'}
                </p>
                {#if !configured(provider)}<p class="help">
                    {providerName(provider)} sign-in is currently unavailable.
                  </p>{/if}
              </div>
              {#if identity}<button
                  class="secondary"
                  disabled={task.busy}
                  onclick={() => (removing = provider)}>Unlink</button
                >{:else}<button
                  class="secondary"
                  disabled={task.busy}
                  onclick={() => link(provider)}>Link {providerName(provider)}</button
                >{/if}
            </div>
            {#if removing === provider}<div class="notice stack">
                <p>Remove {providerName(provider)} sign-in? Your passkeys will still work.</p>
                <div class="row actions">
                  <button
                    class="danger"
                    disabled={task.busy}
                    onclick={() => task.run(() => stepUp.run('unlink', provider))}
                    >Confirm unlink</button
                  ><button class="secondary" onclick={() => (removing = null)}>Cancel</button>
                </div>
              </div>{/if}
          </li>{/each}
      </ul>
      {#if !providers.length}<p class="empty">Social sign-in is not available yet.</p>{/if}
    </section>
    <section class="card" aria-labelledby="history-heading">
      <div class="row between">
        <div>
          <h2 id="history-heading">Security history</h2>
          <p class="help">
            See every sign-in and change to your account, and secure it if something wasn’t you.
          </p>
        </div>
        <a class="button secondary" href="/settings/history">View history</a>
      </div>
    </section>
  {/if}
</section>
