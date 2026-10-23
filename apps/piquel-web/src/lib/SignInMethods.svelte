<script lang="ts">
  import { onMount } from 'svelte';
  import {
    Handles,
    Passkeys,
    StepUp,
    errorMessage,
    providerName,
    type Provider
  } from '@piquel/auth-sdk';
  import { Account, Task, type Identity, type Passkey } from '$lib/account.svelte';
  const account = Account.current();
  const task = new Task();
  let passkeys = $state<Passkey[]>([]);
  let identities = $state<Identity[]>([]);
  let loading = $state(true);
  let editing = $state<string | null>(null);
  let name = $state('');
  let removing = $state<string | null>(null);
  const handles = new Handles(account.api);
  // The new handle while it is being edited, and why it cannot be taken.
  let handle = $state<string | null>(null);
  let handleRefusal = $state('');
  // Changing the handle, removing a passkey or unlinking a provider needs a recent
  // passkey confirmation. When the session has none, auth confirms it and sends the
  // user back to finish.
  const stepUp = new StepUp(new Passkeys(account.api), () => account.session?.user.id, {
    handle: async (value) => {
      const renamed = await handles.rename(value);
      if (account.session) account.session.user.handle = renamed.handle;
      handle = null;
    },
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
  const configured = (provider: Provider) => account.config?.providers.includes(provider) ?? false;
  // Identities of since-disabled providers stay listed so they can still be unlinked.
  const providers = $derived([
    ...(account.config?.providers ?? []),
    ...identities.map((identity) => identity.provider).filter((provider) => !configured(provider))
  ]);
  onMount(() => {
    void load();
  });
  async function load() {
    try {
      [passkeys, identities] = await Promise.all([account.passkeys(), account.identities()]);
      await stepUp.resume();
    } catch (cause) {
      task.error = errorMessage(cause);
    } finally {
      loading = false;
    }
  }
  // The current handle needs no check: renaming to it is refused anyway.
  $effect(() =>
    handles.watch(handle === account.session?.user.handle ? '' : (handle ?? ''), (refusal) => {
      handleRefusal = refusal;
    })
  );
  function authPage(page: string) {
    return account.page(page, account.config?.settings_url ?? window.location.href);
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
      if (!account.config) throw new Error('Account settings are still loading. Please try again.');
      const result = await account.api.request<{ redirect_url: string }>(
        `/login/${provider}/start`,
        'POST',
        { mode: 'link', return_to: account.config.settings_url }
      );
      window.location.assign(result.redirect_url);
    });
  }
</script>

<svelte:head
  ><title>Sign-in methods · Piquel</title><meta
    name="description"
    content="Manage the passkeys and social sign-in methods for your Piquel account."
  /></svelte:head
>
{#if task.error}<p class="notice error" role="alert">{task.error}</p>{/if}
{#if loading}<p role="status">Loading your sign-in methods…</p>
{:else}
  <section class="card" aria-labelledby="handle-heading">
    <h2 id="handle-heading">Handle</h2>
    <p class="help">
      Your public name on Piquel and the name you sign in with. Apps you use see it as your
      username.
    </p>
    {#if handle === null}<div class="row between">
        <strong>@{account.session?.user.handle}</strong>
        <button
          class="text-button"
          disabled={task.busy}
          onclick={() => (handle = account.session?.user.handle ?? '')}>Change</button
        >
      </div>
    {:else}<form
        onsubmit={(event) => {
          event.preventDefault();
          void task.run(() => stepUp.run('handle', handle?.trim() ?? ''));
        }}
      >
        <label
          >New handle<input
            bind:value={handle}
            autocapitalize="none"
            autocomplete="off"
            spellcheck="false"
            pattern="[A-Za-z0-9]+(-[A-Za-z0-9]+)*"
            minlength="3"
            maxlength="32"
            required
          /></label
        >
        <small>3–32 lowercase letters, numbers, or single hyphens between them.</small>
        {#if handleRefusal}<p class="notice error" role="status">{handleRefusal}</p>{/if}
        <div class="notice stack">
          <p>
            <strong>@{account.session?.user.handle} stops working right away.</strong> Links to it, and
            apps and services that look you up by it, stop finding you.
          </p>
          <p>
            Nobody else can ever take it; you can take it back later. You can change your handle
            once every 30 days.
          </p>
        </div>
        <div class="row actions">
          <button disabled={task.busy || !!handleRefusal}>Change handle</button><button
            class="secondary"
            type="button"
            onclick={() => (handle = null)}>Cancel</button
          >
        </div>
      </form>{/if}
  </section>
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
    {#if !passkeys.length}<p class="empty">Add your first passkey to protect your account.</p>{/if}
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
              >{:else}<button class="secondary" disabled={task.busy} onclick={() => link(provider)}
                >Link {providerName(provider)}</button
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
{/if}
