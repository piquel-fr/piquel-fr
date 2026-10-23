<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { errorMessage, type Session } from '@piquel/auth-sdk';
  import { Account, Task, type ConnectedApp } from '$lib/account.svelte';

  const account = new Account(page.data.authOrigin);
  const task = new Task();
  let session = $state<Session | null>(null);
  let apps = $state<ConnectedApp[]>([]);
  let loading = $state(true);
  // The app whose removal confirmation is open.
  let removing = $state<string | null>(null);
  let notice = $state('');
  onMount(() => {
    void load();
  });
  async function load() {
    try {
      session = await account.api.request('/session');
      apps = await account.apps();
    } catch (cause) {
      task.error = errorMessage(cause);
    } finally {
      loading = false;
    }
  }
  async function remove(app: ConnectedApp) {
    await task.run(async () => {
      await account.removeApp(app.client_id);
      apps = apps.filter((other) => other.client_id !== app.client_id);
      removing = null;
      notice = `${app.name} no longer has access to your account.`;
    });
  }
  const date = (value: string) =>
    new Date(value).toLocaleDateString(undefined, { dateStyle: 'medium' });
</script>

<svelte:head
  ><title>Connected apps · Piquel</title><meta
    name="description"
    content="See the apps you use with your Piquel account, and remove their access."
  /></svelte:head
>
<section class="settings">
  <div class="settings-header">
    <a href="/settings">← Account settings</a>
    <p class="eyebrow">Your account</p>
    <h1>Connected apps</h1>
    <p>The apps you sign in to with Piquel, and what they can see. Remove any you no longer use.</p>
  </div>
  {#if task.error}<p class="notice error" role="alert">{task.error}</p>{/if}
  {#if notice}<p class="notice" role="status">{notice}</p>{/if}
  {#if loading}<p role="status">Loading your apps…</p>
  {:else if !session}<div class="card stack">
      <h2>Sign in to see your apps</h2>
      <a class="button" href={account.page('login', window.location.href)}>Sign in</a>
    </div>
  {:else}
    {#each apps as app (app.client_id)}<section
        class="card stack"
        aria-labelledby={`app-${app.client_id}`}
      >
        <div class="row between">
          <h2 id={`app-${app.client_id}`}>{app.name}</h2>
          {#if app.first_party}<span class="badge">Made by Piquel</span>{/if}
        </div>
        <div>
          <strong>It can see</strong>
          <ul>
            {#each app.scopes as { scope, description } (scope)}<li>
                {description ?? scope}
              </li>{/each}
          </ul>
          <p class="help">
            {app.offline_access
              ? 'It can use your account while you are away.'
              : 'It can use your account only while you are signed in to it.'}
          </p>
        </div>
        <p class="help">
          Connected {date(app.granted_at)} · Last used {date(app.last_used_at)}
        </p>
        {#if removing === app.client_id}<div class="notice stack">
            <strong>Remove {app.name}’s access?</strong>
            <p>
              {app.first_party
                ? `Piquel makes ${app.name}, so signing in to it again gives it access without asking.`
                : `${app.name} will need your approval again to use your account.`}
              It may stay signed in for up to 5 minutes.
            </p>
            <div class="row actions">
              <button class="danger" disabled={task.busy} onclick={() => remove(app)}
                >Remove access</button
              ><button class="secondary" onclick={() => (removing = null)}>Cancel</button>
            </div>
          </div>
        {:else}<div class="row actions">
            <button
              class="secondary"
              disabled={task.busy}
              onclick={() => {
                notice = '';
                removing = app.client_id;
              }}>Remove access</button
            >
          </div>{/if}
      </section>{/each}
    {#if !apps.length}<p class="empty">No apps have access to your account.</p>{/if}
  {/if}
</section>
