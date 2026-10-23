<script lang="ts">
  import { onMount } from 'svelte';
  import { errorMessage } from '@piquel/auth-sdk';
  import { Account } from '$lib/account.svelte';
  import { Clients, type Client } from '$lib/clients.svelte';
  const clients = new Clients(Account.current().api);
  let list = $state<Client[]>([]);
  let loading = $state(true);
  let error = $state('');
  onMount(() => {
    void load();
  });
  async function load() {
    try {
      list = await clients.list();
    } catch (cause) {
      error = errorMessage(cause);
    } finally {
      loading = false;
    }
  }
  /** Whether it works, and when a token was last issued to it, as one line. */
  function status(client: Client): string {
    const state = client.suspended_at
      ? 'Suspended by an administrator'
      : client.enabled
        ? 'Enabled'
        : 'Disabled';
    const used = client.last_used_at
      ? `last used ${new Date(client.last_used_at).toLocaleDateString(undefined, { dateStyle: 'medium' })}`
      : 'never used';
    return `${Clients.kindName(client.kind)} · ${state} · ${used}`;
  }
</script>

<svelte:head
  ><title>Developers · Piquel</title><meta
    name="description"
    content="Register the apps that sign users in with Piquel."
  /></svelte:head
>
{#if error}<p class="notice error" role="alert">{error}</p>{/if}
{#if loading}<p role="status">Loading your apps…</p>
{:else}
  <section class="card" aria-labelledby="clients-heading">
    <div class="row between">
      <h2 id="clients-heading">Your apps</h2>
      <span class="badge">{list.length} of {Clients.limit}</span>
    </div>
    <ul class="list">
      {#each list as client (client.id)}<li>
          <a href={`/developers/clients/${client.id}`}><strong>{client.display_name}</strong></a>
          <p class="help"><code>{client.id}</code></p>
          <p class="help">{status(client)}</p>
        </li>{/each}
    </ul>
    {#if !list.length}<p class="empty">
        You have no apps yet. Register one to get its client ID.
      </p>{/if}
    {#if list.length < Clients.limit}<a class="button full" href="/developers/new">New app</a
      >{:else}<p class="help">Delete an app to register another.</p>{/if}
  </section>
  <section class="card stack" aria-labelledby="docs-heading">
    <h2 id="docs-heading">How it works</h2>
    <p>
      Piquel is a standard OpenID Connect provider. Each app gets a client ID, and apps with a
      backend a secret. Use the Rust SDK, or any OpenID Connect library with the settings on your
      app's page.
    </p>
    <ul>
      <li>
        <a href="https://github.com/piquel-fr/piquel-fr/tree/main/crates/auth-sdk"
          >Rust SDK (<code>piquel-auth</code>)</a
        >
      </li>
      <li>
        <a
          href="https://github.com/piquel-fr/piquel-fr/blob/main/docs/guides/step-up-authentication.md"
          >Asking for a passkey before sensitive actions (step-up)</a
        >
      </li>
    </ul>
  </section>
{/if}
