<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { resolve } from '$app/paths';
  import { Passkeys, StepUp } from '@piquel/auth-sdk';
  import { Account, Task } from '$lib/account.svelte';
  import ClientForm from '$lib/ClientForm.svelte';
  import { ClientDraft, Clients, ManagedClient, type ClientSettings } from '$lib/clients.svelte';
  const account = Account.current();
  const managed = ManagedClient.current();
  const task = new Task();
  // The layout renders this page once the client is loaded.
  let draft = $state(new ClientDraft(managed.client ?? Clients.defaults(), managed.client?.kind));
  let notice = $state('');
  let deleting = $state(false);
  // Changing the URIs or deleting needs a recent passkey confirmation. Without one,
  // auth confirms it and sends the user back here, where the action resumes.
  const stepUp = new StepUp(new Passkeys(account.api), () => account.session?.user.id, {
    save: async (argument) => {
      const settings = JSON.parse(argument) as ClientSettings;
      draft = new ClientDraft(settings, managed.client?.kind);
      await managed.update(settings);
      notice = 'Your changes were saved.';
    },
    delete: async () => {
      await managed.delete();
      await goto(resolve('/developers'));
    }
  });
  onMount(() => {
    void task.run(async () => {
      try {
        await stepUp.resume();
      } catch (cause) {
        if (!draft.reject(cause)) throw cause;
      }
    });
  });
</script>

<svelte:head><title>Settings · {managed.client?.display_name} · Piquel</title></svelte:head>
{#if task.error}<p class="notice error" role="alert">{task.error}</p>{/if}
{#if notice}<p class="notice" role="status">{notice}</p>{/if}
<ClientForm
  {draft}
  action="Save changes"
  submit={() => {
    notice = '';
    return stepUp.run('save', JSON.stringify(draft.settings()));
  }}
/>
{#if managed.client}{@const client = managed.client}
  <section class="card stack" aria-labelledby="danger-heading">
    <h2 id="danger-heading">Danger zone</h2>
    <div class="row between">
      <div>
        <strong>{client.enabled ? 'Disable this app' : 'Enable this app'}</strong>
        <p class="help">
          {client.suspended_at
            ? 'An administrator suspended this app. Contact them to restore it.'
            : client.enabled
              ? 'It stops signing users in, exchanging codes and refreshing tokens until you enable it again.'
              : 'It can sign users in again.'}
        </p>
      </div>
      <button
        class="secondary"
        disabled={task.busy || Boolean(client.suspended_at)}
        onclick={() => task.run(() => managed.setEnabled(!client.enabled))}
        >{client.enabled ? 'Disable' : 'Enable'}</button
      >
    </div>
    {#if deleting}<div class="notice stack">
        <strong>Delete “{client.display_name}”?</strong>
        <p>
          It stops working at once: its refresh tokens are revoked, and its secrets and the consents
          users gave it are removed. This cannot be undone.
        </p>
        <div class="row actions">
          <button
            class="danger"
            disabled={task.busy}
            onclick={() => task.run(() => stepUp.run('delete'))}>Delete for good</button
          ><button class="secondary" onclick={() => (deleting = false)}>Cancel</button>
        </div>
      </div>
    {:else}<div class="row between">
        <div>
          <strong>Delete this app</strong>
          <p class="help">Its client ID is never used again.</p>
        </div>
        <button class="danger" disabled={task.busy} onclick={() => (deleting = true)}>Delete</button
        >
      </div>{/if}
  </section>
{/if}
