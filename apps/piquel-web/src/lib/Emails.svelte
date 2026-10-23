<script lang="ts">
  import { onMount } from 'svelte';
  import { Passkeys, StepUp, errorMessage } from '@piquel/auth-sdk';
  import { Account, Task, type Email } from '$lib/account.svelte';

  const account = Account.current();
  const task = new Task();
  let emails = $state<Email[]>([]);
  let loading = $state(true);
  let address = $state('');
  let notice = $state('');
  // The address whose removal confirmation is open.
  let removing = $state<string | null>(null);
  // Adding, changing the primary address and removing one need a recent passkey
  // confirmation: the addresses receive security notices.
  const stepUp = new StepUp(new Passkeys(account.api), () => account.session?.user.id, {
    add: async (email) => {
      const added = await account.addEmail(email);
      address = '';
      notice = `We sent a link to ${added.address}. Open it to confirm the address.`;
      emails = await account.emails();
    },
    primary: async (id) => {
      await account.makePrimaryEmail(id);
      notice = 'Your primary address changed. We told your previous one.';
      emails = await account.emails();
    },
    remove: async (id) => {
      await account.removeEmail(id);
      removing = null;
      notice = 'The address was removed.';
      emails = emails.filter((email) => email.id !== id);
    }
  });
  // Another verified address must become primary before the primary one can go.
  const replaceable = (email: Email) =>
    email.primary && emails.some((other) => other.id !== email.id && other.verified);
  onMount(() => {
    void load();
  });
  async function load() {
    try {
      emails = await account.emails();
      await stepUp.resume();
    } catch (cause) {
      task.error = errorMessage(cause);
    } finally {
      loading = false;
    }
  }
  async function add(event: SubmitEvent) {
    event.preventDefault();
    notice = '';
    await task.run(() => stepUp.run('add', address.trim()));
  }
</script>

<svelte:head
  ><title>Email addresses · Piquel</title><meta
    name="description"
    content="Manage the email addresses of your Piquel account."
  /></svelte:head
>
<p class="help">
  Piquel sends security notices to your primary address, and apps you sign in to receive it. Every
  address is verified before it is used.
</p>
{#if task.error}<p class="notice error" role="alert">{task.error}</p>{/if}
{#if notice}<p class="notice" role="status">{notice}</p>{/if}
{#if loading}<p role="status">Loading your addresses…</p>
{:else}
  <section class="card" aria-labelledby="emails-heading">
    <div class="row between">
      <h2 id="emails-heading">Your addresses</h2>
      <span class="badge">{emails.length} added</span>
    </div>
    <ul class="list">
      {#each emails as email (email.id)}<li>
          <div class="row between">
            <div>
              <strong>{email.address}</strong>
              <p class="help">
                {email.primary
                  ? 'Primary: receives security notices'
                  : email.verified
                    ? 'Verified'
                    : 'Waiting for confirmation: open the link we sent'}
              </p>
            </div>
            <div class="row">
              {#if email.verified && !email.primary}<button
                  class="text-button"
                  disabled={task.busy}
                  onclick={() => task.run(() => stepUp.run('primary', email.id))}
                  >Make primary</button
                >{/if}
              {#if !email.verified}<button
                  class="text-button"
                  disabled={task.busy}
                  onclick={() => {
                    notice = '';
                    void task.run(() => stepUp.run('add', email.address));
                  }}>Resend link</button
                >{/if}
              <button
                class="text-button"
                disabled={task.busy || replaceable(email)}
                title={replaceable(email)
                  ? 'Make another address primary before removing this one.'
                  : undefined}
                aria-label={`Remove ${email.address}`}
                onclick={() => (removing = email.id)}>Remove</button
              >
            </div>
          </div>
          {#if removing === email.id}<div class="notice stack">
              <p>
                Remove {email.address}?{email.primary
                  ? ' Piquel will no longer be able to email you security notices.'
                  : ''}
              </p>
              <div class="row actions">
                <button
                  class="danger"
                  disabled={task.busy}
                  onclick={() => task.run(() => stepUp.run('remove', email.id))}
                  >Confirm removal</button
                ><button class="secondary" onclick={() => (removing = null)}>Cancel</button>
              </div>
            </div>{/if}
        </li>{/each}
    </ul>
    {#if !emails.length}<p class="empty">
        Add an address so Piquel can tell you about changes to your account.
      </p>{/if}
    {#if account.config?.email_enabled}<form class="stack" onsubmit={add}>
        <label
          >Add an address<input
            type="email"
            bind:value={address}
            autocomplete="email"
            maxlength="254"
            required
          /></label
        >
        <button class="secondary full" disabled={task.busy}>Send a confirmation link</button>
      </form>
    {:else}<p class="help">
        Piquel cannot send email right now, so addresses cannot be added.
      </p>{/if}
  </section>
{/if}
