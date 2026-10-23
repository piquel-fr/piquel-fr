<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { resolve } from '$app/paths';
  import { Passkeys, StepUp, errorMessage } from '@piquel/auth-sdk';
  import { Account } from '$lib/account.svelte';
  import ClientForm from '$lib/ClientForm.svelte';
  import SecretPanel from '$lib/SecretPanel.svelte';
  import { ClientDraft, Clients, type ClientKind, type ClientSettings } from '$lib/clients.svelte';
  /** What registering sends, and what a step-up saves until it resumes. */
  type Registration = { kind: ClientKind; settings: ClientSettings };
  const account = Account.current();
  const clients = new Clients(account.api);
  let draft = $state(new ClientDraft(Clients.defaults()));
  // A confidential client's secret, kept only in this page, which leaves once the
  // user saved it.
  let created = $state<{ id: string; secret: string } | null>(null);
  let error = $state('');
  // Registering needs a recent passkey confirmation. Without one, auth confirms it
  // and sends the user back here, where the registration resumes.
  const stepUp = new StepUp(new Passkeys(account.api), () => account.session?.user.id, {
    create: async (argument) => {
      const { kind, settings } = JSON.parse(argument) as Registration;
      // Back from a confirmation, the form shows what is being registered again.
      draft = new ClientDraft(settings, kind);
      const client = await clients.create(kind, settings);
      if (client.client_secret) created = { id: client.id, secret: client.client_secret };
      else await goto(resolve('/developers/clients/[id]', { id: client.id }));
    }
  });
  onMount(() => {
    stepUp.resume().catch((cause: unknown) => {
      if (!draft.reject(cause)) error = errorMessage(cause);
    });
  });
  function register(): Promise<void> {
    const registration: Registration = { kind: draft.kind, settings: draft.settings() };
    return stepUp.run('create', JSON.stringify(registration));
  }
</script>

<svelte:head><title>New app · Piquel</title></svelte:head>
<p><a href="/developers">← Your apps</a></p>
{#if created}{@const id = created.id}<SecretPanel
    secret={created.secret}
    saved={() => void goto(resolve('/developers/clients/[id]', { id }))}
  />
{:else}
  <h2>Register an app</h2>
  {#if error}<p class="notice error" role="alert">{error}</p>{/if}
  <ClientForm {draft} askKind action="Register app" submit={register} />
{/if}
