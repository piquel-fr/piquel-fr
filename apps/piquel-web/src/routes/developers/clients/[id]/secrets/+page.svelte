<script lang="ts">
  import { onMount } from 'svelte';
  import { Passkeys, StepUp } from '@piquel/auth-sdk';
  import { Account, Task } from '$lib/account.svelte';
  import SecretPanel from '$lib/SecretPanel.svelte';
  import { ManagedClient, type ClientSecret } from '$lib/clients.svelte';
  const account = Account.current();
  const managed = ManagedClient.current();
  const task = new Task();
  // How long earlier secrets keep working after a rotation, as auth reads it.
  const graces = [
    { value: '0', label: 'Stop them now' },
    { value: '1h', label: 'For an hour' },
    { value: '24h', label: 'For a day' },
    { value: '7d', label: 'For a week' },
    { value: '30d', label: 'For 30 days' }
  ];
  let grace = $state('24h');
  // The new secret, kept only here until the user saved it.
  let secret = $state<string | null>(null);
  // Rotating needs a recent passkey confirmation. Without one, auth confirms it and
  // sends the user back here, where the rotation resumes.
  const stepUp = new StepUp(new Passkeys(account.api), () => account.session?.user.id, {
    rotate: async (argument) => {
      secret = await managed.rotate(argument);
    }
  });
  onMount(() => {
    void task.run(() => stepUp.resume());
  });
  const date = (value: string) =>
    new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  function lifetime(value: ClientSecret): string {
    if (!value.expires_at) return 'Works until you rotate it';
    return Date.parse(value.expires_at) > Date.now()
      ? `Stops working ${date(value.expires_at)}`
      : `Stopped working ${date(value.expires_at)}`;
  }
</script>

<svelte:head><title>Secrets · {managed.client?.display_name} · Piquel</title></svelte:head>
{#if task.error}<p class="notice error" role="alert">{task.error}</p>{/if}
{#if secret}<SecretPanel {secret} saved={() => (secret = null)} />{/if}
<section class="card" aria-labelledby="secrets-heading">
  <h2 id="secrets-heading">Client secrets</h2>
  <p class="help">
    Your server sends one with HTTP Basic authentication. Piquel shows a secret only when it creates
    it.
  </p>
  <ul class="list">
    {#each managed.client?.secrets ?? [] as value (value.id)}<li>
        <strong>Created {date(value.created_at)}</strong>
        <p class="help">{lifetime(value)}</p>
      </li>{/each}
  </ul>
</section>
<form
  class="card"
  onsubmit={(event) => {
    event.preventDefault();
    void task.run(() => stepUp.run('rotate', grace));
  }}
>
  <h2>Rotate the secret</h2>
  <p class="help">
    Get a new secret, and give your app time to switch to it: the earlier ones keep working for the
    period you choose.
  </p>
  <label
    >Earlier secrets keep working<select bind:value={grace}
      >{#each graces as option (option.value)}<option value={option.value}>{option.label}</option
        >{/each}</select
    ></label
  >
  <button disabled={task.busy}>Rotate secret</button>
</form>
