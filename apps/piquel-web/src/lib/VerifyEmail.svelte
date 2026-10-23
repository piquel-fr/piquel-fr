<script lang="ts">
  import { onMount } from 'svelte';
  import { replaceState } from '$app/navigation';
  import { resolve } from '$app/paths';
  import { page } from '$app/state';
  import { Account, Task } from '$lib/account.svelte';

  // Outside the settings layout (`+page@`): whoever opens the link may be signed
  // out, or signed in to another account, which auth then refuses.
  // The link carries its token in the fragment, which never reaches a server, and
  // only the button below spends it: mail scanners open links, and must not verify.
  const account = new Account(page.data.authOrigin);
  const task = new Task();
  let token = $state<string | null>(null);
  let verified = $state<{ address: string; primary: boolean } | null>(null);
  // The fragment is read in the browser only; until then, nothing is said about it.
  let ready = $state(false);
  onMount(() => {
    token = new URLSearchParams(window.location.hash.slice(1)).get('token');
    ready = true;
  });
  async function confirm() {
    await task.run(async () => {
      if (!token) return;
      verified = await account.api.request('/account/emails/verify', 'POST', { token });
      token = null;
      // The spent token leaves the address bar and history, so a reload does not
      // offer to confirm again.
      replaceState(resolve('/settings/emails/verify'), {});
    });
  }
</script>

<svelte:head
  ><title>Confirm your email address · Piquel</title><meta
    name="description"
    content="Confirm an email address of your Piquel account."
  /></svelte:head
>
<section class="settings">
  <div class="settings-header">
    <p class="eyebrow">Your account</p>
    <h1>Confirm your email address</h1>
  </div>
  {#if task.error}<p class="notice error" role="alert">{task.error}</p>{/if}
  {#if verified}<div class="card stack">
      <h2>Address confirmed</h2>
      <p>
        {verified.address} is verified{verified.primary ? ' and is now your primary address' : ''}.
      </p>
      <a class="button" href="/settings/emails">Manage your addresses</a>
    </div>
  {:else if token}<div class="card stack">
      <p>
        Confirm only if you added this address to your own Piquel account: the email names the
        account it joins.
      </p>
      <button disabled={task.busy} onclick={confirm}>Confirm this address</button>
    </div>
  {:else if ready && !task.error}<div class="card stack">
      <h2>This link is incomplete</h2>
      <p>Open the link from the email again, or add the address again to get a new one.</p>
      <a class="button secondary" href="/settings/emails">Manage your addresses</a>
    </div>{/if}
</section>
