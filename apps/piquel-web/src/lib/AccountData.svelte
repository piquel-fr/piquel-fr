<script lang="ts">
  import { onMount } from 'svelte';
  import { Passkeys, StepUp } from '@piquel/auth-sdk';
  import { Account, Task } from '$lib/account.svelte';
  const account = Account.current();
  const task = new Task();
  // The danger zone's username confirmation, while open.
  let deleting = $state(false);
  let confirmation = $state('');
  // Downloading the account's data and deleting it need a recent passkey
  // confirmation. When the session has none, auth confirms it and sends the user
  // back to finish.
  const stepUp = new StepUp(new Passkeys(account.api), () => account.session?.user.id, {
    download: async () => {
      const data = await account.exportData();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = `piquel-account-${data.profile.username}-${data.exported_at.slice(0, 10)}.json`;
      link.click();
      setTimeout(() => {
        URL.revokeObjectURL(link.href);
      }, 0);
    },
    delete: async (username) => {
      await account.deleteAccount(username);
    }
  });
  const username = $derived(account.session?.user.username ?? '');
  onMount(() => {
    void task.run(() => stepUp.resume());
  });
</script>

{#if task.error}<p class="notice error" role="alert">{task.error}</p>{/if}
<section class="card" aria-labelledby="data-heading">
  <div class="row between">
    <div>
      <h2 id="data-heading">Your data</h2>
      <p class="help">
        Download everything Piquel keeps about your account: your profile, emails, passkeys,
        devices, connected apps and security history.
      </p>
    </div>
    <button
      class="secondary"
      disabled={task.busy}
      onclick={() => task.run(() => stepUp.run('download'))}>Download your data</button
    >
  </div>
</section>
<section class="card stack" aria-labelledby="delete-heading">
  <h2 id="delete-heading">Delete account</h2>
  <p class="help">
    Your account stops working at once and every device is signed out. It is deleted for good after
    30 days, with the apps you registered; until then, signing in with your passkey restores it.
    Apps you signed in to keep their own records of you.
  </p>
  {#if deleting}<form
      class="stack"
      onsubmit={(event) => {
        event.preventDefault();
        void task.run(() => stepUp.run('delete', confirmation.trim()));
      }}
    >
      <label
        ><span>Type your username, <strong>{username}</strong>, to confirm</span><input
          bind:value={confirmation}
          autocomplete="off"
          autocapitalize="none"
          spellcheck="false"
          required
        /></label
      >
      <div class="row actions">
        <button class="danger" disabled={task.busy || confirmation.trim() !== username}
          >Delete my account</button
        ><button
          class="secondary"
          type="button"
          onclick={() => {
            deleting = false;
            confirmation = '';
          }}>Cancel</button
        >
      </div>
    </form>
  {:else}<button class="danger" disabled={task.busy} onclick={() => (deleting = true)}
      >Delete account</button
    >{/if}
</section>
