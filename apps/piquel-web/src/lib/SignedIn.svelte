<script lang="ts">
  import { onMount, type Snippet } from 'svelte';
  import { page } from '$app/state';
  import { Account, Task } from '$lib/account.svelte';
  /**
   * Renders `children` for the signed-in account only, below a line naming it with a
   * sign-out button. It loads the account and shares it with `children` through
   * `Account.current()`. Signed-out visitors see `heading` and `prompt` with a sign-in
   * link that returns to this page.
   */
  let { heading, prompt, children }: { heading: string; prompt: string; children: Snippet } =
    $props();
  // Each environment has its own auth origin, which the server sets at runtime.
  const account = Account.provide(new Account(page.data.authOrigin));
  const task = new Task();
  onMount(() => {
    void task.run(() => account.load());
  });
</script>

{#if task.error}<p class="notice error" role="alert">{task.error}</p>{/if}
{#if account.loading}<p role="status">Loading your account…</p>
{:else if !account.config}<div class="card stack">
    <h2>This page is unavailable</h2>
    <p>Piquel's sign-in service could not be reached.</p>
    <button
      class="button"
      onclick={() => {
        window.location.reload();
      }}>Try again</button
    >
  </div>
{:else if !account.session}<div class="card stack">
    <h2>{heading}</h2>
    <p>{prompt}</p>
    <a class="button" href={account.page('login', window.location.href)}>Sign in</a>
  </div>
{:else}
  <div class="row between">
    <div>
      <strong>{account.session.user.display_name}</strong>
      <p class="help">@{account.session.user.username}</p>
    </div>
    <button
      class="text-button"
      disabled={task.busy}
      onclick={() => task.run(() => account.logout())}>Sign out</button
    >
  </div>
  {@render children()}
{/if}
