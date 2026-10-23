<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { Account, Task } from '$lib/account.svelte';
  import type { LayoutProps } from './$types';
  let { children }: LayoutProps = $props();
  // Each environment has its own auth origin, which the server sets at runtime.
  const account = Account.provide(new Account(page.data.authOrigin));
  const task = new Task();
  // Every settings page, in navigation order.
  const sections = [
    { href: '/settings', label: 'Sign-in methods' },
    { href: '/settings/sessions', label: 'Devices' },
    { href: '/settings/history', label: 'Security history' }
  ];
  onMount(() => {
    void task.run(() => account.load());
  });
</script>

<section class="settings">
  <div class="settings-header">
    <p class="eyebrow">Your account</p>
    <h1>Security, made personal.</h1>
    <p>Manage how you sign in to Piquel and keep your account in your hands.</p>
  </div>
  {#if task.error}<p class="notice error" role="alert">{task.error}</p>{/if}
  {#if account.loading}<p role="status">Loading account settings…</p>
  {:else if !account.config}<div class="card stack">
      <h2>Account settings are unavailable</h2>
      <p>Piquel's sign-in service could not be reached.</p>
      <button
        class="button"
        onclick={() => {
          window.location.reload();
        }}>Try again</button
      >
    </div>
  {:else if !account.session}<div class="card stack">
      <h2>Sign in to see your settings</h2>
      <p>Use your Piquel account to manage your passkeys, devices and linked providers.</p>
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
    <nav class="tabs" aria-label="Account settings">
      {#each sections as section (section.href)}<a
          href={section.href}
          aria-current={page.url.pathname === section.href ? 'page' : undefined}>{section.label}</a
        >{/each}
    </nav>
    {@render children()}
  {/if}
</section>
