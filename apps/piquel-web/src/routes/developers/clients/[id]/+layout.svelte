<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { errorMessage } from '@piquel/auth-sdk';
  import { Account } from '$lib/account.svelte';
  import { Clients, ManagedClient } from '$lib/clients.svelte';
  import type { LayoutProps } from './$types';
  let { children }: LayoutProps = $props();
  // Another client's pages are reached through the list, outside this layout, so the
  // ID stays the same while it lives.
  const managed = ManagedClient.provide(
    new ManagedClient(Account.current().api, page.params.id ?? '')
  );
  let error = $state('');
  const base = `/developers/clients/${encodeURIComponent(managed.id)}`;
  // The client's pages, in navigation order; public clients have no secrets.
  const sections = $derived([
    { href: base, label: 'Overview' },
    { href: `${base}/settings`, label: 'Settings' },
    ...(managed.client?.kind === 'confidential'
      ? [{ href: `${base}/secrets`, label: 'Secrets' }]
      : [])
  ]);
  onMount(() => {
    managed.load().catch((cause: unknown) => (error = errorMessage(cause)));
  });
</script>

<p><a href="/developers">← Your apps</a></p>
{#if error}<p class="notice error" role="alert">{error}</p>
{:else if !managed.client}<p role="status">Loading your app…</p>
{:else}
  <div class="row">
    <h2>{managed.client.display_name}</h2>
    <span class="badge">{Clients.kindName(managed.client.kind)}</span>
    {#if managed.client.suspended_at}<span class="badge warning">Suspended</span>
    {:else if !managed.client.enabled}<span class="badge warning">Disabled</span>{/if}
  </div>
  <nav class="tabs" aria-label="App">
    {#each sections as section (section.href)}<a
        href={section.href}
        aria-current={page.url.pathname === section.href ? 'page' : undefined}>{section.label}</a
      >{/each}
  </nav>
  {@render children()}
{/if}
