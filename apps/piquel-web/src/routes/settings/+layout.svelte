<script lang="ts">
  import { page } from '$app/state';
  import SignedIn from '$lib/SignedIn.svelte';
  import type { LayoutProps } from './$types';
  let { children }: LayoutProps = $props();
  // Every settings page, in navigation order.
  const sections = [
    { href: '/settings', label: 'Sign-in methods' },
    { href: '/settings/sessions', label: 'Devices' },
    { href: '/settings/history', label: 'Security history' }
  ];
</script>

<section class="settings">
  <div class="settings-header">
    <p class="eyebrow">Your account</p>
    <h1>Security, made personal.</h1>
    <p>Manage how you sign in to Piquel and keep your account in your hands.</p>
  </div>
  <SignedIn
    heading="Sign in to see your settings"
    prompt="Use your Piquel account to manage your passkeys, devices and linked providers."
  >
    <nav class="tabs" aria-label="Account settings">
      {#each sections as section (section.href)}<a
          href={section.href}
          aria-current={page.url.pathname === section.href ? 'page' : undefined}>{section.label}</a
        >{/each}
    </nav>
    {@render children()}
  </SignedIn>
</section>
