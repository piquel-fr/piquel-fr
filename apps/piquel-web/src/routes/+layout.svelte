<script lang="ts">
  import '@piquel/auth-sdk/style.css';
  import { page } from '$app/state';
  import type { LayoutProps } from './$types';
  let { children }: LayoutProps = $props();
  // The site's areas; each is current on its path and every path below it.
  const areas = [
    { href: '/settings', label: 'Account' },
    { href: '/developers', label: 'Developers' }
  ];
  const current = (href: string) =>
    page.url.pathname === href || page.url.pathname.startsWith(`${href}/`);
</script>

<svelte:head><meta name="robots" content="noindex" /></svelte:head>
<div class="shell">
  <header class="row between">
    <a class="brand" href="/" aria-label="Piquel home"
      ><span class="mark" aria-hidden="true">p</span>piquel</a
    >
    <nav class="site-nav" aria-label="Piquel">
      {#each areas as area (area.href)}<a
          href={area.href}
          aria-current={current(area.href) ? 'page' : undefined}>{area.label}</a
        >{/each}
    </nav>
  </header>
  <main>{@render children()}</main>
</div>
