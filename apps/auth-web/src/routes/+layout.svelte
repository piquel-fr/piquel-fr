<script lang="ts">
  import '@piquel/auth-sdk/style.css';
  import type { LayoutProps } from './$types';
  let { children }: LayoutProps = $props();
</script>

<svelte:head><meta name="robots" content="noindex" /></svelte:head>
<div class="shell">
  <header>
    <!-- auth-service answers / with its settings, not this app: rel="external" keeps
      prerendering off it. -->
    <a class="brand" href="/" rel="external" aria-label="Piquel home"
      ><span class="mark" aria-hidden="true">p</span>piquel<span class="muted"> / sign in</span></a
    >
  </header>
  <main>{@render children()}</main>
</div>
