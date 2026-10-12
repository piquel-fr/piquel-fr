<script lang="ts">
  import '@piquel/auth-client/style.css';
  import type { LayoutProps } from './$types';
  let { children }: LayoutProps = $props();
</script>

<svelte:head><meta name="robots" content="noindex" /></svelte:head>
<div class="shell">
  <header>
    <a class="brand" href="/" aria-label="Piquel home"
      ><span class="mark" aria-hidden="true">p</span>piquel<span class="muted"> / sign in</span></a
    >
  </header>
  <main>{@render children()}</main>
</div>
