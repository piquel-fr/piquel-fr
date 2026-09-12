<script lang="ts">
  import "@piquel/browser/style.css";
  let { children } = $props();
</script>
<svelte:head><meta name="robots" content="noindex" /></svelte:head>
<div class="shell"><header><a class="brand" href="/" aria-label="Piquel home"><span class="mark" aria-hidden="true">p</span>piquel<span class="muted"> / account</span></a></header><main>{@render children()}</main></div>
