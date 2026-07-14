<script lang="ts">let { children } = $props();</script>
<svelte:head><title>Piquel authentication</title><meta name="robots" content="noindex" /></svelte:head>
<main>{@render children()}</main>
<style>main { margin: auto; max-width: 34rem; padding: 2rem 1.25rem; font-family: system-ui, sans-serif; } :global(button), :global(a) { min-height: 2.75rem; } </style>
