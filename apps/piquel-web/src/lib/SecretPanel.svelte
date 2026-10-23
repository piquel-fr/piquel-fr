<script lang="ts">
  import Copy from '$lib/Copy.svelte';
  /**
   * Shows a client secret auth returned, once: it lives only in the caller's state,
   * which `saved` should clear or leave, and is never stored or put in a URL.
   */
  let { secret, saved }: { secret: string; saved: () => void } = $props();
</script>

<section class="card stack" aria-labelledby="secret-heading">
  <h2 id="secret-heading">Your client secret</h2>
  <p class="notice error" role="alert">
    This is the only time this secret is shown. Store it in your app's secret manager or environment
    now; Piquel keeps only a digest of it.
  </p>
  <div class="row between code-line">
    <code>{secret}</code><Copy value={secret} label="client secret" />
  </div>
  <button onclick={saved}>I saved it</button>
</section>
