<script lang="ts">
  /** Why auth or the form rejects a setting; its input names `id` in `aria-describedby`. */
  let { id, message }: { id: string; message: string | undefined } = $props();
</script>

{#if message}<p class="field-error" {id}>{message}</p>{/if}
