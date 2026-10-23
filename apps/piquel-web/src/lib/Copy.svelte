<script lang="ts">
  /** Copies `value` to the clipboard; `label` names it for screen readers. */
  let { value, label }: { value: string; label: string } = $props();
  let copied = $state(false);
  async function copy() {
    await navigator.clipboard.writeText(value);
    copied = true;
    setTimeout(() => (copied = false), 2000);
  }
</script>

<button class="text-button" type="button" aria-label={`Copy ${label}`} onclick={copy}
  >{copied ? 'Copied' : 'Copy'}</button
>
