<script lang="ts">
  import { onMount } from 'svelte';
  type Transaction = { client_name: string; scopes: string[]; audience: string };
  let transaction = $state('');
  let details = $state<Transaction | null>(null);
  let error = $state('');

  onMount(async () => {
    transaction = new URLSearchParams(window.location.search).get('transaction') ?? '';
    if (!transaction) { error = 'This authorization request is missing or expired.'; return; }
    try {
      const response = await fetch(`/oauth/authorize/transaction/${encodeURIComponent(transaction)}`, { credentials: 'same-origin' });
      if (response.status === 401) {
        window.location.assign(`/login?transaction=${encodeURIComponent(transaction)}`);
        return;
      }
      if (!response.ok) throw new Error();
      details = await response.json();
    } catch {
      error = 'This authorization request is invalid or has expired.';
    }
  });
</script>

<svelte:head><title>Authorize application · Piquel</title></svelte:head>
<section aria-labelledby="title">
  <p class="eyebrow">Authorization</p>
  <h1 id="title">Continue to {details?.client_name ?? 'the application'}</h1>
  {#if error}
    <div class="error" role="alert">{error}</div>
    <a href="/login">Return to sign in</a>
  {:else if !details}
    <p role="status">Loading the authorization request…</p>
  {:else}
    <div class="card">
      <p><strong>{details.client_name}</strong> is requesting access to <code>{details.audience}</code>.</p>
      <h2>Requested permissions</h2>
      <ul>{#each details.scopes as scope}<li><code>{scope}</code></li>{/each}</ul>
    </div>
    <form method="POST" action="/oauth/authorize/decision">
      <input type="hidden" name="transaction" value={transaction} />
      <button name="decision" value="approve">Continue</button>
      <button class="secondary" name="decision" value="deny">Cancel</button>
    </form>
  {/if}
</section>
