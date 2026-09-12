<script lang="ts">
  import { onMount } from 'svelte';
  import { AuthApi, errorMessage } from '@piquel/browser';
  const api = new AuthApi();
  let transaction = $state('');
  let details = $state<{ client_name: string; scopes: string[]; audience: string } | null>(null);
  let error = $state('');
  let busy = $state(false);
  onMount(async () => {
    transaction = new URLSearchParams(window.location.search).get('transaction') ?? '';
    if (!transaction) { error = 'This authorization request is missing. Start again from the application.'; return; }
    try { details = await api.request(`/oauth/authorize/transaction/${encodeURIComponent(transaction)}`); }
    catch (cause) { error = errorMessage(cause); }
  });
  async function decide(decision: 'approve' | 'deny') {
    busy = true; error = '';
    try { const result = await api.form('/oauth/authorize/decision', new URLSearchParams({ transaction, decision })); window.location.assign(result.redirect_url); }
    catch (cause) { error = errorMessage(cause); busy = false; }
  }
</script>
<svelte:head><title>Authorize application · Piquel</title></svelte:head>
<section class="auth-shell stack">
  <div><p class="eyebrow">Application access</p><h1>Continue to {details?.client_name ?? 'your application'}.</h1><p>Review what this application will receive from your Piquel account.</p></div>
  {#if error}<p class="notice error" role="alert">{error}</p><a href={`/login?transaction=${encodeURIComponent(transaction)}`}>Sign in again</a>
  {:else if !details}<p role="status">Loading application details…</p>
  {:else}<div class="card"><h2>{details.client_name}</h2><ul>{#each details.scopes as scope}<li>{scope === 'openid' ? 'Your account identifier' : scope === 'profile' ? 'Your username and display name' : scope === 'email' ? 'Your verified email address' : scope === 'offline_access' ? 'Stay signed in' : scope}</li>{/each}</ul></div><button disabled={busy} onclick={() => decide('approve')}>Continue</button><button class="secondary" disabled={busy} onclick={() => decide('deny')}>Cancel</button>{/if}
</section>
