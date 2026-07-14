<script lang="ts">
  import { onMount } from 'svelte';
  import { authenticatePasskey, webauthnAvailable } from '$lib/webauthn';
  import { authorizationDestination, safeReturnTo } from '$lib/navigation';

  let username = $state('');
  let transaction = $state('');
  let returnTo = $state('');
  let submitting = $state(false);
  let error = $state('');

  onMount(() => {
    const query = new URLSearchParams(window.location.search);
    transaction = query.get('transaction') ?? '';
    const requested = query.get('return_to') ?? '';
    returnTo = safeReturnTo(requested);
  });

  function destination() {
    return authorizationDestination(transaction, returnTo);
  }

  function providerUrl(provider: 'github' | 'google') {
    return `/login/${provider}?return_to=${encodeURIComponent(destination())}`;
  }

  async function signIn() {
    if (submitting) return;
    submitting = true;
    error = '';
    try {
      await authenticatePasskey(username.trim());
      window.location.assign(destination());
    } catch {
      error = 'We could not sign you in. Check the username and try again.';
      submitting = false;
    }
  }
</script>

<svelte:head><title>Sign in · Piquel</title></svelte:head>
<section aria-labelledby="title">
  <p class="eyebrow">Piquel account</p>
  <h1 id="title">Sign in</h1>
  <p>Use your passkey, or continue with an approved identity provider.</p>
  {#if error}<div class="error" role="alert" tabindex="-1">{error}</div>{/if}
  {#if webauthnAvailable()}
    <form onsubmit={async (event) => { event.preventDefault(); await signIn(); }}>
      <label for="username">Username</label>
      <input id="username" bind:value={username} autocomplete="username webauthn" pattern={'[a-z0-9_]{3,32}'} required />
      <button disabled={submitting}>{submitting ? 'Waiting for your passkey…' : 'Sign in with a passkey'}</button>
    </form>
  {:else}
    <p role="status">Passkeys are unavailable in this browser or insecure context.</p>
  {/if}
  <div class="alternatives" aria-label="Social sign in">
    <a class="provider" href={providerUrl('github')}>Sign in with GitHub</a>
    <a class="provider" href={providerUrl('google')}>Sign in with Google</a>
  </div>
  <p class="help">Need a new account? <a href="/register">Create one with a passkey</a>.</p>
  <p class="help">“Sign in with GitHub” identifies you. Connecting a product-owned GitHub integration is a separate feature.</p>
</section>
