<script lang="ts">
  import { authenticatePasskey, webauthnAvailable } from '$lib/webauthn';
  let accountId=$state('');let submitting=$state(false);let error=$state('');
  async function signIn(){if(submitting)return;submitting=true;error='';try{await authenticatePasskey(accountId.trim());window.location.assign('/security');}catch{error='We could not sign you in. Check the account and try again.';submitting=false;}}
</script>
<svelte:head><title>Sign in · Piquel</title></svelte:head>
<section aria-labelledby="title"><p class="eyebrow">Piquel account</p><h1 id="title">Sign in</h1><p>Use your passkey, or continue with an approved identity provider.</p>
{#if error}<div class="error" role="alert" tabindex="-1">{error}</div>{/if}
{#if webauthnAvailable()}<form onsubmit={async(event)=>{event.preventDefault();await signIn();}}><label for="account">Account ID</label><input id="account" bind:value={accountId} autocomplete="username" required /><button disabled={submitting}>{submitting?'Waiting for your passkey…':'Sign in with a passkey'}</button></form>{:else}<p role="status">Passkeys are unavailable in this browser or insecure context.</p>{/if}
<div class="alternatives" aria-label="Social sign in"><a class="provider" href="/login/github">Sign in with GitHub</a><a class="provider" href="/login/google">Sign in with Google</a></div><p class="help">Need a new account? <a href="/register">Create one with a passkey</a>.</p><p class="help">“Sign in with GitHub” identifies you. Connecting a product-owned GitHub integration is a separate feature.</p></section>
