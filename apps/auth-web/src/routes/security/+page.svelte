<script lang="ts">
  import { onMount } from 'svelte';
  import { enrollPasskey, webauthnAvailable } from '$lib/webauthn';

  type Passkey = { id: string; friendly_name: string };
  type SocialIdentity = { provider: string; linked_email: string };
  let passkeys = $state<Passkey[]>([]);
  let identities = $state<SocialIdentity[]>([]);
  let signingOut = $state(false);
  let enrolling = $state(false);
  let error = $state('');
  let loading = $state(true);

  onMount(async () => {
    try {
      const [passkeyResponse, identityResponse] = await Promise.all([
        fetch('/account/passkeys', { credentials: 'same-origin' }),
        fetch('/account/social-identities', { credentials: 'same-origin' })
      ]);
      if (!passkeyResponse.ok || !identityResponse.ok) throw new Error();
      passkeys = await passkeyResponse.json();
      identities = await identityResponse.json();
    } catch {
      error = 'We could not load your security settings. Sign in again if your session expired.';
    } finally {
      loading = false;
    }
  });

  async function addPasskey() {
    const friendlyName = window.prompt('Name this passkey', 'This device')?.trim();
    if (!friendlyName) return;
    enrolling = true;
    error = '';
    try {
      await enrollPasskey(friendlyName);
      window.location.reload();
    } catch {
      error = 'Adding a passkey requires a sign-in from the last ten minutes.';
      enrolling = false;
    }
  }

  async function rename(passkey: Passkey) {
    const friendly_name = window.prompt('New passkey name', passkey.friendly_name)?.trim();
    if (!friendly_name) return;
    const response = await fetch(`/account/passkeys/${passkey.id}`, {
      method: 'PATCH', credentials: 'same-origin',
      headers: { 'content-type': 'application/json', 'x-piquel-csrf': '1' },
      body: JSON.stringify({ friendly_name })
    });
    if (response.ok) passkey.friendly_name = friendly_name;
    else error = 'Fresh sign-in is required to change this passkey.';
  }

  async function remove(passkey: Passkey) {
    if (!window.confirm(`Remove “${passkey.friendly_name}”? You cannot undo this.`)) return;
    const response = await fetch(`/account/passkeys/${passkey.id}`, {
      method: 'DELETE', credentials: 'same-origin', headers: { 'x-piquel-csrf': '1' }
    });
    if (response.ok) passkeys = passkeys.filter((value) => value.id !== passkey.id);
    else error = 'Keep at least one passkey and sign in again before removing one.';
  }

  async function logout() {
    signingOut = true;
    const response = await fetch('/session/logout', {
      method: 'POST', credentials: 'same-origin', headers: { 'x-piquel-csrf': '1' }
    });
    if (response.ok) window.location.assign('/login');
    else { error = 'We could not sign out. Please try again.'; signingOut = false; }
  }
</script>

<svelte:head><title>Account security · Piquel</title></svelte:head>
<section>
  <p class="eyebrow">Piquel account</p>
  <h1>Account security</h1>
  {#if error}<div class="error" role="alert">{error} <a href="/login?return_to=%2Fsecurity">Sign in again</a></div>{/if}
  <div class="card">
    <h2>Passkeys</h2>
    {#if loading}<p role="status">Loading passkeys…</p>
    {:else if passkeys.length}
      <ul>{#each passkeys as passkey}<li><span>{passkey.friendly_name}</span><span><button class="secondary compact" onclick={() => rename(passkey)}>Rename</button> <button class="danger compact" onclick={() => remove(passkey)}>Remove</button></span></li>{/each}</ul>
    {:else}<p>No passkeys were returned.</p>{/if}
    {#if webauthnAvailable()}<button class="provider" onclick={addPasskey} disabled={enrolling}>{enrolling ? 'Adding passkey…' : 'Add a passkey'}</button>{/if}
    <p class="help">Adding, renaming, or removing a passkey requires a sign-in from the last ten minutes.</p>
  </div>
  <div class="card">
    <h2>Social sign-in</h2>
    {#if loading}<p role="status">Loading social identities…</p>
    {:else if identities.length}<ul>{#each identities as identity}<li><span>Sign in with {identity.provider === 'github' ? 'GitHub' : 'Google'}</span><span>{identity.linked_email}</span></li>{/each}</ul>
    {:else}<p>No social identities are linked.</p>{/if}
  </div>
  <button class="secondary" onclick={logout} disabled={signingOut}>{signingOut ? 'Signing out…' : 'Sign out'}</button>
</section>
<style>ul{list-style:none;padding:0;display:grid;gap:.6rem}li{display:flex;align-items:center;justify-content:space-between;gap:1rem}.compact{min-height:2rem;padding:.45rem .7rem}.danger{background:#8b2929}</style>
