<script lang="ts">
  import { AuthApi, errorMessage } from '@piquel/auth-sdk';
  let error = $state('');
  let busy = $state(false);
  async function logout() {
    busy = true;
    try {
      const response = await new AuthApi().form(
        '/oidc/logout',
        new URLSearchParams(window.location.search)
      );
      window.location.assign(response.redirect_url);
    } catch (cause) {
      error = errorMessage(cause);
      busy = false;
    }
  }
</script>

<svelte:head><title>Sign out · Piquel</title></svelte:head>
<section class="auth-shell stack">
  <div>
    <p class="eyebrow">Your Piquel account</p>
    <h1>Ready to sign out?</h1>
    <p>This will end your Piquel sign-in session in this browser.</p>
  </div>
  {#if error}<p class="notice error" role="alert">{error}</p>{/if}<button
    disabled={busy}
    onclick={logout}>Sign out</button
  ><a href="/login">Keep my session</a>
</section>
