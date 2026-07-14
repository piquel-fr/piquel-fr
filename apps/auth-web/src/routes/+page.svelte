<script lang="ts">
  let submitting = $state(false);
  function beginPasskey() { submitting = true; window.location.assign('/webauthn/authenticate/start'); }
</script>

<h1>Sign in to Piquel</h1>
<p>Use a passkey or one of the approved identity providers.</p>
<button type="button" onclick={beginPasskey} disabled={submitting}>{submitting ? 'Starting passkey…' : 'Sign in with a passkey'}</button>
<p><a href="/login/github" rel="nofollow">Sign in with GitHub</a></p>
<p><a href="/login/google" rel="nofollow">Sign in with Google</a></p>
<p class="help">Connecting a product-owned GitHub integration is different from signing in with GitHub.</p>
<style>.help { color: #555; font-size: .9rem; }</style>
