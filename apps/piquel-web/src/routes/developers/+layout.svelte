<script lang="ts">
  import SignedIn from '$lib/SignedIn.svelte';
  import type { LayoutProps } from './$types';
  let { children }: LayoutProps = $props();
</script>

<section class="settings">
  <div class="settings-header">
    <p class="eyebrow">Developers</p>
    <h1>Sign users in with Piquel.</h1>
    <p>
      Register your apps as OpenID Connect clients, so their users sign in with their Piquel account
      and passkeys.
    </p>
  </div>
  <SignedIn
    heading="Sign in to manage your apps"
    prompt="Use your Piquel account to register and manage the apps that sign users in with it."
  >
    {@render children()}
  </SignedIn>
</section>
