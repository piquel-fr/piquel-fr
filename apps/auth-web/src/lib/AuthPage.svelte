<script lang="ts">
  import { onMount } from 'svelte';
  import {
    AuthApi,
    Passkeys,
    StepUp,
    errorMessage,
    passkeysAvailable,
    providerName,
    safeDestination,
    type Configuration,
    type PasskeyKind,
    type Provider,
    type Session
  } from '@piquel/auth-sdk';
  let { mode = 'login' }: { mode?: 'login' | 'register' | 'confirm' | 'enroll' | 'link' } =
    $props();
  const api = new AuthApi();
  const passkeys = new Passkeys(api);
  let config = $state<Configuration | null>(null);
  let session = $state<Session | null>(null);
  // `link` comes from an email match; `explicit_link` from settings, bound to that session.
  let pending = $state<{
    id: string;
    kind: 'signup' | 'link' | 'explicit_link';
    provider: Provider;
    display_name: string;
    email: string | null;
    return_to: string;
  } | null>(null);
  let username = $state('');
  let friendlyName = $state('My passkey');
  let invitation = $state('');
  let transaction = $state('');
  let returnTo = $state('');
  let busy = $state(false);
  let error = $state('');
  let ready = $state(false);
  let fallback = $state(false);
  let available = $state(false);
  let android = $state(false);
  let passkeyKind = $state<PasskeyKind>('standard');
  const registration = $derived(mode === 'register' || pending?.kind === 'signup');
  const linking = $derived(pending?.kind === 'link' || pending?.kind === 'explicit_link');
  // Pages that act on the signed-in account rather than sign someone in.
  const security = $derived(mode === 'confirm' || mode === 'enroll');
  const title = $derived(
    linking
      ? 'Add this sign-in method?'
      : registration
        ? 'Your account starts here.'
        : mode === 'enroll'
          ? 'Add a passkey.'
          : mode === 'confirm'
            ? 'Confirm it’s you.'
            : 'Welcome back.'
  );
  onMount(async () => {
    available = passkeysAvailable();
    android = /Android/i.test(navigator.userAgent);
    const query = new URLSearchParams(window.location.search);
    if (query.get('error') === 'social_cancelled')
      error = 'Social sign-in was cancelled. You can try again or use a passkey.';
    if (query.get('error') === 'social_failed')
      error = 'Social sign-in could not be verified. Please try again or use a passkey.';
    transaction = query.get('transaction') ?? '';
    invitation =
      query.get('invitation') ??
      query.get('invite') ??
      sessionStorage.getItem('piquel.invitation') ??
      '';
    returnTo = query.get('return_to') ?? '';
    try {
      config = await api.request<Configuration>('/config');
      if (query.has('social') || mode === 'link')
        pending = await api.request('/login/social/pending');
      if (security || linking) session = await api.request<Session>('/session').catch(() => null);
      ready = true;
    } catch (cause) {
      error = errorMessage(cause);
    }
  });
  function destination() {
    if (transaction)
      return `/oauth/authorize/resume?transaction=${encodeURIComponent(transaction)}`;
    if (!config) throw new Error('Sign-in options are still loading. Please try again.');
    return safeDestination(pending?.return_to ?? returnTo, config);
  }
  async function run(action: () => Promise<void>) {
    if (busy) return;
    busy = true;
    error = '';
    try {
      await action();
    } catch (cause) {
      error = errorMessage(cause);
    } finally {
      busy = false;
    }
  }
  // On this origin, actions needing a recent passkey confirmation confirm inline.
  const stepUp = new StepUp(passkeys, () => session?.user.id, {
    enroll: () => passkeys.register(friendlyName.trim(), undefined, passkeyKind),
    link: () => api.request('/login/social/link', 'POST', {})
  });
  // Signs in when this browser has no session. A passkey sign-in also confirms the
  // session, so the action after it prompts no more.
  async function signIn() {
    if (session) return;
    await passkeys.authenticate(username.trim() || undefined);
    session = await api.request<Session>('/session');
  }
  async function submit() {
    await run(async () => {
      // Resolve the destination first, so nothing can fail after authentication commits.
      const target = destination();
      if (registration) {
        await passkeys.register(
          friendlyName.trim(),
          {
            username: username.trim(),
            ...(invitation ? { invitation } : {}),
            // Only the social signup page joins its pending identity, never plain registration.
            ...(pending?.kind === 'signup' ? { pending_signup: pending.id } : {})
          },
          passkeyKind
        );
        sessionStorage.removeItem('piquel.invitation');
      } else if (linking || mode === 'enroll') {
        await signIn();
        await stepUp.run(linking ? 'link' : 'enroll');
      } else if (mode === 'confirm' && session) {
        await passkeys.confirm();
      } else {
        await passkeys.authenticate(username.trim() || undefined);
      }
      window.location.assign(target);
    });
  }
  async function social(provider: Provider) {
    await run(async () => {
      if (invitation) sessionStorage.setItem('piquel.invitation', invitation);
      const result = await api.request<{ redirect_url: string }>(
        `/login/${provider}/start`,
        'POST',
        { return_to: destination(), mode: 'login', ...(invitation ? { invitation } : {}) }
      );
      window.location.assign(result.redirect_url);
    });
  }
  // Both keep the stored continuation: explicit links return to it (settings), while
  // email-match links offer sign-in again before continuing.
  async function cancelLink() {
    await run(async () => {
      const target = destination();
      await api.request('/login/social/cancel', 'POST', {});
      window.location.assign(
        pending?.kind === 'explicit_link'
          ? target
          : `/login?${new URLSearchParams({ return_to: target })}`
      );
    });
  }
  async function switchAccount() {
    await run(async () => {
      await api.request('/session/logout', 'POST', {});
      session = null;
      username = '';
      fallback = false;
    });
  }
</script>

<svelte:head
  ><title
    >{linking
      ? 'Link social sign-in'
      : registration
        ? 'Create your account'
        : security
          ? 'Verify your passkey'
          : 'Sign in'} · Piquel</title
  ></svelte:head
>
<section class="auth-shell">
  <p class="eyebrow">
    {security
      ? 'Account security'
      : linking
        ? 'Social sign-in'
        : registration
          ? 'One account. Your services.'
          : 'Your Piquel account'}
  </p>
  <h1>{title}</h1>
  {#if linking && pending}
    {#if pending.kind === 'explicit_link'}<p>
        Verify your passkey to add {providerName(pending.provider)} sign-in to your account.
      </p>
    {:else}<p>
        {providerName(pending.provider)} uses an email associated with an existing account. Verify that
        account with its passkey to add this provider.
      </p>{/if}
    {#if pending.email}<p class="notice">{pending.email}</p>{/if}
    {#if session}<p class="help">Signed in as @{session.user.username}.</p>{/if}
  {:else if registration}
    <p>
      Create a passkey with your device or password manager. You’ll use it to sign in and protect
      your account settings.
    </p>
    {#if pending}<p class="notice">
        Finish creating your account to add {providerName(pending.provider)} sign-in.
      </p>{/if}
  {:else if mode === 'confirm'}
    <p>Verify your passkey to continue with your change.</p>
  {:else if mode === 'enroll'}
    <p>
      Save another passkey with your device or password manager. You may need to verify an existing
      passkey first.
    </p>
  {:else}<p>Sign in with a passkey, or use a linked social account.</p>{/if}
  {#if error}<p class="notice error" role="alert">{error}</p>{/if}
  {#if !ready && !error}<p role="status">Loading your sign-in options…</p>{/if}
  {#if ready && config}
    <div class="stack">
      {#if available}
        <form
          onsubmit={(event) => {
            event.preventDefault();
            void submit();
          }}
        >
          {#if registration || fallback}
            <label
              >Username<input
                bind:value={username}
                autocomplete="username webauthn"
                autocapitalize="none"
                spellcheck="false"
                pattern={'[a-z0-9_\\-]{3,32}'}
                minlength="3"
                maxlength="32"
                required={registration || fallback}
              /></label
            >
            {#if registration}<small
                >3–32 lowercase letters, numbers, underscores, or hyphens.</small
              >{/if}
          {/if}
          {#if registration || mode === 'enroll'}<label
              >Passkey name<input
                bind:value={friendlyName}
                maxlength="80"
                required
                autocomplete="off"
              /></label
            >{/if}
          {#if android && (registration || mode === 'enroll')}
            <label
              >Save this passkey with
              <select bind:value={passkeyKind}>
                <option value="standard">Passkey or security key</option>
                <option value="google_password_manager"
                  >Google Password Manager on this device</option
                >
              </select>
            </label>
            <p class="help">
              Choose Google Password Manager only if it is available on this Android device.
            </p>
          {/if}
          {#if registration && config.invite_required}<label
              >Invitation<input bind:value={invitation} required autocomplete="off" /></label
            >{/if}
          <button disabled={busy} class="full"
            >{busy
              ? 'Waiting for your passkey…'
              : linking
                ? 'Verify passkey and add provider'
                : registration
                  ? 'Create account with a passkey'
                  : mode === 'enroll'
                    ? 'Add passkey'
                    : mode === 'confirm'
                      ? 'Verify with a passkey'
                      : 'Sign in with a passkey'}</button
          >
        </form>
        {#if !registration && !fallback && !session}<button
            class="text-button"
            disabled={busy}
            onclick={() => (fallback = true)}>Use a username instead</button
          >{/if}
      {:else}<p class="notice">
          Passkeys need a supported browser and a secure connection. Open this page in Safari,
          Chrome, or another browser with passkey support.
        </p>{/if}
      {#if !registration && !security && !linking}
        {#if config.providers.length}<div class="divider">or continue with</div>{/if}
        {#each config.providers as provider (provider)}<button
            class="secondary full"
            disabled={busy}
            onclick={() => social(provider)}>{providerName(provider)}</button
          >{/each}
      {/if}
      {#if linking}
        <!-- Explicit links are bound to this session; signing out would strand them. -->
        {#if session && pending?.kind === 'link'}<button
            class="secondary"
            disabled={busy}
            onclick={switchAccount}>Use a different account</button
          >{/if}
        <button class="text-button" disabled={busy} onclick={cancelLink}>Cancel linking</button>
      {/if}
    </div>
    <footer>
      {#if security}<a href={safeDestination(returnTo, config)}>Go back</a>
      {:else if registration}<p class="help">
          Already have an account? <a
            href={`/login?${new URLSearchParams({ ...(transaction ? { transaction } : {}), ...(returnTo ? { return_to: returnTo } : {}) })}`}
            >Sign in</a
          >
        </p>
      {:else if !linking}<p class="help">
          New to Piquel? <a
            href={`/register?${new URLSearchParams({ ...(invitation ? { invitation } : {}), ...(transaction ? { transaction } : {}), ...(returnTo ? { return_to: returnTo } : {}) })}`}
            >Create an account</a
          >
        </p>{/if}
      <p class="help">Your passkey stays with your device or password manager.</p>
    </footer>
  {/if}
</section>

<style>
  select {
    font: inherit;
    width: 100%;
    min-height: 46px;
    border: 1px solid #a9b8aa;
    border-radius: 8px;
    padding: 0.7rem 0.8rem;
    background: #fff;
    color: inherit;
  }
  select:focus-visible {
    outline: 3px solid #ab7900;
    outline-offset: 4px;
  }
</style>
