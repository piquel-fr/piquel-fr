<script lang="ts">
  import { Task } from '$lib/account.svelte';
  import FieldError from '$lib/FieldError.svelte';
  import { Clients, type ClientDraft, type ClientField } from '$lib/clients.svelte';
  /**
   * Edits `draft`, asking for its kind when `askKind`, and runs `submit` once the
   * cheap checks pass. Auth's rejection of a setting is shown beside its input.
   */
  let {
    draft,
    askKind = false,
    action,
    submit
  }: {
    draft: ClientDraft;
    askKind?: boolean;
    action: string;
    submit: () => Promise<void>;
  } = $props();
  const task = new Task();
  const described = (field: ClientField) => (draft.errors[field] ? `${field}-error` : undefined);
  function onsubmit(event: SubmitEvent) {
    event.preventDefault();
    if (!draft.check()) return;
    void task.run(async () => {
      try {
        await submit();
      } catch (cause) {
        if (!draft.reject(cause)) throw cause;
      }
    });
  }
</script>

<form class="card" {onsubmit} novalidate>
  {#if task.error}<p class="notice error" role="alert">{task.error}</p>{/if}
  <label
    >App name<input
      bind:value={draft.name}
      maxlength="80"
      required
      aria-invalid={Boolean(draft.errors.display_name)}
      aria-describedby={described('display_name')}
    /><small>Users see it when they sign in to your app.</small></label
  >
  <FieldError id="display_name-error" message={draft.errors.display_name} />
  {#if askKind}<fieldset>
      <legend>Does your app have a backend that can keep a secret?</legend>
      <label class="choice"
        ><input type="radio" bind:group={draft.kind} value="confidential" />
        <span
          >Yes, a web app with a backend<small
            >Its server signs users in with a client secret.</small
          ></span
        ></label
      >
      <label class="choice"
        ><input type="radio" bind:group={draft.kind} value="public" />
        <span
          >No, it runs in the browser or on a device<small
            >Single-page, mobile and desktop apps, which cannot hide a secret.</small
          ></span
        ></label
      >
      <small>Both sign in with PKCE (S256). The type cannot change later.</small>
    </fieldset>{/if}
  <label
    >Redirect URIs<textarea
      bind:value={draft.redirects}
      rows="3"
      placeholder="https://app.example/auth/callback"
      aria-invalid={Boolean(draft.errors.redirect_uris)}
      aria-describedby={described('redirect_uris')}></textarea><small
      >One per line, matched exactly: where Piquel sends users back after signing in. HTTPS, or HTTP
      on a loopback IP for native apps.</small
    ></label
  >
  <FieldError id="redirect_uris-error" message={draft.errors.redirect_uris} />
  <label
    >Post-logout URIs<textarea
      bind:value={draft.logouts}
      rows="2"
      placeholder="https://app.example/"
      aria-invalid={Boolean(draft.errors.post_logout_uris)}
      aria-describedby={described('post_logout_uris')}></textarea><small
      >Optional, one per line: pages users may return to after signing out.</small
    ></label
  >
  <FieldError id="post_logout_uris-error" message={draft.errors.post_logout_uris} />
  <fieldset aria-describedby={described('allowed_scopes')}>
    <legend>Scopes</legend>
    {#each Clients.scopes as scope (scope.name)}<label class="choice"
        ><input type="checkbox" bind:group={draft.scopes} value={scope.name} />
        <span><code>{scope.name}</code><small>{scope.description}</small></span></label
      >{/each}
  </fieldset>
  <FieldError id="allowed_scopes-error" message={draft.errors.allowed_scopes} />
  <label class="choice"
    ><input type="checkbox" bind:checked={draft.refresh} />
    <span
      >Allow refresh tokens<small
        >When your app requests <code>offline_access</code>, it can stay signed in without sending
        users back to Piquel.</small
      ></span
    ></label
  >
  <label class="choice"
    ><input type="checkbox" bind:checked={draft.pushed} />
    <span
      >Require pushed authorization requests<small
        >Your app must post its sign-in requests to <code>/oauth/par</code> (RFC 9126), so none of their
        parameters travel through the browser.</small
      ></span
    ></label
  >
  <button disabled={task.busy}>{action}</button>
</form>
