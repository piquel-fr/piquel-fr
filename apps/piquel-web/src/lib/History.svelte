<script lang="ts">
  import { onMount } from 'svelte';
  import { Passkeys, StepUp, errorMessage, providerName, type Provider } from '@piquel/auth-sdk';
  import {
    Account,
    Task,
    type Device,
    type Email,
    type Identity,
    type Passkey
  } from '$lib/account.svelte';

  type Method = 'passkey' | 'federation';
  /** An entry of `GET /account/history`, newest first. */
  type Entry = {
    id: string;
    occurred_at: string;
    /** Who acted. Only entries the account caused can be reported. */
    actor: 'account' | 'admin' | 'operator' | 'client' | 'system' | 'anonymous' | 'unrecorded';
    /** Why an administrator or operator made the change, as they wrote it. */
    reason: string | null;
    client: { id: string; name: string | null } | null;
    ip: string | null;
    device: Device | null;
    /** Retention deleted the IP address and device. */
    erased: boolean;
  } & (
    | { kind: 'account.created' | 'session.signed_in'; method: Method }
    | { kind: 'session.revoked'; reason: { type: string } }
    | {
        kind: 'passkey.added' | 'passkey.renamed' | 'passkey.removed' | 'account.recovered';
        passkey_id: string;
      }
    | { kind: 'identity.linked' | 'identity.unlinked'; provider: Provider }
    | { kind: 'email.added'; email_id: string; address: string | null }
    | { kind: 'email.verified' | 'email.primary_changed' | 'email.removed'; email_id: string }
    | { kind: 'consent.granted'; scopes: string[] }
    | { kind: 'compromise.reported'; event_id: string }
    | { kind: 'legacy'; action: string; outcome: string }
    | {
        kind:
          | 'session.signed_out'
          | 'token.reused'
          | 'account.disabled'
          | 'account.enabled'
          | 'account.viewed'
          | 'account.handle_changed'
          | 'account.recovery_started'
          | 'account.recovery_undone'
          | 'administrator.granted'
          | 'administrator.revoked';
      }
  );
  type HistoryPage = { entries: Entry[]; next: string | null };
  /** What undoes a reported entry; it needs a recent passkey confirmation. */
  type FollowUp =
    | { action: 'remove_passkey'; passkey_id: string }
    | { action: 'unlink_identity'; provider: Provider }
    | { action: 'remove_email'; email_id: string };

  const actors: Record<Entry['actor'], string | null> = {
    account: null,
    admin: 'By a Piquel administrator',
    operator: 'By a Piquel operator',
    client: 'By an app',
    system: 'Automatically by Piquel',
    anonymous: null,
    unrecorded: null
  };
  const revocations: Record<string, string> = {
    credential_removed: 'Signed out after a passkey was removed',
    identity_unlinked: 'Signed out after a social sign-in was unlinked',
    admin: 'Signed out by an administrator',
    account_disabled: 'Signed out because the account was disabled',
    account_deletion: 'Signed out because the account is being deleted',
    compromise_reported: 'Signed out after you reported activity',
    user_revoked: 'Signed out from your devices list'
  };
  // Rows recorded before typed history, by their logged action.
  const legacy: Record<string, string> = {
    'account.create': 'Account created',
    'passkey.login': 'Signed in with a passkey',
    'passkey.add': 'Passkey added',
    'passkey.rename': 'Passkey renamed',
    'passkey.remove': 'Passkey removed',
    'settings.unlock': 'Settings unlocked',
    'federation.login': 'Signed in with a social provider',
    'federation.link': 'Social sign-in linked',
    'federation.unlink': 'Social sign-in unlinked',
    'refresh.replay': 'An app’s sign-in was reused and revoked',
    'refresh.policy_rejected': 'An app’s access ended'
  };

  const account = Account.current();
  const task = new Task();
  let entries = $state<Entry[]>([]);
  let next = $state<string | null>(null);
  let passkeys = $state<Passkey[]>([]);
  let identities = $state<Identity[]>([]);
  let emails = $state<Email[]>([]);
  let loading = $state(true);
  // The entry whose report confirmation is open.
  let reporting = $state<string | null>(null);
  // Set once a report succeeds: what is left to undo, if anything.
  let reported = $state<{ followUp: FollowUp | null } | null>(null);
  let notice = $state('');
  const stepUp = new StepUp(new Passkeys(account.api), () => account.session?.user.id, {
    remove: async (id) => {
      await account.removePasskey(id);
      notice = 'The passkey was removed.';
      await refresh();
    },
    unlink: async (provider) => {
      await account.unlinkIdentity(provider);
      notice = `${providerName(provider as Provider)} sign-in was unlinked.`;
      await refresh();
    },
    removeEmail: async (id) => {
      await account.removeEmail(id);
      notice = 'The email address was removed.';
      await refresh();
    }
  });
  // Entries grouped by the day they happened, in the reader's time zone.
  const days = $derived.by(() => {
    const groups: { day: string; entries: Entry[] }[] = [];
    for (const entry of entries) {
      const day = new Date(entry.occurred_at).toLocaleDateString(undefined, { dateStyle: 'full' });
      let group = groups.at(-1);
      if (group?.day !== day) {
        group = { day, entries: [] };
        groups.push(group);
      }
      group.entries.push(entry);
    }
    return groups;
  });
  // The follow-up of the last report, while there is still something to undo.
  const pending = $derived.by(() => {
    const followUp = reported?.followUp;
    if (followUp?.action === 'remove_passkey') {
      const passkey = passkeys.find((key) => key.id === followUp.passkey_id);
      return passkey && { followUp, label: `Remove passkey “${passkey.friendly_name}”` };
    }
    if (followUp?.action === 'unlink_identity') {
      const linked = identities.some((identity) => identity.provider === followUp.provider);
      return linked && { followUp, label: `Unlink ${providerName(followUp.provider)} sign-in` };
    }
    if (followUp?.action === 'remove_email') {
      const email = emails.find((value) => value.id === followUp.email_id);
      return email && { followUp, label: `Remove ${email.address}` };
    }
    return null;
  });
  onMount(() => {
    void load();
  });
  async function load() {
    try {
      await refresh();
      await stepUp.resume();
    } catch (cause) {
      task.error = errorMessage(cause);
    } finally {
      loading = false;
    }
  }
  /** Reloads the newest page and the account's credentials. */
  async function refresh() {
    // Credentials too: a report's follow-up may name one added since the page loaded.
    let page: HistoryPage;
    [page, passkeys, identities, emails] = await Promise.all([
      account.api.request<HistoryPage>('/account/history'),
      account.passkeys(),
      account.identities(),
      account.emailsOrNone()
    ]);
    ({ entries, next } = page);
  }
  async function older() {
    await task.run(async () => {
      if (!next) return;
      const older = await account.api.request<HistoryPage>(
        `/account/history?before=${encodeURIComponent(next)}`
      );
      entries = [...entries, ...older.entries];
      next = older.next;
    });
  }
  async function report(entry: Entry) {
    await task.run(async () => {
      const result = await account.api.request<{ follow_up: FollowUp | null }>(
        `/account/history/${entry.id}/report`,
        'POST',
        {}
      );
      reporting = null;
      notice = '';
      reported = { followUp: result.follow_up };
      await refresh();
    });
  }
  async function undo(followUp: FollowUp) {
    await task.run(() => {
      switch (followUp.action) {
        case 'remove_passkey':
          return stepUp.run('remove', followUp.passkey_id);
        case 'unlink_identity':
          return stepUp.run('unlink', followUp.provider);
        case 'remove_email':
          return stepUp.run('removeEmail', followUp.email_id);
      }
    });
  }
  function passkeyName(id: string) {
    const passkey = passkeys.find((key) => key.id === id);
    return passkey ? ` “${passkey.friendly_name}”` : '';
  }
  /** The address `id`, while it is still on the account, with a leading space. */
  function emailAddress(id: string) {
    const email = emails.find((value) => value.id === id);
    return email ? ` ${email.address}` : '';
  }
  function describe(entry: Entry): string {
    switch (entry.kind) {
      case 'account.created':
        return entry.method === 'passkey'
          ? 'Account created with a passkey'
          : 'Account created with social sign-in';
      case 'session.signed_in':
        return entry.method === 'passkey'
          ? 'Signed in with a passkey'
          : 'Signed in with a social provider';
      case 'session.signed_out':
        return 'Signed out';
      case 'session.revoked':
        return revocations[entry.reason.type] ?? 'Signed out';
      case 'passkey.added':
        return `Passkey${passkeyName(entry.passkey_id)} added`;
      case 'passkey.renamed':
        return `Passkey${passkeyName(entry.passkey_id)} renamed`;
      case 'passkey.removed':
        return 'Passkey removed';
      case 'identity.linked':
        return `${providerName(entry.provider)} sign-in linked`;
      case 'identity.unlinked':
        return `${providerName(entry.provider)} sign-in unlinked`;
      case 'email.added': {
        const address = entry.address ? ` ${entry.address}` : emailAddress(entry.email_id);
        return `Email address${address} added`;
      }
      case 'email.verified':
        return `Email address${emailAddress(entry.email_id)} confirmed`;
      case 'email.primary_changed':
        return `Primary email address changed${emailAddress(entry.email_id) ? ` to${emailAddress(entry.email_id)}` : ''}`;
      case 'email.removed':
        return 'Email address removed';
      case 'consent.granted':
        return `Access approved: ${entry.scopes.join(', ')}`;
      case 'token.reused':
        return 'An app’s sign-in was used twice, so its access was revoked';
      case 'account.disabled':
        return 'Account disabled';
      case 'account.enabled':
        return 'Account re-enabled';
      case 'account.viewed':
        return 'Account details viewed';
      case 'account.handle_changed':
        return 'Handle changed';
      case 'account.recovery_started':
        return 'Account recovery started';
      case 'account.recovered':
        return 'Account recovered with a new passkey';
      case 'account.recovery_undone':
        return 'Account recovery undone';
      case 'administrator.granted':
        return 'Administrator rights granted';
      case 'administrator.revoked':
        return 'Administrator rights removed';
      case 'compromise.reported':
        return 'You reported activity that wasn’t you';
      case 'legacy':
        return `${legacy[entry.action] ?? entry.action}${entry.outcome === 'success' ? '' : ' (failed)'}`;
    }
  }
  /** When, from where and through which app, as one line. */
  function details(entry: Entry): string {
    const time = new Date(entry.occurred_at).toLocaleTimeString(undefined, { timeStyle: 'short' });
    const app = entry.client && `App: ${entry.client.name ?? entry.client.id}`;
    const origin = entry.erased
      ? ['Device details erased']
      : [Account.deviceName(entry.device), entry.ip];
    return [time, ...origin, app].filter(Boolean).join(' · ');
  }
  // Reports and the sign-outs other changes cause are reported through those changes.
  const reportable = (entry: Entry) =>
    entry.actor === 'account' &&
    entry.kind !== 'compromise.reported' &&
    entry.kind !== 'session.revoked';
</script>

<svelte:head
  ><title>Security history · Piquel</title><meta
    name="description"
    content="Review the sign-ins and changes to your Piquel account."
  /></svelte:head
>
<p class="help">
  Every sign-in and change to your account. If something wasn’t you, say so: we’ll sign out every
  other device and help you undo it.
</p>
{#if task.error}<p class="notice error" role="alert">{task.error}</p>{/if}
{#if notice}<p class="notice" role="status">{notice}</p>{/if}
{#if loading}<p role="status">Loading your history…</p>
{:else}
  {#if reported}<div class="notice stack" role="status">
      <strong>Your account is secured.</strong>
      <p>
        Every other device was signed out, and every app must sign in again, including on this
        device.
      </p>
      {#if pending}<p>Undo the change, too:</p>
        <div class="row actions">
          <button class="danger" disabled={task.busy} onclick={() => undo(pending.followUp)}
            >{pending.label}</button
          >
        </div>{/if}
    </div>{/if}
  {#each days as group (group.day)}<section class="card" aria-label={group.day}>
      <h2>{group.day}</h2>
      <ul class="list">
        {#each group.entries as entry (entry.id)}<li>
            <div class="row between">
              <div>
                <strong>{describe(entry)}</strong>
                <p class="help">{details(entry)}</p>
                {#if actors[entry.actor]}<p class="help">
                    {actors[entry.actor]}{#if entry.reason}: “{entry.reason}”{/if}
                  </p>{/if}
              </div>
              {#if reportable(entry) && reporting !== entry.id}<button
                  class="text-button"
                  disabled={task.busy}
                  onclick={() => (reporting = entry.id)}>This wasn’t me</button
                >{/if}
            </div>
            {#if reporting === entry.id}<div class="notice stack">
                <strong>Secure your account?</strong>
                <p>
                  This signs out every device but this one, and every app you use with Piquel must
                  sign in again, including on this device. Your passkeys keep working.
                </p>
                {#if entry.kind === 'passkey.added' || entry.kind === 'identity.linked' || entry.kind === 'email.added'}<p
                  >
                    Afterwards, you can confirm with your passkey to undo this change.
                  </p>{/if}
                <div class="row actions">
                  <button class="danger" disabled={task.busy} onclick={() => report(entry)}
                    >Sign out everywhere else</button
                  ><button class="secondary" onclick={() => (reporting = null)}>Cancel</button>
                </div>
              </div>{/if}
          </li>{/each}
      </ul>
    </section>{/each}
  {#if !entries.length && !next}<p class="empty">Nothing has happened to your account yet.</p>{/if}
  {#if next}<button class="secondary full" disabled={task.busy} onclick={older}
      >Show older activity</button
    >{/if}
{/if}
