<script lang="ts">
  import { onMount } from 'svelte';
  import { errorMessage } from '@piquel/auth-sdk';
  import { Account, Task, type Device } from '$lib/account.svelte';

  /** An entry of `GET /account/sessions`, most recently active first. */
  type SignedIn = {
    id: string;
    /** The session of this browser. */
    current: boolean;
    device: Device | null;
    ip: string | null;
    methods: ('passkey' | 'federation')[];
    authenticated_at: string;
    /** Refreshed at most every five minutes. */
    last_seen_at: string;
  };
  // Units from coarsest to finest, with their length in seconds.
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['day', 86_400],
    ['hour', 3_600],
    ['minute', 60]
  ];
  const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

  const account = Account.current();
  const task = new Task();
  let sessions = $state<SignedIn[]>([]);
  let loading = $state(true);
  let notice = $state('');
  const others = $derived(sessions.filter((session) => !session.current));
  onMount(() => {
    void load();
  });
  async function load() {
    try {
      sessions = await account.api.request('/account/sessions');
    } catch (cause) {
      task.error = errorMessage(cause);
    } finally {
      loading = false;
    }
  }
  async function signOut(session: SignedIn) {
    await task.run(async () => {
      await account.api.request(`/account/sessions/${session.id}`, 'DELETE');
      sessions = sessions.filter((value) => value.id !== session.id);
      notice = `${name(session)} was signed out.`;
    });
  }
  async function signOutOthers() {
    await task.run(async () => {
      const { revoked } = await account.api.request<{ revoked: number }>(
        '/account/sessions/revoke-others',
        'POST',
        {}
      );
      sessions = sessions.filter((session) => session.current);
      notice = `Signed out of ${String(revoked)} other ${revoked === 1 ? 'device' : 'devices'}.`;
    });
  }
  function name(session: SignedIn): string {
    return Account.deviceName(session.device) ?? 'An unrecorded device';
  }
  /** How it signed in, from where, and when it was last active, as one line. */
  function details(session: SignedIn): string {
    const methods = session.methods
      .map((method) => (method === 'passkey' ? 'Passkey' : 'Social sign-in'))
      .join(' and ');
    return [methods, session.ip, activity(session)].filter(Boolean).join(' · ');
  }
  function activity(session: SignedIn): string {
    const seconds = (Date.parse(session.last_seen_at) - Date.now()) / 1000;
    const unit = units.find(([, length]) => Math.abs(seconds) >= length);
    // Activity is recorded every five minutes at most, so anything closer is now.
    if (session.current || !unit || (unit[0] === 'minute' && seconds > -300)) return 'Active now';
    return `Active ${relative.format(Math.round(seconds / unit[1]), unit[0])}`;
  }
</script>

<svelte:head
  ><title>Devices · Piquel</title><meta
    name="description"
    content="See where your Piquel account is signed in, and sign out of other devices."
  /></svelte:head
>
<p class="help">
  Every browser signed in to your account. Signing one out also signs out the apps you use through
  it. Don’t recognize one? Sign it out, then review your security history.
</p>
{#if task.error}<p class="notice error" role="alert">{task.error}</p>{/if}
{#if notice}<p class="notice" role="status">{notice}</p>{/if}
{#if loading}<p role="status">Loading your devices…</p>
{:else}
  <section class="card" aria-labelledby="sessions-heading">
    <div class="row between">
      <h2 id="sessions-heading">Signed-in devices</h2>
      <span class="badge">{sessions.length} active</span>
    </div>
    <ul class="list">
      {#each sessions as session (session.id)}<li>
          <div class="row between">
            <div>
              <div class="row">
                <strong>{name(session)}</strong>
                {#if session.current}<span class="badge">This device</span>{/if}
              </div>
              <p class="help">{details(session)}</p>
              <p class="help">
                Signed in {new Date(session.authenticated_at).toLocaleDateString(undefined, {
                  dateStyle: 'medium'
                })}
              </p>
            </div>
            {#if !session.current}<button
                class="text-button"
                disabled={task.busy}
                aria-label={`Sign out ${name(session)}`}
                onclick={() => signOut(session)}>Sign out</button
              >{/if}
          </div>
        </li>{/each}
    </ul>
    {#if others.length}<button class="secondary full" disabled={task.busy} onclick={signOutOthers}
        >Sign out of all other devices</button
      >{:else}<p class="empty">You’re only signed in on this device.</p>{/if}
  </section>
{/if}
