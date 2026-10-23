import { getContext, setContext } from 'svelte';
import {
  ApiError,
  AuthApi,
  errorMessage,
  type Configuration,
  type Provider,
  type Session
} from '@piquel/auth-sdk';

/** An active passkey of the account. */
export type Passkey = {
  id: string;
  friendly_name: string;
  created_at?: string;
  last_used_at?: string | null;
};
/** A social identity linked to the account. */
export type Identity = { provider: Provider; linked_email: string | null };
/** The coarse browser and platform auth records for a request. */
export type Device = { browser: string; platform: string };
/** An email address of the account. Only a verified one can be primary. */
export type Email = { id: string; address: string; verified: boolean; primary: boolean };
/** Every record of the account, as auth exports it; only what the page reads is typed. */
export type AccountExport = {
  format: 'piquel.account-export';
  version: number;
  exported_at: string;
  profile: { username: string };
};

const browsers: Record<string, string> = {
  chrome: 'Chrome',
  edge: 'Edge',
  firefox: 'Firefox',
  opera: 'Opera',
  safari: 'Safari'
};
const platforms: Record<string, string> = {
  android: 'Android',
  chrome_os: 'ChromeOS',
  ios: 'iOS',
  linux: 'Linux',
  macos: 'macOS',
  windows: 'Windows'
};
const key = Symbol('account');

/**
 * The account settings API on the auth origin, and the signed-in account. The
 * settings layout loads it and shares it with its pages through `provide`.
 */
export class Account {
  readonly api: AuthApi;
  config = $state<Configuration | null>(null);
  session = $state<Session | null>(null);
  loading = $state(true);
  /** When the account will be purged, once this browser scheduled its deletion. */
  purgeAfter = $state<string | null>(null);
  constructor(readonly authOrigin: string) {
    this.api = new AuthApi(authOrigin);
  }
  /** Shares `account` with the components below the caller. */
  static provide(account: Account): Account {
    return setContext(key, account);
  }
  /** The account the settings layout provides. */
  static current(): Account {
    return getContext<Account>(key);
  }
  /** Names a device, such as “Firefox on Linux”, or `null` when it was not recorded. */
  static deviceName(device: Device | null): string | null {
    if (!device) return null;
    const browser = browsers[device.browser] ?? 'Another browser or app';
    const platform = platforms[device.platform];
    return platform ? `${browser} on ${platform}` : browser;
  }
  /** Loads the public configuration, then the signed-in user, if any. */
  async load(): Promise<void> {
    try {
      this.config = await this.api.request('/config');
      // Auth answers 401 when this browser has no session; that is not a failure.
      this.session = await this.api.request<Session>('/session').catch((cause: unknown) => {
        if (cause instanceof ApiError && cause.status === 401) return null;
        throw cause;
      });
    } finally {
      this.loading = false;
    }
  }
  /** A page of the auth frontend, such as `login`, that returns to `returnTo` when done. */
  page(name: string, returnTo: string): string {
    return `${this.authOrigin}/${name}?return_to=${encodeURIComponent(returnTo)}`;
  }
  /** Ends this browser's session. */
  async logout(): Promise<void> {
    await this.api.request('/session/logout', 'POST', {});
    this.session = null;
  }
  passkeys(): Promise<Passkey[]> {
    return this.api.request('/account/passkeys');
  }
  identities(): Promise<Identity[]> {
    return this.api.request('/account/social-identities');
  }
  /** Primary first. */
  emails(): Promise<Email[]> {
    return this.api.request('/account/emails');
  }
  /** Like `emails`, but empty if auth cannot list them, such as an older release
   * without the endpoint, for pages that only mention addresses. */
  emailsOrNone(): Promise<Email[]> {
    return this.emails().catch(() => []);
  }
  /** Sends a verification link. Needs a recent passkey confirmation; run it through `StepUp`. */
  addEmail(email: string): Promise<Email> {
    return this.api.request('/account/emails', 'POST', { email });
  }
  /** Needs a recent passkey confirmation; run it through `StepUp`. */
  makePrimaryEmail(id: string): Promise<void> {
    return this.api.request(`/account/emails/${id}/primary`, 'POST', {});
  }
  /** Needs a recent passkey confirmation; run it through `StepUp`. */
  removeEmail(id: string): Promise<void> {
    return this.api.request(`/account/emails/${id}`, 'DELETE');
  }
  /** Needs a recent passkey confirmation; run it through `StepUp`. */
  removePasskey(id: string): Promise<void> {
    return this.api.request(`/account/passkeys/${id}`, 'DELETE');
  }
  /** Needs a recent passkey confirmation; run it through `StepUp`. */
  unlinkIdentity(provider: string): Promise<void> {
    return this.api.request(`/account/social-identities/${provider}`, 'DELETE');
  }
  /** Needs a recent passkey confirmation; run it through `StepUp`. */
  exportData(): Promise<AccountExport> {
    return this.api.request('/account/export');
  }
  /**
   * Schedules the account's deletion, confirmed by its `username`, and signs every
   * browser out. Needs a recent passkey confirmation; run it through `StepUp`.
   */
  async deleteAccount(username: string): Promise<void> {
    const scheduled = await this.api.request<{ purge_after: string }>('/account/deletion', 'POST', {
      confirm_username: username
    });
    this.purgeAfter = scheduled.purge_after;
    this.session = null;
  }
}

/** Runs the page's user actions one at a time and keeps the last failure to show. */
export class Task {
  busy = $state(false);
  error = $state('');
  async run(action: () => Promise<void>): Promise<void> {
    this.busy = true;
    this.error = '';
    try {
      await action();
    } catch (cause) {
      this.error = errorMessage(cause);
    } finally {
      this.busy = false;
    }
  }
}
