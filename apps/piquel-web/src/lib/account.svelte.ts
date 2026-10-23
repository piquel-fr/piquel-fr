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
  /** Needs a recent passkey confirmation; run it through `StepUp`. */
  removePasskey(id: string): Promise<void> {
    return this.api.request(`/account/passkeys/${id}`, 'DELETE');
  }
  /** Needs a recent passkey confirmation; run it through `StepUp`. */
  unlinkIdentity(provider: string): Promise<void> {
    return this.api.request(`/account/social-identities/${provider}`, 'DELETE');
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
