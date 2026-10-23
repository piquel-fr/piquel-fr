import { getContext, setContext } from 'svelte';
import { ApiError, type AuthApi } from '@piquel/auth-sdk';

/**
 * The OIDC clients an account manages, through auth's account API. Routes, limits
 * and error codes are in `docs/guides/client-management.md`; auth validates
 * everything, and the console repeats only the cheap checks.
 */

/** Public clients run where users can read their code; confidential ones on a server. */
export type ClientKind = 'public' | 'confidential';
/** The settings an owner chooses, as auth returns them. */
export type ClientSettings = {
  display_name: string;
  redirect_uris: string[];
  post_logout_uris: string[];
  allowed_scopes: string[];
  allow_refresh: boolean;
  require_pushed_authorization_requests: boolean;
};
/** A setting auth may reject, by the `field` its errors name. */
export type ClientField = keyof ClientSettings;
/** A message for each rejected setting. */
export type FieldErrors = Partial<Record<ClientField, string>>;
/** An entry of `GET /account/clients`. */
export type Client = ClientSettings & {
  id: string;
  kind: ClientKind;
  enabled: boolean;
  created_at: string;
  /** When a token was last issued to it, to within an hour. */
  last_used_at: string | null;
  /** An administrator suspended it: it stays disabled until they lift it. */
  suspended_at: string | null;
  /** Where auth posts logout tokens; only an operator sets it for now. */
  backchannel_logout_uri: string | null;
};
/** A secret of a confidential client, never its value. */
export type ClientSecret = { id: string; created_at: string; expires_at: string | null };

/** The account's clients: listing and registering them. */
export class Clients {
  /** The scopes an account's clients may request, with what each releases. */
  static readonly scopes = [
    { name: 'openid', description: 'Sign users in: their stable user ID' },
    { name: 'profile', description: 'Their handle and display name' },
    { name: 'email', description: 'Their email address, when they have one' },
    { name: 'offline_access', description: 'Refresh tokens, if refresh is allowed' }
  ] as const;
  /** How many clients an account may have at once, as auth enforces it. */
  static readonly limit = 10;
  constructor(readonly api: AuthApi) {}
  /** A new client's settings, as auth defaults them. */
  static defaults(): ClientSettings {
    return {
      display_name: '',
      redirect_uris: [],
      post_logout_uris: [],
      allowed_scopes: ['openid', 'profile', 'email'],
      allow_refresh: false,
      require_pushed_authorization_requests: false
    };
  }
  /** Describes a client's kind as the console asks about it. */
  static kindName(kind: ClientKind): string {
    return kind === 'confidential' ? 'Web app with a backend' : 'Browser or native app';
  }
  /**
   * Why auth would refuse `uri` as a redirect or post-logout URI, or `null` if this
   * cheap check passes: it must be HTTPS, or HTTP on a loopback IP.
   */
  static uriProblem(uri: string): string | null {
    const url = URL.parse(uri);
    if (!url) return `${uri} is not an absolute URL.`;
    const loopback = /^127\.\d+\.\d+\.\d+$/.test(url.hostname) || url.hostname === '[::1]';
    if (url.protocol === 'https:' || (url.protocol === 'http:' && loopback)) return null;
    return `${uri} must use https://, or http:// on a loopback IP such as http://127.0.0.1:8080/callback.`;
  }
  list(): Promise<Client[]> {
    return this.api.request('/account/clients');
  }
  /**
   * Registers a client, returning a confidential client's secret, shown only this
   * once. Needs a recent passkey confirmation; run it through `StepUp`.
   */
  create(
    kind: ClientKind,
    settings: ClientSettings
  ): Promise<Client & { client_secret: string | null }> {
    return this.api.request('/account/clients', 'POST', { kind, ...settings });
  }
}

/**
 * A client's settings as the client form edits them, with URIs one per line, and
 * what is wrong with each.
 */
export class ClientDraft {
  kind = $state<ClientKind>('confidential');
  name = $state('');
  redirects = $state('');
  logouts = $state('');
  scopes = $state<string[]>([]);
  refresh = $state(false);
  pushed = $state(false);
  errors = $state<FieldErrors>({});
  constructor(settings: ClientSettings, kind?: ClientKind) {
    if (kind) this.kind = kind;
    this.name = settings.display_name;
    this.redirects = settings.redirect_uris.join('\n');
    this.logouts = settings.post_logout_uris.join('\n');
    this.scopes = [...settings.allowed_scopes];
    this.refresh = settings.allow_refresh;
    this.pushed = settings.require_pushed_authorization_requests;
  }
  /** The settings to send, without blank lines or surrounding spaces. */
  settings(): ClientSettings {
    const lines = (text: string) =>
      text
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);
    return {
      display_name: this.name.trim(),
      redirect_uris: lines(this.redirects),
      post_logout_uris: lines(this.logouts),
      allowed_scopes: this.scopes,
      allow_refresh: this.refresh,
      require_pushed_authorization_requests: this.pushed
    };
  }
  /** Runs the cheap checks, keeping a message for each setting that fails them. */
  check(): boolean {
    const settings = this.settings();
    const uris = (list: string[]) =>
      list.map((uri) => Clients.uriProblem(uri)).find((problem) => problem !== null);
    this.errors = {
      redirect_uris: settings.redirect_uris.length
        ? uris(settings.redirect_uris)
        : 'Add at least one redirect URI.',
      post_logout_uris: uris(settings.post_logout_uris)
    };
    return !Object.values(this.errors).some(Boolean);
  }
  /** Shows auth's rejection of a setting beside it; false for any other failure. */
  reject(error: unknown): boolean {
    if (!(error instanceof ApiError) || !error.field) return false;
    const fields: string[] = Object.keys(this.settings());
    if (!fields.includes(error.field)) return false;
    // Auth prefixes its message with the field name, which the form shows already.
    const message = error.message.replace(`${error.field}: `, '');
    this.errors = { [error.field]: message };
    return true;
  }
}

const key = Symbol('client');

/**
 * One client of the account, which the client pages' layout loads and shares with
 * them through `provide`. Each change reloads it.
 */
export class ManagedClient {
  client = $state<(Client & { secrets: ClientSecret[] }) | null>(null);
  constructor(
    readonly api: AuthApi,
    readonly id: string
  ) {}
  /** Shares `client` with the components below the caller. */
  static provide(client: ManagedClient): ManagedClient {
    return setContext(key, client);
  }
  /** The client the client pages' layout provides. */
  static current(): ManagedClient {
    return getContext<ManagedClient>(key);
  }
  private get path(): string {
    return `/account/clients/${encodeURIComponent(this.id)}`;
  }
  async load(): Promise<void> {
    this.client = await this.api.request(this.path);
  }
  /** Changing the redirect or post-logout URIs needs a recent passkey confirmation. */
  async update(settings: ClientSettings): Promise<void> {
    await this.api.request(this.path, 'PATCH', settings);
    await this.load();
  }
  async setEnabled(enabled: boolean): Promise<void> {
    await this.api.request(`${this.path}/${enabled ? 'enable' : 'disable'}`, 'POST', {});
    await this.load();
  }
  /**
   * Gives the client a new secret, returned only here; earlier ones keep working for
   * `grace`, such as `24h`. Needs a recent passkey confirmation.
   */
  async rotate(grace: string): Promise<string> {
    const { client_secret } = await this.api.request<{ client_secret: string }>(
      `${this.path}/secrets`,
      'POST',
      { grace }
    );
    await this.load();
    return client_secret;
  }
  /** Deletes the client for good. Needs a recent passkey confirmation. */
  delete(): Promise<void> {
    return this.api.request(this.path, 'DELETE');
  }
}
