import { AuthApi, errorMessage, type Provider } from '@piquel/auth-sdk';

/** An active passkey of the account. */
export type Passkey = {
  id: string;
  friendly_name: string;
  created_at?: string;
  last_used_at?: string | null;
};
/** A social identity linked to the account. */
export type Identity = { provider: Provider; linked_email: string | null };
/** An application the account granted access, from `GET /account/apps`. */
export type ConnectedApp = {
  client_id: string;
  name: string;
  /** Made by Piquel: it gets access again without asking on its next sign-in. */
  first_party: boolean;
  /** What it can read. Scopes without a description are shown by name. */
  scopes: { scope: string; description: string | null }[];
  /** Whether it can act while the user is away. */
  offline_access: boolean;
  granted_at: string;
  last_used_at: string;
};

/** The account settings API on the auth origin, shared by the settings pages. */
export class Account {
  readonly api: AuthApi;
  constructor(readonly authOrigin: string) {
    this.api = new AuthApi(authOrigin);
  }
  /** A page of the auth frontend, such as `login`, that returns to `returnTo` when done. */
  page(name: string, returnTo: string): string {
    return `${this.authOrigin}/${name}?return_to=${encodeURIComponent(returnTo)}`;
  }
  passkeys(): Promise<Passkey[]> {
    return this.api.request('/account/passkeys');
  }
  identities(): Promise<Identity[]> {
    return this.api.request('/account/social-identities');
  }
  apps(): Promise<ConnectedApp[]> {
    return this.api.request('/account/apps');
  }
  /** Needs only a session: it removes access, it grants none. */
  removeApp(clientId: string): Promise<void> {
    return this.api.request(`/account/apps/${encodeURIComponent(clientId)}`, 'DELETE');
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
