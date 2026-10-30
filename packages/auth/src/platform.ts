/**
 * The browser APIs the browser client uses, gathered behind one type so tests can
 * replace them. Only `./browser` reads them; the core entry runs anywhere.
 */

/** @internal The page's location, history, storage, passkeys and `fetch`. */
export type Platform = {
  location: Pick<Location, 'href' | 'assign'>;
  history: Pick<History, 'replaceState' | 'state'>;
  /** Where a login waits for its callback: `sessionStorage`. */
  storage: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;
  credentials: Pick<CredentialsContainer, 'get'>;
  /** `PublicKeyCredential.getClientCapabilities()`, or none where the browser lacks it. */
  capabilities: () => Promise<PublicKeyCredentialClientCapabilities>;
  /** Sends a session's requests to resource servers. */
  fetch: (request: Request) => Promise<Response>;
};

/** @internal The current page's APIs. */
export function platform(): Platform {
  return {
    location: globalThis.location,
    history: globalThis.history,
    storage: globalThis.sessionStorage,
    credentials: globalThis.navigator.credentials,
    capabilities: async () =>
      typeof PublicKeyCredential !== 'undefined' && 'getClientCapabilities' in PublicKeyCredential
        ? // A browser that cannot tell has no related origins to offer.
          PublicKeyCredential.getClientCapabilities().catch(() => ({}))
        : {},
    fetch: (request) => fetch(request)
  };
}
