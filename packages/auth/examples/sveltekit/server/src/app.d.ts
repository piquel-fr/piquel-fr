import type { SignedIn } from '@piquel/auth/server';

declare global {
  namespace App {
    // eslint-disable-next-line @typescript-eslint/consistent-type-definitions -- SvelteKit's App types are extended by declaration merging
    interface Locals {
      /** The signed-in user, or `null`; set by `handle` in hooks.server.ts. */
      user: SignedIn | null;
    }
  }
}

export {};
