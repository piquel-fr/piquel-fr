declare global {
  namespace App {
    /** Data every page receives from the root layout. */
    // eslint-disable-next-line @typescript-eslint/consistent-type-definitions -- only an interface merges with SvelteKit's PageData.
    interface PageData {
      /** The auth origin, without a trailing slash. */
      authOrigin: string;
    }
  }
}

export {};
