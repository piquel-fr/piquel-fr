// Public build settings read through import.meta.env.
// eslint-disable-next-line @typescript-eslint/consistent-type-definitions -- only an interface merges with Vite's ImportMetaEnv.
interface ImportMetaEnv {
  /** Set by local builds; deployed images read the auth origin from /config.json. */
  readonly VITE_AUTH_ORIGIN?: string;
}
