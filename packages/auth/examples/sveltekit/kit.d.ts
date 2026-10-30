/**
 * The few SvelteKit declarations the recipe in the package README uses, so `tsc`
 * checks it against this package without installing SvelteKit, whose peer
 * dependencies are its whole build toolchain. They match `@sveltejs/kit` 3; what this
 * fixture guards is the SDK's side of the recipe.
 */
declare module '@sveltejs/kit' {
  type MaybePromise<T> = T | Promise<T>;

  type RequestEvent = {
    request: Request;
    url: URL;
    locals: App.Locals;
    fetch: typeof fetch;
  };

  type Handle = (input: {
    event: RequestEvent;
    resolve: (event: RequestEvent) => MaybePromise<Response>;
  }) => MaybePromise<Response>;

  type ServerLoad = (event: RequestEvent) => MaybePromise<Record<string, unknown>>;
  type Load = (event: { url: URL; fetch: typeof fetch }) => MaybePromise<Record<string, unknown>>;

  function redirect(status: 303, location: string): never;
  function error(status: number, message: string): never;
}

declare module '$env/dynamic/private' {
  const env: Record<string, string | undefined>;
}

declare namespace App {
  // eslint-disable-next-line @typescript-eslint/consistent-type-definitions, @typescript-eslint/no-empty-object-type -- empty until the app's app.d.ts extends it by declaration merging, as in SvelteKit
  interface Locals {}
}
