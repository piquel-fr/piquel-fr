/**
 * A server-side app signing users in with `@sourceorigin/auth/server`, in one file, on
 * Node's `http` server. The session lives in the browser, in a cookie sealed with
 * `COOKIE_KEY`, so the app stores nothing, and sessions a back-channel logout ended
 * are signed out. Run it with Node 22.18 or later, which runs TypeScript directly:
 *
 * ```sh
 * AUTH_URL=https://auth.sourceorigin.dev CLIENT_ID=notes-web CLIENT_SECRET=socs_… \
 *   COOKIE_KEY="$(openssl rand -base64 32)" APP_URL=http://127.0.0.1:4100 \
 *   node packages/auth/examples/server.ts
 * ```
 *
 * Register the client as confidential, allowed `offline_access`, with the redirect
 * URI `$APP_URL/auth/callback` and the post-logout URI `$APP_URL/`. An app outside
 * this repository imports `@sourceorigin/auth` and `@sourceorigin/auth/server` instead of the
 * sources. The `ANCHOR` comments mark the parts `docs/user/apps/sign-in-typescript.md`
 * shows.
 */
import { type IncomingMessage, type ServerResponse, createServer } from 'node:http';
import { Issuer } from '../src/index.ts';
import { CookieKey, Login, type SignedIn } from '../src/server.ts';

/** A required environment variable. */
function env(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === '') throw new Error(`${name} is not set`);
  return value;
}

// ANCHOR: login
/**
 * Auth sessions that back-channel logouts ended. Kept in the app's database in
 * practice, so every replica sees it.
 */
const ended = new Set<string>();

const app = new URL(env('APP_URL'));
const issuer = await Issuer.discover(env('AUTH_URL'));
const login = new Login(
  issuer.client({
    clientId: env('CLIENT_ID'),
    clientSecret: env('CLIENT_SECRET'),
    redirectUri: new URL('/auth/callback', app).href
  }),
  {
    // The same key on every replica, kept like the client secret. Without one, a
    // random key signs every user out on restart.
    cookieKey: process.env.COOKIE_KEY
      ? CookieKey.parse(process.env.COOKIE_KEY)
      : CookieKey.generate(),
    scopes: ['profile'],
    afterLogout: new URL('/', app).href,
    // Auth's logout tokens always name the session that ended.
    backchannelLogout: (token) => {
      if (token.target.kind === 'session') ended.add(token.target.sid);
      return Promise.resolve();
    }
  }
);
// ANCHOR_END: login

/** A page around `body`, escaped by the caller. */
function page(body: string): Response {
  const html = `<!doctype html><meta charset="utf-8"><title>Notes</title>${body}`;
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8' } });
}

/** `text` with HTML's special characters escaped. */
function escape(text: string): string {
  return text.replace(/[&<>"']/g, (character) => `&#${String(character.charCodeAt(0))};`);
}

// ANCHOR: handle
/**
 * The app: login's routes, a public home page, and a page that needs a recent
 * passkey.
 */
async function handle(request: Request): Promise<Response> {
  const routed = await login.handle(request);
  if (routed) return routed;
  const user = await login.session(request);
  if (user instanceof Response) return user; // 403 from another site, or 503
  // A session a back-channel logout ended is signed out.
  const live = user?.sid !== undefined && ended.has(user.sid) ? null : user;
  // Sets the cookies the session's read needs, such as a refreshed session.
  return login.respond(request, answer(request, live));
}

/** The app's page `request` asks for, for `user` when signed in. */
function answer(request: Request, user: SignedIn | null): Response {
  switch (new URL(request.url).pathname) {
    case '/':
      if (!user) return page('<h1>Notes</h1><a href="/auth/login">Sign in</a>');
      return page(
        `<h1>Notes</h1><p>Signed in as ${escape(user.name)}.</p>` +
          '<p><a href="/settings">Settings</a></p>' +
          '<form method="post" action="/auth/logout"><button>Sign out</button></form>'
      );
    case '/settings': {
      if (!user) return login.signIn(request);
      // A passkey sign-in within five minutes, or a redirect through login and back.
      const stepUp = user.require({ acr_values: 'phr', max_age: 300 });
      if (stepUp) return stepUp;
      return page(`<h1>Settings</h1><p>Recently confirmed as ${escape(user.name)}.</p>`);
    }
    default:
      return new Response('Not found', { status: 404 });
  }
}
// ANCHOR_END: handle

/** Answers one of Node's requests with {@link handle}, converting to and from `Request` and `Response`. */
async function serve(incoming: IncomingMessage, outgoing: ServerResponse): Promise<void> {
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming.headers)) {
    for (const item of [value ?? []].flat()) headers.append(name, item);
  }
  const chunks: Buffer[] = [];
  for await (const chunk of incoming) chunks.push(chunk as Buffer);
  const method = incoming.method ?? 'GET';
  const response = await handle(
    new Request(new URL(incoming.url ?? '/', app), {
      method,
      headers,
      body: method === 'GET' || method === 'HEAD' ? null : Buffer.concat(chunks)
    })
  );
  for (const [name, value] of response.headers) outgoing.setHeader(name, value);
  // Each cookie in a header of its own: `Headers` joins them otherwise.
  outgoing.setHeader('set-cookie', response.headers.getSetCookie());
  outgoing.writeHead(response.status).end(Buffer.from(await response.arrayBuffer()));
}

createServer((incoming, outgoing) => {
  serve(incoming, outgoing).catch((error: unknown) => {
    console.error(error);
    outgoing.writeHead(500).end();
  });
}).listen(Number(app.port), app.hostname, () => {
  console.log(`Notes is listening on ${app.origin}`);
});
