/**
 * A server-side app signing users in with `@piquel/auth/server`, in one file, on
 * Node's `http` server. Tokens stay on the server; the browser holds only a session
 * cookie. Run it with Node 22.18 or later, which runs TypeScript directly:
 *
 * ```sh
 * AUTH_URL=https://auth.piquel.fr CLIENT_ID=notes-web CLIENT_SECRET=pqcs_… \
 *   APP_URL=http://127.0.0.1:4100 node packages/auth/examples/server.ts
 * ```
 *
 * Register the client as confidential, with the redirect URI `$APP_URL/auth/callback`
 * and the post-logout URI `$APP_URL/`. An app outside this repository imports
 * `@piquel/auth` and `@piquel/auth/server` instead of the sources.
 */
import { type IncomingMessage, type ServerResponse, createServer } from 'node:http';
import { Issuer } from '../src/index.ts';
import { Login, MemoryBackend } from '../src/server.ts';

/** A required environment variable. */
function env(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === '') throw new Error(`${name} is not set`);
  return value;
}

const app = new URL(env('APP_URL'));
const issuer = await Issuer.discover(env('AUTH_URL'));
const login = new Login(
  issuer.client({
    clientId: env('CLIENT_ID'),
    clientSecret: env('CLIENT_SECRET'),
    redirectUri: new URL('/auth/callback', app).href
  }),
  {
    // Sessions are lost on restart: a real app implements `SessionBackend`.
    backend: new MemoryBackend(),
    scopes: ['profile'],
    afterLogout: new URL('/', app).href
  }
);

/** A page around `body`, escaped by the caller. */
function page(body: string): Response {
  const html = `<!doctype html><meta charset="utf-8"><title>Notes</title>${body}`;
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8' } });
}

/** `text` with HTML's special characters escaped. */
function escape(text: string): string {
  return text.replace(/[&<>"']/g, (character) => `&#${String(character.charCodeAt(0))};`);
}

/** The app: login's routes, a public home page, and a page that needs a recent passkey. */
async function handle(request: Request): Promise<Response> {
  const routed = await login.handle(request);
  if (routed) return routed;
  const user = await login.session(request);
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
