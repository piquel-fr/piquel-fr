/** The transport policy: a deadline and no redirects, whatever the injected `fetch` does. */
import assert from 'node:assert/strict';
import { mock, test } from 'node:test';
import { AuthError } from '../src/index.ts';
import { Http } from '../src/http.ts';

const TOKEN_URL = 'https://auth.example.com/oauth/token';

/** Whether `error` is a `network` error. */
const network = (error: unknown) => error instanceof AuthError && error.code === 'network';

test('a server that never answers times out, though the fetch ignores its signal', async () => {
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    // A fetch that never settles, whatever its signal says.
    const http = new Http(() => new Promise<Response>(() => undefined));
    const sent = http.get(TOKEN_URL);
    mock.timers.tick(10_000);
    await assert.rejects(sent, network);
  } finally {
    mock.timers.reset();
  }
});

test('a redirect is refused, and never asked to be followed', async () => {
  let redirect: RequestRedirect | undefined;
  const http = new Http((_, init) => {
    redirect = init.redirect;
    return Promise.resolve(
      new Response(null, { status: 307, headers: { location: 'https://elsewhere.example' } })
    );
  });
  await assert.rejects(http.post(TOKEN_URL, { refresh_token: 'prt_v1_secret' }), network);
  assert.equal(redirect, 'manual');
});

test('only https URLs are requested', async () => {
  let sent = false;
  const http = new Http(() => {
    sent = true;
    return Promise.resolve(new Response('{}'));
  });
  await assert.rejects(http.get('http://auth.example.com/jwks'), network);
  assert.equal(sent, false);
});
