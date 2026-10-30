/** The login client: pushed or query authorization requests, client authentication, errors and the exchange. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { Issuer, type ClientConfig } from '../src/index.ts';
import {
  DISCOVERY_URL,
  DOCUMENT,
  FakeFetch,
  ISSUER,
  JWKS_URI,
  REDIRECT_URI,
  TOKEN_URL,
  outcome,
  vector
} from './vectors.ts';

const PAR_URL = `${ISSUER}/oauth/par`;
const REQUEST_URI = 'urn:ietf:params:oauth:request_uri:pushed';
const REVOCATION_URL = (DOCUMENT as { revocation_endpoint: string }).revocation_endpoint;
const ID = vector('tokens', 'id-valid');
const PUBLIC: ClientConfig = { clientId: 'notes-web', redirectUri: REDIRECT_URI };

/** A client of the vectors' issuer at the vectors' time; `routes` add or replace endpoints. */
async function client(
  routes: Record<string, () => Response> = {},
  config: ClientConfig = PUBLIC,
  document: object = DOCUMENT as object
) {
  const fetch = new FakeFetch({
    [DISCOVERY_URL]: () => Response.json(document),
    [JWKS_URI]: () => Response.json(ID.input.jwks),
    [PAR_URL]: () => Response.json({ request_uri: REQUEST_URI, expires_in: 60 }, { status: 201 }),
    ...routes
  });
  const issuer = await Issuer.discover(ISSUER, { fetch: fetch.fetch, clock: () => ID.now * 1000 });
  return { fetch, client: issuer.client(config) };
}

/** The form and headers of the last request to `url`, which must have been sent. */
function sent(fetch: FakeFetch, url: string) {
  const request = fetch.sent(url);
  assert.ok(request, `no request to ${url}`);
  return request;
}

test('authorization requests are pushed when the issuer advertises it, and in the URL otherwise', async () => {
  const pushed = await client();
  const request = { scopes: ['profile'], stepUp: { acr_values: 'phr', max_age: 300 } } as const;
  const { url, pending } = await pushed.client.authorize(request);
  assert.equal(
    url,
    `${ISSUER}/oauth/authorize?client_id=notes-web&request_uri=${encodeURIComponent(REQUEST_URI)}`
  );
  const expected = {
    response_type: 'code',
    client_id: 'notes-web',
    redirect_uri: REDIRECT_URI,
    scope: 'openid profile',
    state: pending.state,
    nonce: pending.nonce,
    code_challenge: createHash('sha256').update(pending.verifier).digest('base64url'),
    code_challenge_method: 'S256',
    acr_values: 'phr',
    max_age: '300'
  };
  assert.deepEqual(sent(pushed.fetch, PAR_URL).form, expected);
  assert.equal(pending.verifier.length, 43);

  const withoutPar = Object.fromEntries(
    Object.entries(DOCUMENT as object).filter(
      ([name]) => name !== 'pushed_authorization_request_endpoint'
    )
  );
  const query = await client({}, PUBLIC, withoutPar);
  const direct = await query.client.authorize(request);
  const parameters = Object.fromEntries(new URL(direct.url).searchParams);
  assert.deepEqual(parameters, {
    ...expected,
    state: direct.pending.state,
    nonce: direct.pending.nonce,
    code_challenge: createHash('sha256').update(direct.pending.verifier).digest('base64url')
  });
  assert.equal(query.fetch.count(PAR_URL), 0);
});

test('a confidential client authenticates with HTTP Basic, a public one sends its ID', async () => {
  const refused = () => Response.json({ error: 'invalid_grant' }, { status: 400 });
  const confidential = await client(
    { [TOKEN_URL]: refused },
    { ...PUBLIC, clientSecret: 'a secret/+' }
  );
  await outcome(() => confidential.client.refresh('prt_v1_old'));
  const basic = sent(confidential.fetch, TOKEN_URL);
  // RFC 6749 §2.3.1 form-encodes both before base64.
  assert.equal(basic.headers.get('authorization'), `Basic ${btoa('notes-web:a+secret%2F%2B')}`);
  assert.deepEqual(basic.form, { grant_type: 'refresh_token', refresh_token: 'prt_v1_old' });

  const publicClient = await client({ [TOKEN_URL]: refused });
  await outcome(() => publicClient.client.refresh('prt_v1_old'));
  const form = sent(publicClient.fetch, TOKEN_URL);
  assert.equal(form.headers.get('authorization'), null);
  assert.equal(form.form.client_id, 'notes-web');
});

test('a refused request keeps its OAuth error; any other answer is a network error', async () => {
  const description = { error: 'invalid_request', error_description: 'request_uri is required' };
  const refused = await client({ [PAR_URL]: () => Response.json(description, { status: 400 }) });
  await assert.rejects(refused.client.authorize(), { code: 'oauth', response: description });
  const broken = await client({
    [TOKEN_URL]: () => new Response('<h1>Bad gateway</h1>', { status: 502 })
  });
  assert.deepEqual(await outcome(() => broken.client.refresh('prt_v1_old')), {
    error: { code: 'network' }
  });
  const unpushed = await client({
    [PAR_URL]: () => Response.json({ request_uri: '', expires_in: 60 }, { status: 201 })
  });
  await assert.rejects(unpushed.client.authorize(), { code: 'network' });
});

test('a revocation succeeds on HTTP 200, whatever its body', async () => {
  const { client: revoking } = await client({
    [REVOCATION_URL]: () => new Response('revoked', { status: 200 })
  });
  await revoking.revoke('prt_v1_old');
});

test('a login completes with an ID token validated against the pending login', async () => {
  const response = {
    access_token: 'at',
    token_type: 'Bearer',
    expires_in: 300,
    scope: 'profile openid',
    id_token: ID.input.token
  };
  const { client: login, fetch } = await client({ [TOKEN_URL]: () => Response.json(response) });
  const callback = new URLSearchParams({ code: 'pac_v1_code', state: 'af0ifjsldkj', iss: ISSUER });
  const pending = {
    issuer: ISSUER,
    clientId: 'notes-web',
    redirectUri: REDIRECT_URI,
    state: 'af0ifjsldkj',
    nonce: String(ID.input.nonce),
    verifier: 'verifier',
    stepUp: { acr_values: 'urn:piquel:acr:social' as const }
  };
  const tokens = await login.complete(pending, callback);
  assert.deepEqual(sent(fetch, TOKEN_URL).form, {
    grant_type: 'authorization_code',
    code: 'pac_v1_code',
    redirect_uri: REDIRECT_URI,
    code_verifier: 'verifier',
    client_id: 'notes-web'
  });
  assert.equal(tokens.idToken?.claims.sub, '01936f3e-8c00-7000-8000-000000000001');
  assert.equal(tokens.expiresAt, (ID.now + 300) * 1000);
  assert.equal(tokens.scopes.toString(), 'openid profile');
  // The sign-in is an hour old: a login asking for a recent one fails.
  const stale = { ...pending, stepUp: { acr_values: 'phr' as const, max_age: 60 } };
  assert.deepEqual(await outcome(() => login.complete(stale, callback)), {
    error: { code: 'invalid_token', reason: 'authentication_too_old' }
  });
  // Another client's pending login never reaches the token endpoint.
  const requests = fetch.count(TOKEN_URL);
  assert.deepEqual(
    await outcome(() => login.complete({ ...pending, clientId: 'other' }, callback)),
    {
      error: { code: 'callback', reason: 'state_mismatch' }
    }
  );
  assert.equal(fetch.count(TOKEN_URL), requests);
});
