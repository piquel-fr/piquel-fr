/** Resource servers: reading the Authorization header, scopes, step-up and the answers. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AuthError, type ClaimsReader, Issuer, defineScopes } from '../src/index.ts';
import { FakeFetch, ISSUER, vector } from './vectors.ts';

const VALID = vector('tokens', 'access-valid');
const METADATA = 'https://notes.example.com/.well-known/oauth-protected-resource';
const notes = defineScopes('notes:read', 'notes:write');

/**
 * The vectors' notes API at the vectors' time, its key endpoint up or down, reading
 * application claims with `claims`.
 */
async function api<X = undefined>(keys: 'up' | 'down' = 'up', claims?: ClaimsReader<X>) {
  const fetch = FakeFetch.issuer(keys === 'up' ? VALID.input.jwks : undefined);
  const issuer = await Issuer.discover(ISSUER, {
    fetch: fetch.fetch,
    clock: () => VALID.now * 1000
  });
  return issuer.resource({
    identifier: String(VALID.input.audience),
    scopes: notes,
    metadata: METADATA,
    ...(claims && { claims })
  });
}

/** A request carrying `authorization` headers. */
function request(...authorization: string[]): Request {
  const headers = new Headers();
  for (const value of authorization) headers.append('authorization', value);
  return new Request('https://notes.example.com/notes', { headers });
}

/** The status and challenge `run` answers with when it throws. */
async function answer(run: () => unknown): Promise<[number, string | null]> {
  try {
    await run();
  } catch (error) {
    assert.ok(error instanceof AuthError);
    const response = error.toResponse();
    return [response.status, response.headers.get('www-authenticate')];
  }
  assert.fail('expected an AuthError');
}

test('a bearer token is read from Authorization, and nothing else', async () => {
  const resource = await api();
  const token = await resource.authenticate(request(`bearer ${String(VALID.input.token)}`));
  assert.deepEqual(token.subject, { kind: 'user', id: '01936f3e-8c00-7000-8000-000000000001' });
  const missing = `Bearer resource_metadata="${METADATA}"`;
  assert.deepEqual(await answer(() => resource.authenticate(request())), [401, missing]);
  assert.deepEqual(await answer(() => resource.authenticate(request('Basic YTpi'))), [
    401,
    missing
  ]);
  // A required scope is named even without a token, so the client knows what to ask for.
  assert.deepEqual(await answer(() => resource.authenticate(request(), 'notes:write')), [
    401,
    `Bearer scope="notes:write", resource_metadata="${METADATA}"`
  ]);
  const invalid = `Bearer error="invalid_request", resource_metadata="${METADATA}"`;
  // Several headers are malformed whatever their schemes, as the Rust SDK reads them.
  for (const malformed of [
    ['Bearer'],
    ['Bearer  '],
    ['Bearer a', 'Bearer b'],
    ['Basic YTpi', 'Bearer a']
  ]) {
    assert.deepEqual(await answer(() => resource.authenticate(request(...malformed))), [
      400,
      invalid
    ]);
  }
  // A token holding a space is read, and fails validation.
  assert.deepEqual(await answer(() => resource.authenticate(request('Bearer a b'))), [
    401,
    `Bearer error="invalid_token", resource_metadata="${METADATA}"`
  ]);
  assert.deepEqual(await answer(() => resource.validate('not.a.token')), [
    401,
    `Bearer error="invalid_token", resource_metadata="${METADATA}"`
  ]);
});

test('scopes and step-up requirements answer with their challenges', async () => {
  const token = await (await api()).validate(String(VALID.input.token));
  assert.ok(token.has('notes:read'));
  assert.equal(token.has('notes:write'), false);
  token.require('notes:read');
  assert.deepEqual(await answer(() => token.require('notes:write', 'notes:read')), [
    403,
    `Bearer error="insufficient_scope", scope="notes:read notes:write", resource_metadata="${METADATA}"`
  ]);
  // The token's passkey sign-in is an hour old: `phr` meets a social requirement,
  // and max_age gets the 30-second leeway.
  token.requireAuthentication({ acr_values: 'urn:piquel:acr:social' });
  token.requireAuthentication({ acr_values: 'phr', max_age: 3570 });
  assert.deepEqual(
    await answer(() => {
      token.requireAuthentication({ acr_values: 'phr', max_age: 3569 });
    }),
    [
      401,
      `Bearer error="insufficient_user_authentication", acr_values="phr", max_age="3569", resource_metadata="${METADATA}"`
    ]
  );
});

test('keys that cannot be fetched are the server failing, without a challenge', async () => {
  const resource = await api('down');
  assert.deepEqual(await answer(() => resource.validate(String(VALID.input.token))), [503, null]);
});

test('application claims are read with the claims check, and fail it when invalid', async () => {
  const read = await api('up', (claims) => ({ client: String(claims.client_id) }));
  const token = await read.validate(String(VALID.input.token));
  assert.deepEqual(token.extra, { client: 'notes-web' });
  const strict = await api('up', (claims) => {
    if (typeof claims.tenant !== 'string') throw new TypeError('tenant is required');
    return claims.tenant;
  });
  await assert.rejects(strict.validate(String(VALID.input.token)), {
    code: 'invalid_token',
    reason: 'invalid_claims'
  });
});
