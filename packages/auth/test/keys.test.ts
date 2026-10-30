/** The key cache's fetch rules: one refetch per unknown kid, spacing, freshness and outages. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Jws, KeyCache } from '../src/index.ts';
import * as base64 from '../src/base64.ts';
import { FakeFetch, JWKS_URI, ManualClock, outcome, vector } from './vectors.ts';

const jwks = (name: string) => vector('jwks', name).input.jwks;
const token = (name: string) => String(vector('tokens', name).input.token);
const OLD = token('access-valid');
const NEW = token('access-new-key');
/** The old token with a header naming a key no set has. */
const UNKNOWN = `${base64.encode(new TextEncoder().encode('{"alg":"RS256","kid":"key-2027","typ":"at+jwt"}'))}.${OLD.split('.').slice(1).join('.')}`;

/** A key endpoint serving `documents[phase]`, and failing past the end. */
class KeyServer extends FakeFetch {
  phase = 0;

  constructor(documents: unknown[], headers: HeadersInit = {}) {
    super({
      [JWKS_URI]: () => {
        const document = documents[this.phase];
        return document === undefined
          ? new Response(null, { status: 503 })
          : Response.json(document, { headers });
      }
    });
  }

  get served(): number {
    return this.count(JWKS_URI);
  }
}

/** Verifies `compact`'s signature with `keys`, in the vectors' error form. */
function verify(keys: KeyCache, compact: string) {
  return outcome(async () => {
    const jws = Jws.parse(compact);
    await keys.verify(jws, jws.requireAlgorithm(['RS256']));
    return 'verified';
  });
}

test('a new kid refetches once, no more than every 30 seconds, and outages keep the last keys', async () => {
  const server = new KeyServer([jwks('rotation-before'), jwks('rotation-during')]);
  const clock = new ManualClock(1_767_225_600);
  const keys = new KeyCache(JWKS_URI, { fetch: server.fetch, clock: clock.now });

  const first = await Promise.all(Array.from({ length: 5 }, () => verify(keys, OLD)));
  assert.deepEqual(first, Array(5).fill({ ok: 'verified' }));
  assert.equal(server.served, 1, 'concurrent first uses share one fetch');

  server.phase = 1;
  clock.seconds += 31;
  assert.deepEqual(await verify(keys, NEW), { ok: 'verified' });
  assert.equal(server.served, 2, 'a new kid refetches once');

  clock.seconds += 9;
  assert.deepEqual(await verify(keys, UNKNOWN), {
    error: { code: 'invalid_token', reason: 'unknown_key' }
  });
  assert.deepEqual(await verify(keys, NEW), { ok: 'verified' });
  assert.equal(server.served, 2, 'no refetch within 30 seconds');

  server.phase = 2;
  clock.seconds += 2 * 3600;
  assert.deepEqual(
    await verify(keys, OLD),
    { ok: 'verified' },
    'stale keys survive a failed refresh'
  );
  assert.equal(server.served, 3);
  clock.seconds += 31;
  assert.deepEqual(await verify(keys, UNKNOWN), { error: { code: 'network' } });
  assert.equal(server.served, 4);
  // Until a fetch succeeds, a missing key is unavailable rather than unknown.
  assert.deepEqual(await verify(keys, UNKNOWN), { error: { code: 'network' } });
  assert.equal(server.served, 4);
});

test('keys stay fresh for max-age, bounded to 30 seconds through 24 hours, or an hour', async () => {
  for (const [cacheControl, lifetime] of [
    ['max-age=5', 30],
    ['public, max-age=600', 600],
    ['max-age=999999', 24 * 3600],
    ['no-cache', 3600]
  ] as const) {
    const server = new KeyServer([jwks('rotation-before')], { 'cache-control': cacheControl });
    const clock = new ManualClock(1_767_225_600);
    const keys = new KeyCache(JWKS_URI, { fetch: server.fetch, clock: clock.now });
    await verify(keys, OLD);
    clock.seconds += lifetime - 1;
    await verify(keys, OLD);
    assert.equal(server.served, 1, `${cacheControl}: fresh before ${String(lifetime)} seconds`);
    clock.seconds += 1;
    await verify(keys, OLD);
    assert.equal(server.served, 2, `${cacheControl}: stale after ${String(lifetime)} seconds`);
  }
});

test('a set with a duplicate kid is rejected and the previous set stays in use', async () => {
  const server = new KeyServer([jwks('rotation-before'), jwks('duplicate-kid')]);
  const clock = new ManualClock(1_767_225_600);
  const keys = new KeyCache(JWKS_URI, { fetch: server.fetch, clock: clock.now });
  await verify(keys, OLD);
  server.phase = 1;
  clock.seconds += 2 * 3600;
  assert.deepEqual(await verify(keys, OLD), { ok: 'verified' });
  clock.seconds += 31;
  assert.deepEqual(await verify(keys, NEW), {
    error: { code: 'keys', reason: 'duplicate_key_id' }
  });
  assert.equal(server.served, 3);
});
