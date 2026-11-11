/** Every case in tests/sdk-vectors, with the case's clock and a fake fetch. */
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  Issuer,
  KeySet,
  formatChallenge,
  parseChallenge,
  type BearerChallenge
} from '../src/index.ts';
import * as json from '../src/json.ts';
import { CookieKey, Login } from '../src/server.ts';
import {
  DISCOVERY_URL,
  DOCUMENT,
  FakeFetch,
  ISSUER,
  REDIRECT_URI,
  TOKEN_URL,
  cases,
  outcome
} from './vectors.ts';

describe('discovery vectors', () => {
  for (const vector of cases('discovery')) {
    test(vector.name, async () => {
      const issuer = String(vector.input.issuer);
      const fetch = FakeFetch.serving({
        [`${issuer}/.well-known/openid-configuration`]: vector.input.document
      });
      const result = await outcome(
        async () => (await Issuer.discover(issuer, { fetch: fetch.fetch })).metadata
      );
      assert.deepEqual(result, vector.expected);
    });
  }
});

describe('jwks vectors', () => {
  for (const vector of cases('jwks')) {
    test(vector.name, async () => {
      // As the parsed document, and as its JSON text.
      for (const document of [vector.input.jwks, JSON.stringify(vector.input.jwks)]) {
        const result = await outcome(() => Promise.resolve({ kids: KeySet.parse(document).kids }));
        assert.deepEqual(result, vector.expected);
      }
    });
  }
});

describe('token vectors', () => {
  for (const vector of cases('tokens')) {
    test(vector.name, async () => {
      const issuer = await Issuer.discover(ISSUER, {
        fetch: FakeFetch.issuer(vector.input.jwks).fetch,
        clock: () => vector.now * 1000
      });
      const token = String(vector.input.token);
      const audience = String(vector.input.audience);
      const result = await outcome(async () => {
        switch (vector.input.kind) {
          case 'access':
            return (await issuer.resource({ identifier: audience }).validate(token)).claims;
          case 'id': {
            const { nonce, max_age: maxAge } = vector.input;
            const id = await issuer.tokens.idToken(
              token,
              audience,
              // `null` when the login sent none.
              typeof nonce === 'string' ? nonce : undefined,
              typeof maxAge === 'number' ? maxAge : undefined
            );
            return id.claims;
          }
          case 'logout': {
            const client = issuer.client({ clientId: audience, redirectUri: REDIRECT_URI });
            return (await client.logoutToken(token)).claims;
          }
          default:
            throw new Error(`unknown token kind in ${vector.name}`);
        }
      });
      assert.deepEqual(result, vector.expected);
    });
  }
});

describe('challenge vectors', () => {
  for (const vector of cases('challenges')) {
    test(vector.name, () => {
      const expected = 'ok' in vector.expected ? vector.expected.ok : undefined;
      const { header, challenge } = vector.input;
      if (typeof header === 'string') {
        // Parse cases: headers not in canonical form.
        assert.deepEqual({ challenge: parseChallenge(header) ?? null }, expected);
        return;
      }
      // Format cases go both ways.
      const formatted = formatChallenge(challenge as BearerChallenge);
      assert.deepEqual(formatted, expected);
      assert.deepEqual(parseChallenge(formatted.header), challenge);
    });
  }
});

describe('callback vectors', () => {
  for (const vector of cases('callbacks')) {
    test(vector.name, async () => {
      // The token endpoint refuses every code; the test checks which code reached it.
      const fetch = new FakeFetch({
        [DISCOVERY_URL]: () =>
          Response.json({
            ...(DOCUMENT as object),
            authorization_response_iss_parameter_supported:
              vector.input.authorization_response_iss_parameter_supported
          }),
        [TOKEN_URL]: () => Response.json({ error: 'invalid_grant' }, { status: 400 })
      });
      const issuer = await Issuer.discover(String(vector.input.issuer), { fetch: fetch.fetch });
      const client = issuer.client({ clientId: 'notes-web', redirectUri: REDIRECT_URI });
      const pending = {
        issuer: issuer.issuer,
        clientId: 'notes-web',
        redirectUri: REDIRECT_URI,
        state: String(vector.input.state),
        nonce: 'unused',
        verifier: 'unused',
        stepUp: {}
      };
      const parameters = new URLSearchParams(vector.input.parameters as Record<string, string>);
      const result = await outcome(() => client.complete(pending, parameters));
      const sent = fetch.sent(TOKEN_URL);
      if (sent === undefined) {
        assert.deepEqual(result, vector.expected);
      } else {
        assert.deepEqual({ ok: { code: sent.form.code } }, vector.expected);
        assert.deepEqual(result, { error: { code: 'oauth' } });
      }
    });
  }
});

describe('cookie key vectors', () => {
  for (const vector of cases('cookie-keys')) {
    test(vector.name, async () => {
      const text = String(vector.input.cookie_key);
      const { ok: hex } = vector.expected as { ok: string | null };
      if (hex === null) {
        assert.throws(() => CookieKey.parse(text), TypeError);
        return;
      }
      // The same bytes derive the same keys: one opens what the other sealed.
      const bytes = Uint8Array.from(hex.match(/../g) ?? [], (pair) => parseInt(pair, 16));
      const expected = CookieKey.parse(btoa(String.fromCharCode(...bytes)));
      const sealed = await (await CookieKey.parse(text).keys()).session.seal('value', 'context');
      assert.equal(
        await (await expected.keys()).session.open(sealed, 'context', json.string),
        'value'
      );
    });
  }
});

describe('session cookie vectors', () => {
  for (const vector of cases('sessions')) {
    test(vector.name, async () => {
      const issuer = await Issuer.discover(ISSUER, {
        fetch: FakeFetch.issuer().fetch,
        clock: () => vector.now * 1000
      });
      const client = issuer.client({
        clientId: String(vector.input.client_id),
        clientSecret: 'secret',
        redirectUri: REDIRECT_URI
      });
      const login = new Login(client, {
        cookieKey: CookieKey.parse(String(vector.input.cookie_key))
      });
      const request = new Request(REDIRECT_URI, {
        headers: { cookie: String(vector.input.cookie) }
      });
      const session = await login.openSession(request);
      // Read back in the shape the cookie holds, as JSON writes it.
      const read: unknown =
        typeof session === 'string' ? null : JSON.parse(JSON.stringify(session.data));
      assert.deepEqual({ ok: read }, vector.expected);
    });
  }
});
