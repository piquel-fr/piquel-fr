// The resource validator in any runtime: validates one vector token with the built
// package, discovery and key fetch served by a fake fetch. Node, Deno and Bun run
// this file; workerd calls its `test` handler (see workerd.js), since it allows no
// I/O or timers outside a handler.
import { Issuer } from '../../dist/index.js';

const WORKERD = globalThis.navigator?.userAgent === 'Cloudflare-Workers';

/** Reads a vector. workerd refuses import attributes, which the other runtimes require. */
async function load(name) {
  const path = `../../../../tests/sdk-vectors/${name}.json`;
  const module = await (WORKERD ? import(path) : import(path, { with: { type: 'json' } }));
  return module.default;
}

/** Validates the vector's token, throwing if it fails. */
async function smoke() {
  const { input: discovery } = await load('discovery/valid');
  const vector = await load('tokens/access-valid');
  const documents = {
    [`${discovery.issuer}/.well-known/openid-configuration`]: discovery.document,
    [discovery.document.jwks_uri]: vector.input.jwks
  };
  const issuer = await Issuer.discover(discovery.issuer, {
    fetch: (url) => Promise.resolve(Response.json(documents[url])),
    clock: () => vector.now * 1000
  });
  const resource = issuer.resource({ identifier: vector.input.audience });
  const token = await resource.validate(vector.input.token);
  if (token.subject.id !== vector.expected.ok.sub) throw new Error('wrong subject');
  console.log(`validated a token for ${token.subject.kind} ${token.subject.id}`);
}

export default { test: smoke };

if (!WORKERD) await smoke();
