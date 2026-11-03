/** Reads the shared vectors in tests/sdk-vectors, and fakes the endpoints they describe. */
import { readFileSync, readdirSync } from 'node:fs';
import { AuthError, type Fetch } from '../src/index.ts';

/** The vectors' root. */
const ROOT = new URL('../../../tests/sdk-vectors/', import.meta.url);

/** One vector file. */
export type Case = {
  /** File name, for test names. */
  name: string;
  /** The Unix time the clock returns, in seconds. */
  now: number;
  input: Record<string, unknown>;
  expected: { ok: unknown } | { error: { code: string; reason?: string } };
};

/** Every case of `category`, in file name order. */
export function cases(category: string): Case[] {
  const directory = new URL(`${category}/`, ROOT);
  return readdirSync(directory)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map(
      (name) =>
        ({
          name,
          ...(JSON.parse(readFileSync(new URL(name, directory), 'utf8')) as object)
        }) as Case
    );
}

/** The case of `category` named `name`. */
export function vector(category: string, name: string): Case {
  const found = cases(category).find((candidate) => candidate.name === `${name}.json`);
  if (found === undefined) throw new Error(`no vector ${category}/${name}`);
  return found;
}

/** The issuer every token vector is for, and its metadata document. */
export const ISSUER = 'https://auth.example.com';
export const DOCUMENT = vector('discovery', 'valid').input.document;
export const DISCOVERY_URL = `${ISSUER}/.well-known/openid-configuration`;
export const JWKS_URI = `${ISSUER}/.well-known/jwks.json`;

/** A fake `fetch` answering each URL with its route's response, counting requests. */
export class FakeFetch {
  readonly requests: { url: string; init: RequestInit }[] = [];
  readonly routes: Record<string, () => Response>;

  constructor(routes: Record<string, () => Response>) {
    this.routes = routes;
  }

  /** Serves `documents` as JSON at their URLs. */
  static serving(documents: Record<string, unknown>): FakeFetch {
    return new FakeFetch(
      Object.fromEntries(
        Object.entries(documents).map(([url, body]) => [url, () => Response.json(body)])
      )
    );
  }

  /** The discovery document and `jwks`, as auth serves them; no key endpoint without `jwks`. */
  static issuer(jwks?: unknown): FakeFetch {
    return FakeFetch.serving(
      jwks === undefined
        ? { [DISCOVERY_URL]: DOCUMENT }
        : { [DISCOVERY_URL]: DOCUMENT, [JWKS_URI]: jwks }
    );
  }

  /** Requests sent to `url`. */
  count(url: string): number {
    return this.requests.filter((request) => request.url === url).length;
  }

  readonly fetch: Fetch = (url, init) => {
    this.requests.push({ url, init });
    const route = this.routes[url];
    return Promise.resolve(route ? route() : new Response(null, { status: 404 }));
  };
}

/** A clock tests move by hand, in seconds. */
export class ManualClock {
  seconds: number;

  constructor(seconds: number) {
    this.seconds = seconds;
  }

  readonly now = () => this.seconds * 1000;
}

/** What `run` returns or throws, in the vectors' `expected` form. */
export async function outcome(run: () => Promise<unknown>): Promise<Case['expected']> {
  try {
    return { ok: await run() };
  } catch (error) {
    if (!(error instanceof AuthError)) throw error;
    return {
      error:
        error.reason === undefined
          ? { code: error.code }
          : { code: error.code, reason: error.reason }
    };
  }
}
