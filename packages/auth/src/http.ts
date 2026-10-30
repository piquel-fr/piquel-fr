/** Requests to auth's endpoints, with bounded bodies and errors that name the URL. */
import { AuthError } from './error.ts';
import { DecodeError, parse } from './json.ts';

/** Most bytes read from any response. Metadata, key sets and token responses are a few kilobytes. */
const MAX_BODY_BYTES = 256 * 1024;
/** How long a request may take. */
const TIMEOUT_MS = 10_000;

/** The `fetch` the SDK sends requests with; inject one to proxy or mock them. */
export type Fetch = (input: string, init: RequestInit) => Promise<Response>;

/** A response read in full. */
export class Reply {
  /** HTTP status. */
  readonly status: number;
  /** `Cache-Control: max-age`, in seconds, when present. */
  readonly maxAge: number | undefined;
  /** Where the request went. */
  readonly url: string;
  readonly #body: Uint8Array;

  constructor(url: string, response: Response, body: Uint8Array) {
    this.url = url;
    this.status = response.status;
    this.#body = body;
    // The first directive that parses as a `u64`, as the Rust SDK reads it.
    const maxAge = (response.headers.get('cache-control') ?? '')
      .split(',')
      .map((directive) => /^max-age=\+?([0-9]+)$/.exec(directive.trim())?.[1])
      .find((seconds) => seconds !== undefined && BigInt(seconds) < 2n ** 64n);
    this.maxAge = maxAge === undefined ? undefined : Number(maxAge);
  }

  /** Requires `200 OK`, as document endpoints answer. */
  ok(): this {
    if (this.status === 200) return this;
    throw new AuthError({ code: 'network' }, `${this.url} answered HTTP ${String(this.status)}`);
  }

  /** The body as JSON, or a {@link DecodeError} when it is not UTF-8 JSON. */
  json(): unknown {
    let text: string;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(this.#body);
    } catch (error) {
      throw new DecodeError('the document is not UTF-8', { cause: error });
    }
    return parse(text);
  }
}

/** Sends requests with an injected or the global `fetch`. */
export class Http {
  readonly #fetch: Fetch;

  constructor(fetcher: Fetch = (input, init) => fetch(input, init)) {
    this.#fetch = fetcher;
  }

  /** Sends a `GET`. */
  get(url: string, headers: Record<string, string> = {}): Promise<Reply> {
    return this.send(url, { method: 'GET', headers });
  }

  /** Sends a form `POST`. */
  post(
    url: string,
    form: Record<string, string>,
    headers: Record<string, string> = {}
  ): Promise<Reply> {
    return this.send(url, {
      method: 'POST',
      headers: { ...headers, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(form).toString()
    });
  }

  /**
   * Sends `init` to `url` and reads the response. Redirects are not followed: no auth
   * endpoint redirects, and one would carry credentials elsewhere.
   */
  async send(url: string, init: RequestInit): Promise<Reply> {
    const fetcher = this.#fetch;
    const failed = (cause: unknown) =>
      new AuthError({ code: 'network', url }, `request to ${url} failed`, { cause });
    let response: Response;
    try {
      response = await fetcher(url, {
        ...init,
        redirect: 'manual',
        signal: AbortSignal.timeout(TIMEOUT_MS)
      });
    } catch (error) {
      throw failed(error);
    }
    const chunks: Uint8Array[] = [];
    let length = 0;
    const reader = response.body?.getReader();
    try {
      for (;;) {
        const chunk = await reader?.read();
        if (chunk === undefined || chunk.done) break;
        length += chunk.value.length;
        if (length > MAX_BODY_BYTES) {
          await reader?.cancel();
          throw new AuthError(
            { code: 'network' },
            `${url} sent more than ${String(MAX_BODY_BYTES)} bytes`
          );
        }
        chunks.push(chunk.value);
      }
    } catch (error) {
      throw error instanceof AuthError ? error : failed(error);
    }
    const body = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.length;
    }
    return new Reply(url, response, body);
  }
}
