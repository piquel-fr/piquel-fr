/**
 * Requests to auth's endpoints: the SDK's transport policy, bounded bodies, and
 * errors that name the URL.
 */
import { asciiLowercase } from './challenge.ts';
import { AuthError } from './error.ts';
import { DecodeError, parse } from './json.ts';

/** Most bytes read from any response. Metadata, key sets and token responses are a few kilobytes. */
const MAX_BODY_BYTES = 256 * 1024;
/** How long a request may take, from sending it to its last body byte. */
const TIMEOUT_MS = 10_000;

/** The `fetch` the SDK sends requests with; inject one to proxy or mock them. */
export type Fetch = (input: string, init: RequestInit) => Promise<Response>;

/** A response read in full. */
export class Reply {
  /** HTTP status. */
  readonly status: number;
  /** How long `Cache-Control` lets the body be kept, in seconds, when it says. */
  readonly maxAge: number | undefined;
  /** Where the request went. */
  readonly url: string;
  readonly #body: Uint8Array;

  constructor(url: string, response: Response, body: Uint8Array) {
    this.url = url;
    this.status = response.status;
    this.#body = body;
    this.maxAge = Reply.#maxAge(response.headers.get('cache-control') ?? '');
  }

  /**
   * How long a `Cache-Control` value lets a response be kept, in seconds, as the Rust
   * SDK reads it (RFC 9111 §5.2): none with `no-store` or `no-cache`, whatever else it
   * says, else the first `max-age` that parses as a `u64`, quoted or not.
   */
  static #maxAge(header: string): number | undefined {
    let maxAge: number | undefined;
    for (const directive of header.split(',')) {
      const equals = directive.indexOf('=');
      const name = asciiLowercase((equals < 0 ? directive : directive.slice(0, equals)).trim());
      if (name === 'no-store' || name === 'no-cache') return 0;
      if (name !== 'max-age' || maxAge !== undefined || equals < 0) continue;
      const value = directive
        .slice(equals + 1)
        .trim()
        .replace(/^"+|"+$/g, '');
      const seconds = /^\+?([0-9]+)$/.exec(value)?.[1];
      if (seconds !== undefined && BigInt(seconds) < 2n ** 64n) maxAge = Number(seconds);
    }
    return maxAge;
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
   * @internal Reads `body` whole, or `undefined` once it holds more than `limit` bytes.
   * `signal` aborting cancels the body, so a stalled one is released.
   */
  static async readBody(
    body: ReadableStream<Uint8Array> | null,
    limit: number,
    signal?: AbortSignal
  ): Promise<Uint8Array | undefined> {
    const chunks: Uint8Array[] = [];
    let length = 0;
    const reader = body?.getReader();
    const cancel = () => void reader?.cancel().catch(() => undefined);
    signal?.addEventListener('abort', cancel, { once: true });
    try {
      for (;;) {
        const chunk = await reader?.read();
        if (chunk === undefined || chunk.done) break;
        length += chunk.value.length;
        if (length > limit) {
          await reader?.cancel();
          return undefined;
        }
        chunks.push(chunk.value);
      }
    } finally {
      signal?.removeEventListener('abort', cancel);
    }
    const whole = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      whole.set(chunk, offset);
      offset += chunk.length;
    }
    return whole;
  }

  /**
   * Sends `init` to `url` and reads the response, holding the SDK's transport policy
   * whatever the injected `fetch` does: only `https` URLs, no redirect, since no auth
   * endpoint redirects and a 307 or 308 would resend a code or token elsewhere, and a
   * 10-second deadline, which holds even when `fetch` ignores its abort signal.
   */
  async send(url: string, init: RequestInit): Promise<Reply> {
    if (asciiLowercase(url.slice(0, 8)) !== 'https://') {
      throw new AuthError({ code: 'network', url }, `${url} does not use https`);
    }
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(
          new AuthError(
            { code: 'network', url },
            `request to ${url} took longer than ${String(TIMEOUT_MS / 1000)} seconds`
          )
        );
      }, TIMEOUT_MS);
    });
    try {
      return await Promise.race([this.#exchange(url, init, controller.signal), deadline]);
    } finally {
      clearTimeout(timer);
    }
  }

  /** Sends a request and reads its response, refusing redirects and bodies over the limit. */
  async #exchange(url: string, init: RequestInit, signal: AbortSignal): Promise<Reply> {
    const fetcher = this.#fetch;
    const failed = (cause: unknown) =>
      new AuthError({ code: 'network', url }, `request to ${url} failed`, { cause });
    let response: Response;
    try {
      response = await fetcher(url, { ...init, redirect: 'manual', signal });
    } catch (error) {
      throw failed(error);
    }
    // A response that comes after the deadline, or that redirected, is not read: its
    // body is cancelled so the connection is released.
    const discard = () => void response.body?.cancel().catch(() => undefined);
    if (signal.aborted) {
      discard();
      throw failed(signal.reason);
    }
    // A browser's `fetch` hides a manual redirect behind an opaque response, and one
    // that ignored `redirect: 'manual'` marks the response it followed to.
    const status = response.status;
    if (
      response.redirected ||
      response.type === 'opaqueredirect' ||
      (status >= 300 && status < 400)
    ) {
      discard();
      throw new AuthError(
        { code: 'network', url },
        `${url} redirected with HTTP ${String(status)}`
      );
    }
    let body: Uint8Array | undefined;
    try {
      body = await Http.readBody(response.body, MAX_BODY_BYTES, signal);
    } catch (error) {
      throw failed(error);
    }
    if (body === undefined) {
      throw new AuthError(
        { code: 'network' },
        `${url} sent more than ${String(MAX_BODY_BYTES)} bytes`
      );
    }
    return new Reply(url, response, body);
  }
}
