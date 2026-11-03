/**
 * Decoders from parsed JSON to the wire types, applying the rules serde applies when
 * the Rust SDK reads the same documents: unknown members are ignored, `null` reads as
 * an absent optional member, defaults fill absent lists and flags, and vocabulary
 * lists drop the values this version does not know. Every value is checked rather
 * than cast: it decodes to its type or throws a {@link DecodeError} naming where.
 */

/** A JSON value that does not have the expected shape. */
export class DecodeError extends Error {
  override name = 'DecodeError';
}

/** Reads a parsed JSON value at `path` (for error messages) as `T`. */
export type Decoder<T> = (value: unknown, path: string) => T;

/** The decoded type of each member of an object shape. */
type Shape = Record<string, Decoder<unknown>>;

/** An object decoded from `S`: members whose decoder can return `undefined` are optional. */
type Decoded<S extends Shape> = {
  [K in keyof S as undefined extends ReturnType<S[K]> ? never : K]: ReturnType<S[K]>;
} & {
  [K in keyof S as undefined extends ReturnType<S[K]> ? K : never]?: Exclude<
    ReturnType<S[K]>,
    undefined
  >;
};

/** Fails at `path`. */
function fail(path: string, expected: string): never {
  throw new DecodeError(`${path} must be ${expected}`);
}

/** Whether `value` is a JSON object. */
export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Parses JSON text, throwing a {@link DecodeError} when it is not JSON. */
export function parse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new DecodeError('the document is not JSON', { cause: error });
  }
}

/** A string. */
export const string: Decoder<string> = (value, path) =>
  typeof value === 'string' ? value : fail(path, 'a string');

/** A boolean. */
export const boolean: Decoder<boolean> = (value, path) =>
  typeof value === 'boolean' ? value : fail(path, 'a boolean');

/** An integer from `min` to `max`, as Rust's integer types read JSON numbers. */
export function integer(min: number, max: number): Decoder<number> {
  return (value, path) =>
    typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max
      ? value
      : fail(path, `an integer from ${String(min)} to ${String(max)}`);
}

/** Seconds since the Unix epoch (RFC 7519 `NumericDate`), as whole seconds. */
export const seconds = integer(Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER);

/** A string matching `pattern`. */
export function matching(pattern: RegExp, expected: string): Decoder<string> {
  return (value, path) =>
    typeof value === 'string' && pattern.test(value) ? value : fail(path, expected);
}

/** Whether `value` is one of `values`. */
export function includes<T extends string>(values: readonly T[], value: unknown): value is T {
  return values.some((known) => known === value);
}

/** One of a closed vocabulary's spellings. */
export function oneOf<const T extends string>(values: readonly T[]): Decoder<T> {
  return (value, path) =>
    includes(values, value) ? value : fail(path, `one of ${values.join(', ')}`);
}

/** An absolute URL, normalized as Rust's `Url` writes it. */
export const url: Decoder<string> = (value, path) =>
  typeof value === 'string' && URL.canParse(value) ? new URL(value).href : fail(path, 'a URL');

/** A string transformed by `read`, which returns `undefined` for invalid values. */
export function refine<T>(expected: string, read: (value: string) => T | undefined): Decoder<T> {
  return (value, path) =>
    (typeof value === 'string' ? read(value) : undefined) ?? fail(path, expected);
}

/** An optional member: absent or `null` reads as `undefined`. */
export function optional<T>(decoder: Decoder<T>): Decoder<T | undefined> {
  return (value, path) =>
    value === undefined || value === null ? undefined : decoder(value, path);
}

/** A member that falls back to `fallback` when absent; `null` is still an error. */
export function withDefault<T>(decoder: Decoder<T>, fallback: T): Decoder<T> {
  return (value, path) => (value === undefined ? fallback : decoder(value, path));
}

/** A member that must be absent, not even `null`. */
export const absent: Decoder<undefined> = (value, path) =>
  value === undefined ? undefined : fail(path, 'absent');

/** An array of `T`. */
export function array<T>(decoder: Decoder<T>): Decoder<T[]> {
  return (value, path) =>
    Array.isArray(value)
      ? value.map((item: unknown, index) => decoder(item, `${path}[${String(index)}]`))
      : fail(path, 'an array');
}

/** A vocabulary list of strings, keeping only the values this version knows. */
export function known<const T extends string>(values: readonly T[]): Decoder<T[]> {
  return (value, path) => array(string)(value, path).filter((item) => includes(values, item));
}

/** One optional vocabulary value, read as `undefined` when this version does not know it. */
export function knownOne<const T extends string>(values: readonly T[]): Decoder<T | undefined> {
  return (value, path) => {
    const item = optional(string)(value, path);
    return includes(values, item) ? item : undefined;
  };
}

/** An object with the members of `shape`; other members are ignored. */
export function object<S extends Shape>(shape: S): Decoder<Decoded<S>> {
  return (value, path) => {
    if (!isObject(value)) return fail(path, 'an object');
    const decoded: Record<string, unknown> = {};
    for (const [key, decoder] of Object.entries(shape)) {
      const member = decoder(Object.hasOwn(value, key) ? value[key] : undefined, `${path}.${key}`);
      if (member !== undefined) decoded[key] = member;
    }
    // Each member was decoded by its own decoder, so the record has the shape's type.
    return decoded as Decoded<S>;
  };
}
