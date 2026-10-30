/** ASCII whitespace, which separates scopes in the lists auth reads and writes. */
const WHITESPACE = /[\t\n\f\r ]+/;

/** A scope name breaking RFC 6749 §3.3 syntax becomes `never`, so it does not compile. */
type ScopeName<S extends string> = S extends '' | `${string}${' ' | '"' | '\\'}${string}`
  ? never
  : S;

/**
 * A set of scope tokens (RFC 6749 §3.3), sorted and deduplicated so its
 * space-separated wire form is stable. {@link defineScopes} declares an
 * application's scopes as one, typed by their names.
 */
export class Scopes<S extends string = string> {
  /** Every scope, sorted. */
  readonly all: readonly S[];

  private constructor(scopes: Iterable<S>) {
    this.all = [...new Set(scopes)].sort();
  }

  /** Whether `scope` is a scope token: printable ASCII other than space, `"` and `\`. */
  static isToken(scope: string): boolean {
    return /^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope);
  }

  /**
   * Parses a space-separated list, tolerating repeated whitespace as auth does, or
   * returns `undefined` when a scope has invalid syntax.
   */
  static parse(value: string): Scopes | undefined {
    const scopes = value.split(WHITESPACE).filter((scope) => scope !== '');
    return scopes.every((scope) => Scopes.isToken(scope)) ? new Scopes(scopes) : undefined;
  }

  /** @internal Scopes from an application, throwing a `TypeError` for an invalid one. */
  static checked<S extends string>(scopes: readonly S[]): Scopes<S> {
    const invalid = scopes.find((scope) => !Scopes.isToken(scope));
    if (invalid !== undefined)
      throw new TypeError(`${JSON.stringify(invalid)} is not a valid scope`);
    return new Scopes(scopes);
  }

  /** @internal Scopes already known to be valid tokens. */
  static of<S extends string>(scopes: Iterable<S>): Scopes<S> {
    return new Scopes(scopes);
  }

  /** Whether the set holds `scope`. */
  has(scope: string): scope is S {
    return this.all.some((held) => held === scope);
  }

  /** The space-separated wire form. */
  toString(): string {
    return this.all.join(' ');
  }
}

/**
 * Declares an application's scopes once. Their names become a union type, so
 * requiring a scope that was not declared does not compile:
 *
 * ```ts
 * const notes = defineScopes('notes:read', 'notes:write');
 * const api = issuer.resource({ identifier: 'notes-api', scopes: notes });
 * const token = await api.authenticate(request);
 * token.require('notes:write'); // AccessToken proving notes:write
 * token.require('notes:delete'); // does not compile
 * ```
 *
 * A name that breaks RFC 6749 §3.3 syntax throws a `TypeError`; one holding a space,
 * `"` or `\` does not compile either.
 */
export function defineScopes<const S extends string>(...scopes: ScopeName<S>[]): Scopes<S> {
  return Scopes.checked(scopes);
}
