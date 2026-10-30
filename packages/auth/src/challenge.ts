/**
 * `WWW-Authenticate: Bearer` challenges (RFC 6750 §3, RFC 9470 §3, RFC 9728 §5.1),
 * written by resource servers and read back by clients, exactly as the Rust SDK does.
 */
import type { BearerChallenge, StepUpRequirement } from './protocol.ts';
import { includes } from './json.ts';
import { Scopes } from './scope.ts';
import { ACR } from './vocabulary.ts';

/** The authentication scheme of every challenge here. */
const SCHEME = 'bearer';

/** Lowercases ASCII letters only, as HTTP's case-insensitive comparisons do. */
export function asciiLowercase(value: string): string {
  return value.replace(/[A-Z]/g, (letter) => letter.toLowerCase());
}

/**
 * Quotes a parameter value, escaping `"` and `\`. A control character cannot appear
 * in a header at all, so it is written as `?`.
 */
function quote(value: string): string {
  const characters = Array.from(value, (character) => {
    const code = character.charCodeAt(0);
    if (character === '"' || character === '\\') return `\\${character}`;
    const control = (code < 0x20 && character !== '\t') || (code >= 0x7f && code <= 0x9f);
    return control ? '?' : character;
  });
  return `"${characters.join('')}"`;
}

/** A challenge's status and `WWW-Authenticate` value. */
export type FormattedChallenge = {
  /** 400 for `invalid_request`, 403 for `insufficient_scope`, and 401 otherwise. */
  status: number;
  /** The header value. */
  header: string;
};

/**
 * Writes a challenge with its parameters in the fixed order every SDK uses: `error`,
 * `error_description`, `scope`, `acr_values`, `max_age`, `resource_metadata`, every
 * value quoted.
 */
export function formatChallenge(challenge: BearerChallenge): FormattedChallenge {
  const parameters: [string, string | undefined][] = [
    ['error', challenge.error],
    ['error_description', challenge.error_description],
    ['scope', challenge.scope],
    ['acr_values', challenge.acr_values],
    ['max_age', challenge.max_age?.toString()],
    ['resource_metadata', challenge.resource_metadata]
  ];
  const written = parameters.flatMap(([name, value]) =>
    value === undefined ? [] : [`${name}=${quote(value)}`]
  );
  const status =
    challenge.error === 'invalid_request'
      ? 400
      : challenge.error === 'insufficient_scope'
        ? 403
        : 401;
  const header = written.length === 0 ? 'Bearer' : `Bearer ${written.join(', ')}`;
  return { status, header };
}

/**
 * The step-up requirement `source` names, such as a parsed challenge's
 * `acr_values` and `max_age`, without its other fields.
 */
export function stepUpRequirement(source: StepUpRequirement): StepUpRequirement {
  const requirement: StepUpRequirement = {};
  if (source.acr_values !== undefined) requirement.acr_values = source.acr_values;
  if (source.max_age !== undefined) requirement.max_age = source.max_age;
  return requirement;
}

/**
 * Finds the Bearer challenge in a `WWW-Authenticate` value, following the RFC 9110
 * §11 grammar: parameters in any order with token or quoted values, and other
 * challenges in the same header, including `token68` ones. Returns `undefined` when
 * the header breaks the grammar, has no Bearer challenge, or that challenge has a
 * repeated parameter or an invalid value. Unknown parameters are ignored, and
 * `acr_values` reads as its first value this version knows.
 */
export function parseChallenge(header: string): BearerChallenge | undefined {
  const challenges = new ChallengeParser(header).challenges();
  const bearer = challenges?.find((challenge) => asciiLowercase(challenge.scheme) === SCHEME);
  return bearer && ChallengeParser.bearer(bearer.parameters);
}

/** One parsed challenge. */
type Challenge = {
  /** Authentication scheme. */
  scheme: string;
  /** Parameters, in header order. */
  parameters: [string, string][];
  /** Whether parameters may follow: the scheme was followed by a space, and not by `token68`. */
  acceptsParameters: boolean;
};

/** Thrown inside the parser when the header breaks the grammar. */
class SyntaxFailure extends Error {}

/**
 * Reads RFC 9110 §11 challenges:
 *
 * ```text
 * WWW-Authenticate = 1#challenge
 * challenge        = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
 * auth-param       = token BWS "=" BWS ( token / quoted-string )
 * ```
 *
 * List elements are separated by commas, and empty elements are allowed (§5.6.1).
 */
class ChallengeParser {
  readonly #input: string;
  #position = 0;

  constructor(input: string) {
    this.#input = input;
  }

  /** Builds the Bearer challenge from its parameters, or `undefined` if one is invalid. */
  static bearer(parameters: [string, string][]): BearerChallenge | undefined {
    const challenge: BearerChallenge = {};
    const seen = new Set<string>();
    for (const [rawName, value] of parameters) {
      const name = asciiLowercase(rawName);
      if (seen.has(name)) return undefined;
      seen.add(name);
      switch (name) {
        case 'error':
          challenge.error = value;
          break;
        case 'error_description':
          // Printable ASCII without `"` or `\` (RFC 6750 §3).
          if (!/^[\x20\x21\x23-\x5b\x5d-\x7e]*$/.test(value)) return undefined;
          challenge.error_description = value;
          break;
        case 'scope': {
          // Scope tokens separated by single spaces (RFC 6750 §3).
          const scopes = value.split(' ').every((scope) => Scopes.isToken(scope))
            ? Scopes.parse(value)
            : undefined;
          if (scopes === undefined) return undefined;
          challenge.scope = scopes.toString();
          break;
        }
        case 'acr_values': {
          // Most preferred first: the target is the first value this version knows,
          // as auth picks it (OIDC Core §3.1.2.1).
          const target = value.split(/[\t\n\f\r ]+/).find((acr) => includes(ACR, acr));
          if (includes(ACR, target)) challenge.acr_values = target;
          break;
        }
        case 'max_age':
          // A `u32`, as Rust parses it.
          if (!/^\+?[0-9]+$/.test(value) || Number(value) > 0xffff_ffff) return undefined;
          challenge.max_age = Number(value);
          break;
        case 'resource_metadata':
          if (!URL.canParse(value)) return undefined;
          challenge.resource_metadata = new URL(value).href;
          break;
      }
    }
    return challenge;
  }

  /** Every challenge in the header, or `undefined` if it breaks the grammar. */
  challenges(): Challenge[] | undefined {
    try {
      return this.#challenges();
    } catch (error) {
      if (error instanceof SyntaxFailure) return undefined;
      throw error;
    }
  }

  #challenges(): Challenge[] {
    const challenges: Challenge[] = [];
    for (;;) {
      this.#skipWhitespace();
      const next = this.#peek();
      if (next === undefined) return challenges;
      if (next === ',') {
        this.#position += 1;
        continue;
      }
      const name = this.#token();
      const spaced = this.#skipWhitespace();
      if (this.#peek() === '=') {
        // A parameter continuing the current challenge's list.
        const value = this.#value();
        const current = challenges.at(-1);
        if (current?.acceptsParameters !== true) throw new SyntaxFailure();
        current.parameters.push([name, value]);
      } else {
        // A new challenge, whose credentials follow after a space (RFC 9110 §11).
        const challenge: Challenge = { scheme: name, parameters: [], acceptsParameters: spaced };
        if (spaced && this.#peek() !== undefined && this.#peek() !== ',') {
          const end = this.#token68End();
          if (end !== undefined) {
            this.#position = end;
            challenge.acceptsParameters = false;
          } else {
            const parameter = this.#token();
            this.#skipWhitespace();
            if (this.#peek() !== '=') throw new SyntaxFailure();
            challenge.parameters.push([parameter, this.#value()]);
          }
        }
        challenges.push(challenge);
      }
      // Every element ends at a comma or the end of the header.
      this.#skipWhitespace();
      if (this.#peek() !== undefined && this.#peek() !== ',') throw new SyntaxFailure();
    }
  }

  /** The next character, without consuming it. */
  #peek(at = this.#position): string | undefined {
    return this.#input[at];
  }

  /** Consumes characters matching `pattern`, returning whether there were any. */
  #skip(pattern: RegExp): boolean {
    const start = this.#position;
    while (pattern.test(this.#peek() ?? '')) this.#position += 1;
    return this.#position > start;
  }

  /** Consumes optional whitespace (`OWS`), returning whether there was any. */
  #skipWhitespace(): boolean {
    return this.#skip(/^[ \t]$/);
  }

  /** Reads a `token`: one or more RFC 9110 `tchar`s. */
  #token(): string {
    const start = this.#position;
    if (!this.#skip(/^[A-Za-z0-9!#$%&'*+\-.^_`|~]$/)) throw new SyntaxFailure();
    return this.#input.slice(start, this.#position);
  }

  /**
   * Where a `token68` starting here ends, if what follows is one: base64-like
   * characters, then `=` padding, then the end of the list element.
   */
  #token68End(): number | undefined {
    let end = this.#position;
    while (/^[A-Za-z0-9\-._~+/]$/.test(this.#peek(end) ?? '')) end += 1;
    if (end === this.#position) return undefined;
    while (this.#peek(end) === '=') end += 1;
    let next = end;
    while (this.#peek(next) === ' ' || this.#peek(next) === '\t') next += 1;
    const after = this.#peek(next);
    return after === undefined || after === ',' ? end : undefined;
  }

  /** Reads `BWS "=" BWS ( token / quoted-string )`, from the `=`. */
  #value(): string {
    this.#position += 1;
    this.#skipWhitespace();
    return this.#peek() === '"' ? this.#quoted() : this.#token();
  }

  /**
   * Reads a `quoted-string`, resolving `quoted-pair`s. Control characters other than
   * tab are rejected, as RFC 9110 §5.6.4 requires.
   */
  #quoted(): string {
    const text = (character: string | undefined): character is string =>
      character !== undefined && (character === '\t' || (character >= ' ' && character !== '\x7f'));
    this.#position += 1;
    let value = '';
    for (;;) {
      let character = this.#peek();
      if (character === '"') {
        this.#position += 1;
        return value;
      }
      if (character === '\\') {
        this.#position += 1;
        character = this.#peek();
      }
      if (!text(character)) throw new SyntaxFailure();
      value += character;
      this.#position += 1;
    }
  }
}
