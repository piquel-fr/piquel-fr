/**
 * Session storage. Applications implement {@link SessionBackend}, four plain
 * operations on opaque records, wherever they keep sessions. The SDK keeps everything
 * else: the record format and its validation, expiry, pending logins, the refresh
 * lease that stops two requests from redeeming one refresh token, and the indexes
 * back-channel logout finds sessions with.
 */
import * as base64 from './base64.ts';
import { idTokenClaims, scope } from './claims.ts';
import type { PendingLogin, Tokens } from './client.ts';
import * as json from './json.ts';
import type { StepUpRequirement } from './protocol.ts';
import { Scopes } from './scope.ts';
import { type Clock, LEEWAY } from './time.ts';
import { IdToken, type LogoutToken } from './token.ts';
import { ACR } from './vocabulary.ts';

/** Random bytes in a session key: 256 bits. */
const KEY_BYTES = 32;
/** Random bytes in a lease ID. */
const LEASE_BYTES = 16;
/** Tries at writing an index or logout record before giving up on contention. */
const UPDATE_ATTEMPTS = 8;
/** Rounds of contention {@link checkBackend} runs. */
const CHECK_ROUNDS = 25;
/** Concurrent callers in each round of contention. */
const CHECK_COMPETITORS = 4;

/** Record kind of a signed-in session. */
const SESSION = 'session';
/** Record kind of a pending login. */
const PENDING = 'pending';
/** Record kind of a step-up login's return, which marks its retry. */
const STEP_UP = 'step-up';
/** Record kind of the sessions of one auth session, by issuer and `sid`. */
const SID_INDEX = 'logout-sid';
/** Record kind of the sessions of one user, by issuer and `sub`. */
const SUB_INDEX = 'logout-sub';
/** Record kind of an applied logout token, by issuer and `jti`. */
const LOGOUT_JTI = 'logout-jti';

/**
 * A record a {@link SessionBackend} stores. The SDK writes `data` and reads it back
 * through its own validation, so a backend stores it as an opaque string. `data`
 * holds the user's tokens: never log it.
 */
export type SessionRecord = {
  /** Increases with every write, for {@link SessionBackend.replace}. */
  version: number;
  /** The SDK's serialized record. Store it unchanged. */
  data: string;
  /**
   * When the record stops being valid, in milliseconds since the epoch. The SDK
   * ignores expired records, so a backend may delete them whenever it likes, or never.
   */
  expiresAt: number;
};

/**
 * Where {@link Login} keeps sessions: four operations on {@link SessionRecord}s under
 * string keys, in any database. The SDK keeps all the logic, so a backend needs no
 * knowledge of sessions. It only has to make `insert`, `replace` and `remove`
 * atomic: two replicas refreshing one session at once would otherwise both redeem
 * its refresh token, and auth answers a reused refresh token by revoking the whole
 * family, signing the user out. Check a backend with {@link checkBackend}.
 *
 * Refresh leases expire by the issuer clock, which replicas compare with each other:
 * keep their clocks synchronized, for example with NTP. A lease lasts a minute, so a
 * few seconds of skew are harmless.
 *
 * With PostgreSQL, one table holds every record, and each operation is one statement:
 *
 * ```sql
 * CREATE TABLE auth_sessions (key TEXT PRIMARY KEY, version BIGINT NOT NULL,
 *   data TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL);
 * -- load
 * SELECT version, data, expires_at FROM auth_sessions WHERE key = $1;
 * -- insert: true if one row was inserted
 * INSERT INTO auth_sessions VALUES ($1, $2, $3, $4) ON CONFLICT (key) DO NOTHING;
 * -- replace: true if one row changed
 * UPDATE auth_sessions SET version = $3, data = $4, expires_at = $5
 *   WHERE key = $1 AND version = $2;
 * -- remove: true if one row went
 * DELETE FROM auth_sessions WHERE key = $1;
 * ```
 *
 * Expired rows can be swept with `DELETE FROM auth_sessions WHERE expires_at < now()`.
 */
export type SessionBackend = {
  /** The record under `key`, if any. */
  load(key: string): Promise<SessionRecord | null>;
  /**
   * Stores `record` under `key` only if no record is there, in one atomic step.
   * Returns whether it stored: of two concurrent calls for one key, only one may
   * return `true`. A record still stored counts as there even once expired; the SDK
   * replaces expired records itself.
   */
  insert(key: string, record: SessionRecord): Promise<boolean>;
  /**
   * Replaces the record under `key` with `record`, but only if the stored record is
   * still at version `expected`, in one atomic step. Returns whether it wrote.
   */
  replace(key: string, expected: number, record: SessionRecord): Promise<boolean>;
  /**
   * Removes the record under `key`. Returns whether there was one: of two concurrent
   * calls, only one may return `true`.
   */
  remove(key: string): Promise<boolean>;
};

/**
 * Sessions in process memory, for development and tests only. **Every session is
 * lost on restart, and replicas do not share them**: implement a
 * {@link SessionBackend} for real persistence.
 */
export class MemoryBackend implements SessionBackend {
  readonly #records = new Map<string, SessionRecord>();
  readonly #clock: Clock;

  /** Drops records expired by `clock`, `Date.now` by default. */
  constructor(options: { clock?: Clock } = {}) {
    this.#clock = options.clock ?? Date.now;
  }

  /** Every record, after dropping expired ones. */
  #live(): Map<string, SessionRecord> {
    const now = this.#clock();
    for (const [key, record] of this.#records) {
      if (record.expiresAt <= now) this.#records.delete(key);
    }
    return this.#records;
  }

  load(key: string): Promise<SessionRecord | null> {
    const record = this.#live().get(key);
    return Promise.resolve(record === undefined ? null : { ...record });
  }

  insert(key: string, record: SessionRecord): Promise<boolean> {
    const records = this.#live();
    if (records.has(key)) return Promise.resolve(false);
    records.set(key, { ...record });
    return Promise.resolve(true);
  }

  replace(key: string, expected: number, record: SessionRecord): Promise<boolean> {
    const records = this.#live();
    if (records.get(key)?.version !== expected) return Promise.resolve(false);
    records.set(key, { ...record });
    return Promise.resolve(true);
  }

  remove(key: string): Promise<boolean> {
    return Promise.resolve(this.#live().delete(key));
  }
}

/** @internal A signed-in user's tokens, kept server-side. */
export type StoredLogin = Tokens & {
  /** The issuer the user signed in with. */
  issuer: string;
  /** The validated ID token of the sign-in, or of the latest refresh that sent one. */
  idToken: IdToken;
};

/** @internal A login waiting for its callback, with where to send the user afterwards. */
export type PendingAuthorization = {
  /** The PKCE verifier, `state` and `nonce` of the login. */
  login: PendingLogin;
  /** Where the user goes once signed in, a checked same-origin path. */
  returnTo: string;
  /** Whether the login steps up, so the return to `returnTo` is its retry. */
  stepUp: boolean;
};

/** @internal A session as read: its login, record version, and whether a refresh holds it. */
export type Session = {
  login: StoredLogin;
  version: number;
  leased: boolean;
};

/**
 * @internal The outcome of {@link Sessions.lease}: this attempt holds the lease until
 * `until`, and must refresh, save and give it back before then; another attempt is
 * refreshing (`busy`); the session was saved since it was read, so reload it
 * (`changed`); a lease expired without being given back, so auth may have rotated the
 * refresh token and the session must end (`abandoned`); or the session is gone.
 */
export type Lease =
  { kind: 'acquired'; until: number } | { kind: 'busy' | 'changed' | 'abandoned' | 'missing' };

/** A count from 0, such as a time in milliseconds. */
const count = json.integer(0, Number.MAX_SAFE_INTEGER);

const storedLogin = json.object({
  issuer: json.string,
  idToken: json.string,
  claims: idTokenClaims,
  accessToken: json.string,
  expiresAt: count,
  scopes: scope,
  refreshToken: json.optional(json.string)
});

const lease = json.object({ id: json.string, until: count });

/** What a session record's `data` holds. */
const sessionData = json.object({ login: storedLogin, lease: json.optional(lease) });
type SessionData = ReturnType<typeof sessionData>;

const stepUpRequirement: json.Decoder<StepUpRequirement> = json.object({
  acr_values: json.optional(json.oneOf(ACR)),
  max_age: json.optional(json.integer(0, 0xffff_ffff))
});

const pendingAuthorization: json.Decoder<PendingAuthorization> = json.object({
  login: json.object({
    issuer: json.string,
    clientId: json.string,
    redirectUri: json.string,
    state: json.string,
    nonce: json.string,
    verifier: json.string,
    stepUp: stepUpRequirement
  }),
  returnTo: json.string,
  stepUp: json.boolean
});

/**
 * What an index record's `data` holds: the sessions started under one auth session
 * (`sid`) or for one user (`sub`), which a back-channel logout ends, each with when
 * it expires, and, for a `sid`, whether auth ended it, so no session may join it.
 */
const indexData = json.object({
  sessions: json.array(json.object({ key: json.string, expiresAt: count })),
  ended: json.boolean
});
type IndexData = ReturnType<typeof indexData>;

/** What an applied logout token's record holds: nothing, its presence is the record. */
const applied = json.object({});

/**
 * @internal A random key the browser holds in a cookie: a session's, a pending
 * login's, or a step-up login's return marker.
 */
export class SessionKey {
  /** The key as the cookie carries it. */
  readonly value: string;

  private constructor(value: string) {
    this.value = value;
  }

  /** A fresh random key. */
  static generate(): SessionKey {
    return new SessionKey(base64.random(KEY_BYTES));
  }

  /** A key read from a cookie, if it has the shape of one. */
  static parse(value: string | undefined): SessionKey | undefined {
    return value !== undefined && base64.decode(value)?.length === KEY_BYTES
      ? new SessionKey(value)
      : undefined;
  }
}

/**
 * @internal The SDK's session logic over an application's backend: the record
 * format, expiry, pending logins, the refresh lease, and back-channel logout's
 * records. Backends see only keys hashed with SHA-256, so reading the backend does
 * not give access to sessions.
 */
export class Sessions {
  readonly #backend: SessionBackend;
  readonly #clock: Clock;

  constructor(backend: SessionBackend, clock: Clock) {
    this.#backend = backend;
    this.#clock = clock;
  }

  /**
   * The backend key of the record of `kind` for `parts`: their SHA-256, joined by
   * NUL, never the values themselves, namespaced by `kind` so kinds never collide.
   */
  static async #key(kind: string, ...parts: string[]): Promise<string> {
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(parts.join('\0'))
    );
    return `${kind}:${base64.encode(new Uint8Array(digest))}`;
  }

  /** The data of `record` read by `decoder`, unless it is expired or unreadable. */
  #decode<T>(record: SessionRecord | null, decoder: json.Decoder<T>): T | undefined {
    if (record === null || record.expiresAt <= this.#clock()) return undefined;
    try {
      return decoder(json.parse(record.data), 'record');
    } catch (error) {
      // Written by another version or corrupted: missing rather than trusted.
      if (error instanceof json.DecodeError) return undefined;
      throw error;
    }
  }

  /** The record under `key` and its data, unless it is missing, expired or unreadable. */
  async #read<T>(
    key: string,
    decoder: json.Decoder<T>
  ): Promise<{ record: SessionRecord; data: T } | undefined> {
    const record = await this.#backend.load(key);
    const data = this.#decode(record, decoder);
    return record === null || data === undefined ? undefined : { record, data };
  }

  /** Stores `data` under the fresh random `key`, until `expiresAt`. */
  async #create(key: string, data: unknown, expiresAt: number): Promise<void> {
    const record = { version: 1, data: JSON.stringify(data), expiresAt };
    if (!(await this.#backend.insert(key, record))) {
      throw new Error('a fresh random session key is already in use');
    }
  }

  /**
   * Rewrites the record under `key`. `change` gets its data, `undefined` when it is
   * missing, expired or unreadable, and returns the data to write with its expiry,
   * or `undefined` to leave the record alone. A write that loses to another writer
   * is retried from a fresh read. Returns whether `change` wrote, and the data it
   * last got.
   */
  async #update<T>(
    key: string,
    decoder: json.Decoder<T>,
    change: (current: T | undefined) => { data: T; expiresAt: number } | undefined
  ): Promise<{ written: boolean; current: T | undefined }> {
    for (let attempt = 0; attempt < UPDATE_ATTEMPTS; attempt++) {
      const stored = await this.#backend.load(key);
      const current = this.#decode(stored, decoder);
      const next = change(current);
      if (next === undefined) return { written: false, current };
      const data = JSON.stringify(next.data);
      // An expired or unreadable record is still stored, so it is replaced. A new
      // record starts at the current time in microseconds, a version a deleted
      // record under the key has not reached, so a writer that read the deleted one
      // cannot overwrite its successor.
      const written =
        stored === null
          ? await this.#backend.insert(key, {
              version: this.#clock() * 1000,
              data,
              expiresAt: next.expiresAt
            })
          : await this.#backend.replace(key, stored.version, {
              version: stored.version + 1,
              data,
              expiresAt: next.expiresAt
            });
      if (written) return { written, current };
    }
    throw new Error(
      `a session record kept changing over ${String(UPDATE_ATTEMPTS)} attempts to write it`
    );
  }

  /** The serialized form of `login`. */
  static #write(login: StoredLogin): ReturnType<typeof storedLogin> {
    const { issuer, idToken, accessToken, expiresAt, scopes, refreshToken } = login;
    const written = {
      issuer,
      idToken: idToken.token,
      claims: idToken.claims,
      accessToken,
      expiresAt,
      scopes: scopes.toString()
    };
    return refreshToken === undefined ? written : { ...written, refreshToken };
  }

  /** The login a session record holds. Its ID token was validated when it was stored. */
  #login(data: SessionData): StoredLogin {
    const { issuer, idToken, claims, accessToken, expiresAt, scopes, refreshToken } = data.login;
    const login: StoredLogin = {
      issuer,
      idToken: new IdToken(claims, idToken, { clock: this.#clock }),
      accessToken,
      expiresAt,
      scopes: Scopes.parse(scopes) ?? Scopes.of([])
    };
    if (refreshToken !== undefined) login.refreshToken = refreshToken;
    return login;
  }

  /** The session under `key`. */
  async load(key: SessionKey): Promise<Session | null> {
    const read = await this.#read(await Sessions.#key(SESSION, key.value), sessionData);
    if (read === undefined) return null;
    const { record, data } = read;
    return { login: this.#login(data), version: record.version, leased: data.lease !== undefined };
  }

  /**
   * Starts a session under `key`, until `expiresAt`, and lists it under its `sid` and
   * `sub` for back-channel logout. Returns `false`, keeping no session, when auth
   * already ended its `sid`: a logout overtook the sign-in.
   */
  async insert(key: SessionKey, login: StoredLogin, expiresAt: number): Promise<boolean> {
    const name = await Sessions.#key(SESSION, key.value);
    await this.#create(name, { login: Sessions.#write(login) }, expiresAt);
    let listed = false;
    try {
      listed = await this.#list(name, login, expiresAt);
    } finally {
      // The browser never gets this session's key, so the record is unreachable;
      // removing it is tidiness, and a failure to must not hide why listing failed.
      if (!listed) await this.#backend.remove(name).catch(() => false);
    }
    return listed;
  }

  /**
   * Lists the session `name` under its `sid`, unless auth ended it, then under its
   * `sub`. Returns whether it was listed: a session missing from either index would
   * survive a back-channel logout.
   */
  async #list(name: string, login: StoredLogin, expiresAt: number): Promise<boolean> {
    const now = this.#clock();
    const join = (index: IndexData | undefined) => {
      const sessions = (index?.sessions ?? []).filter(
        (session) => session.expiresAt > now && session.key !== name
      );
      sessions.push({ key: name, expiresAt });
      const last = Math.max(...sessions.map((session) => session.expiresAt));
      return { data: { sessions, ended: index?.ended ?? false }, expiresAt: last };
    };
    const { sid, sub } = login.idToken.claims;
    if (sid !== undefined) {
      const index = await Sessions.#key(SID_INDEX, login.issuer, sid);
      const { written } = await this.#update(index, indexData, (current) =>
        current?.ended === true ? undefined : join(current)
      );
      if (!written) return false;
    }
    await this.#update(await Sessions.#key(SUB_INDEX, login.issuer, sub), indexData, join);
    return true;
  }

  /**
   * Applies a validated back-channel logout: deletes every session listed for its
   * target, then remembers its `jti` until its expiry and the leeway. A session
   * logout also ends the `sid` until `endedUntil`, so a sign-in that completes later
   * cannot join it. Returns `false`, changing nothing, if the token was applied
   * before, as when auth sends it again after losing the answer.
   *
   * The `jti` is remembered only once the deletion is done, so a request cut short by
   * a failure, a crash or auth hanging up is applied again on auth's retry rather
   * than skipped as applied. Two copies racing may both apply, which ends the same
   * sessions twice.
   */
  async logOut(token: LogoutToken, endedUntil: number): Promise<boolean> {
    const { iss, jti, exp } = token.claims;
    const record = await Sessions.#key(LOGOUT_JTI, iss, jti);
    if ((await this.#read(record, applied)) !== undefined) return false;
    let index: IndexData | undefined;
    if (token.target.kind === 'session') {
      // Sessions stay listed, so a retry after a failed deletion finds them again.
      const key = await Sessions.#key(SID_INDEX, iss, token.target.sid);
      ({ current: index } = await this.#update(key, indexData, (current) => ({
        data: { sessions: current?.sessions ?? [], ended: true },
        expiresAt: endedUntil
      })));
    } else {
      const key = await Sessions.#key(SUB_INDEX, iss, token.target.sub);
      index = (await this.#read(key, indexData))?.data;
    }
    for (const session of index?.sessions ?? []) await this.#backend.remove(session.key);
    await this.#update(record, applied, (used) =>
      used === undefined ? { data: {}, expiresAt: exp * 1000 + LEEWAY } : undefined
    );
    return true;
  }

  /** Ends the session under `key`. */
  async delete(key: SessionKey): Promise<void> {
    await this.#backend.remove(await Sessions.#key(SESSION, key.value));
  }

  /**
   * Takes the refresh lease as `id` for `ttl` milliseconds, but only while the
   * session is still at `version` and no attempt holds it.
   */
  async lease(key: SessionKey, version: number, id: string, ttl: number): Promise<Lease> {
    const name = await Sessions.#key(SESSION, key.value);
    const read = await this.#read(name, sessionData);
    if (read === undefined) return { kind: 'missing' };
    const { record, data } = read;
    const now = this.#clock();
    if (data.lease !== undefined) return { kind: data.lease.until > now ? 'busy' : 'abandoned' };
    if (record.version !== version) return { kind: 'changed' };
    const until = now + ttl;
    const leased = {
      version: version + 1,
      data: JSON.stringify({ ...data, lease: { id, until } }),
      expiresAt: record.expiresAt
    };
    // Losing the write means another request wrote in between, most likely taking
    // the lease: wait for its result.
    return (await this.#backend.replace(name, version, leased))
      ? { kind: 'acquired', until }
      : { kind: 'busy' };
  }

  /** A fresh lease ID. */
  static leaseId(): string {
    return base64.random(LEASE_BYTES);
  }

  /**
   * Writes `login` and gives the lease back, but only if `id` still holds it and it
   * has not expired: past its expiry, another request may already have found it
   * abandoned. Returns the saved session, or `null` if the lease was lost, as when
   * the session was logged out meanwhile. The time is read after the backend read,
   * so a slow read cannot make an expired lease look current. The caller bounds the
   * whole save by the lease.
   */
  async save(key: SessionKey, id: string, login: StoredLogin): Promise<Session | null> {
    const name = await Sessions.#key(SESSION, key.value);
    const read = await this.#read(name, sessionData);
    if (read === undefined) return null;
    const { record, data } = read;
    if (data.lease?.id !== id || data.lease.until <= this.#clock()) return null;
    const version = record.version + 1;
    const saved = {
      version,
      data: JSON.stringify({ login: Sessions.#write(login) }),
      expiresAt: record.expiresAt
    };
    return (await this.#backend.replace(name, record.version, saved))
      ? { login, version, leased: false }
      : null;
  }

  /** Keeps a pending login under `key`, until `expiresAt`. */
  async insertPending(
    key: SessionKey,
    pending: PendingAuthorization,
    expiresAt: number
  ): Promise<void> {
    await this.#create(await Sessions.#key(PENDING, key.value), pending, expiresAt);
  }

  /** Takes the pending login under `key`, at most once: only the request whose removal succeeds gets it. */
  async takePending(key: SessionKey): Promise<PendingAuthorization | null> {
    const name = await Sessions.#key(PENDING, key.value);
    const read = await this.#read(name, pendingAuthorization);
    return read !== undefined && (await this.#backend.remove(name)) ? read.data : null;
  }

  /** Marks the return of a step-up login to `path` with `marker`, until `expiresAt`. */
  async markStepUp(marker: SessionKey, path: string, expiresAt: number): Promise<void> {
    await this.#create(await Sessions.#key(STEP_UP, marker.value, path), {}, expiresAt);
  }

  /** Whether `marker` marks a return to `path` not yet taken, taking it: at most once. */
  async takeStepUp(marker: SessionKey, path: string): Promise<boolean> {
    const name = await Sessions.#key(STEP_UP, marker.value, path);
    const read = await this.#read(name, applied);
    return read !== undefined && (await this.#backend.remove(name));
  }
}

/**
 * Checks that `backend` keeps the {@link SessionBackend} contract {@link Login}
 * relies on; run it in a test against the real database. It checks that records
 * round-trip, that `insert` stores only where no record is, that `replace` and
 * `remove` refuse missing records and never create one, and that of several
 * callers racing `insert` of one key, `replace` at one version, or `remove`, exactly
 * one wins, and the stored record is the winner's. The races run concurrently over
 * 25 rounds, which catches a read-then-write backend in practice but cannot prove
 * atomicity: keep each operation a single atomic statement. It writes and removes
 * records under random keys, and throws an `Error` naming the first broken rule;
 * the backend's own failures propagate unchanged.
 *
 * ```ts
 * test('the session backend keeps its contract', () => checkBackend(new PostgresBackend(pool)));
 * ```
 */
export function checkBackend(backend: SessionBackend): Promise<void> {
  return new BackendCheck(backend).run();
}

/** The checks {@link checkBackend} runs. */
class BackendCheck {
  readonly #backend: SessionBackend;

  constructor(backend: SessionBackend) {
    this.#backend = backend;
  }

  /** Throws the rule the backend broke. */
  static #broken(rule: string): never {
    throw new Error(`the session backend breaks its contract: ${rule}`);
  }

  /** A fresh random key. */
  static #key(): string {
    return `check:${base64.random(KEY_BYTES)}`;
  }

  /** A record holding `data` at `version`, valid for five minutes. */
  static #record(version: number, data: string): SessionRecord {
    return { version, data, expiresAt: Date.now() + 5 * 60_000 };
  }

  /** Whether the record under `key` is `expected`, unchanged. */
  async #holds(key: string, expected: SessionRecord): Promise<boolean> {
    const stored = await this.#backend.load(key);
    return (
      stored?.version === expected.version &&
      stored.data === expected.data &&
      stored.expiresAt === expected.expiresAt
    );
  }

  /** Every check, in order, then the rounds of contention. */
  async run(): Promise<void> {
    const backend = this.#backend;
    const broken = BackendCheck.#broken;
    const key = BackendCheck.#key();
    const second = BackendCheck.#record(2, 'second');
    if ((await backend.load(key)) !== null) broken('load found a record that was never inserted');
    if ((await backend.replace(key, 1, second)) || (await backend.load(key)) !== null) {
      broken('replace wrote a record that does not exist');
    }
    if (await backend.remove(key)) broken('remove reported a record that does not exist');
    const first = BackendCheck.#record(1, 'first');
    if (!(await backend.insert(key, first))) broken('insert refused a key that holds no record');
    if (!(await this.#holds(key, first))) {
      broken('load did not return the inserted record unchanged');
    }
    if (
      (await backend.insert(key, BackendCheck.#record(1, 'again'))) ||
      !(await this.#holds(key, first))
    ) {
      broken('insert replaced a record already there');
    }
    if (await backend.replace(key, 7, second)) {
      broken('replace wrote although the version did not match');
    }
    if (!(await backend.replace(key, 1, second)) || !(await this.#holds(key, second))) {
      broken('replace did not write at the matching version');
    }
    if (
      !(await backend.remove(key)) ||
      (await backend.load(key)) !== null ||
      (await backend.replace(key, 2, second)) ||
      (await backend.load(key)) !== null
    ) {
      broken('a removed record came back');
    }
    for (let round = 0; round < CHECK_ROUNDS; round++) await this.#race();
  }

  /**
   * One round of contention on a fresh key: racing `insert` calls, then racing
   * `replace` calls at one version, then racing `remove` calls, started together.
   */
  async #race(): Promise<void> {
    const backend = this.#backend;
    const key = BackendCheck.#key();
    const competitors = Array.from({ length: CHECK_COMPETITORS }, (_, competitor) => competitor);
    const data = (competitor: number) => `competitor ${String(competitor)}`;
    // The one competitor whose call succeeded.
    const winner = async (call: (competitor: number) => Promise<boolean>, rule: string) => {
      const results = await Promise.all(competitors.map(call));
      const [only, ...others] = competitors.filter((competitor) => results[competitor]);
      return only !== undefined && others.length === 0 ? only : BackendCheck.#broken(rule);
    };
    const stored = async () => (await backend.load(key))?.data;
    const inserter = await winner(
      (competitor) => backend.insert(key, BackendCheck.#record(1, data(competitor))),
      'of racing inserts of one key, exactly one must store'
    );
    if ((await stored()) !== data(inserter)) {
      BackendCheck.#broken("the stored record is not the winning insert's");
    }
    const replacer = await winner(
      (competitor) => backend.replace(key, 1, BackendCheck.#record(2, data(competitor))),
      'of racing replaces at one version, exactly one must write'
    );
    if ((await stored()) !== data(replacer)) {
      BackendCheck.#broken("the stored record is not the winning replace's");
    }
    await winner(
      () => backend.remove(key),
      'of racing removes, exactly one must report the record'
    );
    if ((await stored()) !== undefined)
      BackendCheck.#broken('a record survived the racing removes');
  }
}
