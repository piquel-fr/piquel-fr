/** The time source for every expiry and cache check: milliseconds since the Unix epoch, as `Date.now` returns. Inject one to pin time in tests. */
export type Clock = () => number;

/** Clock skew tolerated on `exp`, `nbf`, `iat` and `auth_time`, matching auth's own, in milliseconds. */
export const LEEWAY = 30_000;

/** Access tokens this close to expiry are refreshed first, in milliseconds. */
export const REFRESH_MARGIN = 30_000;

/**
 * How long after a step-up sign-in a refusal is that step-up's one retry, in
 * milliseconds; a later one counts as a new action.
 */
export const STEP_UP_RETRY = 60_000;
