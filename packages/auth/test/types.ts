/** Type tests: `tsc -p packages/auth/test` checks these lines, and nothing runs them. */
import { type AccessToken, type Issuer, defineScopes } from '../src/index.ts';

const notes = defineScopes('notes:read', 'notes:write');
type Notes = (typeof notes.all)[number];

// @ts-expect-error a scope name holding a space does not compile
defineScopes('notes read');

/** Needs a string. */
declare function text(value: string): void;
/** Needs nothing at all. */
declare function absent(value: undefined): void;

/** Needs a token proven to hold notes:write. */
declare function write(token: AccessToken<Notes, 'notes:write'>): void;

export async function checks(issuer: Issuer, compact: string, either: Notes, request: Request) {
  const resource = issuer.resource({ identifier: 'notes-api', scopes: notes });
  const token = await resource.validate(compact);
  // `authenticate` requires and proves the scopes it is given.
  write(await resource.authenticate(request, 'notes:write'));
  // @ts-expect-error a request authenticated without a scope proves none
  write(await resource.authenticate(request));
  // @ts-expect-error a union-typed scope proves nothing
  write(await resource.authenticate(request, either));
  token.require('notes:read');
  // @ts-expect-error a scope the resource did not declare does not compile
  token.require('notes:delete');
  // @ts-expect-error a token not checked for notes:write is refused
  write(token);
  write(token.require('notes:write'));
  // A token proving more scopes is accepted.
  write(token.require('notes:read', 'notes:write'));
  // @ts-expect-error a token proving another scope is refused
  write(token.require('notes:read'));
  if (token.has('notes:write')) write(token);
  // `either` is typed as a union: checked as one of its members, it proves none.
  // @ts-expect-error a union-typed scope proves nothing
  write(token.require(either));
  // @ts-expect-error a union-typed scope proves nothing
  token.require('notes:read', either);
  // @ts-expect-error a union-typed scope proves nothing
  if (token.has(either)) write(token);

  // Application claims take their type from the resource's reader, through narrowing.
  const tenants = issuer.resource({
    identifier: 'notes-api',
    scopes: notes,
    claims: (claims) => ({ tenant: String(claims.tenant) })
  });
  const scoped = (await tenants.validate(compact)).require('notes:write');
  text(scoped.extra.tenant);
  // A token with application claims still proves its scopes to any function.
  write(scoped);
  // Without a reader, a resource reads no application claims.
  absent(token.extra);
}
