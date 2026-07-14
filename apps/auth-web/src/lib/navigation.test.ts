import { describe, expect, it } from 'vitest';
import { authorizationDestination, safeReturnTo } from './navigation';

describe('authorization navigation', () => {
  it('carries only an opaque transaction to the authorization page', () => {
    expect(authorizationDestination('par_v1_value', '')).toBe('/authorize?transaction=par_v1_value');
  });

  it('rejects cross-origin and fragment return targets', () => {
    expect(safeReturnTo('//evil.example')).toBe('');
    expect(safeReturnTo('/security#token')).toBe('');
    expect(safeReturnTo('/security')).toBe('/security');
  });
});
