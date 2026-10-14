import type { LayoutServerLoad } from './$types';

/** Every environment has its own auth origin, set at runtime (see hooks.server.ts). */
export const load: LayoutServerLoad = ({ locals }) => ({ authOrigin: locals.authOrigin });
