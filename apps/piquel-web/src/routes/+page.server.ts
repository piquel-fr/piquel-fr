import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

/** The account settings are the whole site for now. */
export const load: PageServerLoad = () => redirect(307, '/settings');
