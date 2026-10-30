import { redirect, type ServerLoad } from '@sveltejs/kit';

/** Every page under (app) needs a signed-in user. */
export const load: ServerLoad = ({ locals, url }) => {
  if (!locals.user) {
    redirect(303, `/auth/login?return_to=${encodeURIComponent(url.pathname + url.search)}`);
  }
  return { name: locals.user.name };
};
