import { parseChallenge } from '@piquel/auth';
import { error, redirect, type ServerLoad } from '@sveltejs/kit';

/** Calls an API with the user's access token, and steps up when it asks. */
export const load: ServerLoad = async ({ locals, fetch }) => {
  const user = locals.user;
  if (!user) redirect(303, '/auth/login');
  const response = await fetch('https://notes.example/notes', {
    headers: { authorization: `Bearer ${await user.accessToken()}` }
  });
  const challenge = parseChallenge(response.headers.get('www-authenticate') ?? '');
  if (challenge?.error === 'insufficient_user_authentication') {
    // Signs in again as the API asks, back to this page; once only. A form post
    // cannot leave for auth: `stepUp` answers it 401, and the page's GET steps up.
    const answer = user.stepUp(challenge);
    const location = answer.headers.get('location');
    if (location) redirect(303, location);
    error(
      answer.status,
      answer.status === 401
        ? 'This page needs a stronger sign-in: open it again.'
        : 'Signing in again did not give access to this page.'
    );
  }
  return { notes: (await response.json()) as unknown };
};
