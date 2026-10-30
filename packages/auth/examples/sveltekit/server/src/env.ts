import { defineEnvVars } from '@sveltejs/kit/env';

/** The settings hooks.server.ts reads from `$app/env/private`; SvelteKit starts only with them set. */
export const variables = defineEnvVars({
  AUTH_CLIENT_ID: { description: 'The client ID registered at auth.piquel.fr' },
  AUTH_CLIENT_SECRET: { description: 'The client secret' },
  ORIGIN: { description: 'This app’s origin, such as https://notes.example' }
});
