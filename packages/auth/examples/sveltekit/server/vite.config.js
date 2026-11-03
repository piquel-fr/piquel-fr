import { sveltekit } from '@sveltejs/kit/vite';

export default {
  plugins: [
    sveltekit({
      // Auth posts back-channel logout from its servers, with no `Origin`, which
      // SvelteKit's own check refuses: login.session in hooks.server.ts refuses
      // every other unsafe request from another site.
      csrf: { trustedOrigins: ['*'] }
    })
  ]
};
