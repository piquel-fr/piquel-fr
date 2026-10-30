import { sveltekit } from '@sveltejs/kit/vite';

export default {
  plugins: [
    sveltekit({
      // Auth posts back-channel logout from its servers, with no `Origin`, which
      // SvelteKit's own check refuses: hooks.server.ts checks every other form post.
      csrf: { trustedOrigins: ['*'] }
    })
  ]
};
