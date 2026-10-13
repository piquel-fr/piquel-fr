import adapter from '@sveltejs/adapter-node';

// Builds run without AUTH_ORIGIN, since one image serves every environment: the
// server narrows connect-src to its runtime auth origin with a second CSP header
// (see src/hooks.server.ts). `just dev` sets it, so the development CSP allows the
// local auth service too.
const authOrigin = process.env.AUTH_ORIGIN ?? 'https:';
export default {
  kit: {
    adapter: adapter(),
    csp: {
      mode: 'auto',
      directives: {
        'default-src': ['self'],
        'script-src': ['self'],
        'style-src': ['self', 'unsafe-inline'],
        'connect-src': ['self', authOrigin],
        'object-src': ['none'],
        'base-uri': ['none'],
        'form-action': ['self']
      }
    }
  }
};
