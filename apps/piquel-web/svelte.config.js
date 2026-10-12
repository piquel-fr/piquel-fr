import adapter from '@sveltejs/adapter-static';

// Without VITE_AUTH_ORIGIN, the build reads its auth origin at runtime, and the
// server narrows connect-src with its own CSP header (see infra/nginx.conf).
const authOrigin = process.env.VITE_AUTH_ORIGIN ?? 'https:';
export default {
  kit: {
    adapter: adapter(),
    csp: {
      mode: 'hash',
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
