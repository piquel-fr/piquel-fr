import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
export default defineConfig({
  plugins: [sveltekit()],
  server: {
    host: 'localhost',
    port: 3000,
    strictPort: true,
    headers: {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'X-Frame-Options': 'DENY',
      'Content-Security-Policy': "frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
    },
    // Keep /login itself in SvelteKit, but send /login/* (including callbacks)
    // to the same Rust handlers as production. Preserve Origin and cookies.
    proxy: {
      '^/(config|session)(/|\\?|$)|^/(health|webauthn|account|login|oauth|oidc|federation|\\.well-known)/': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: false
      }
    }
  }
});
