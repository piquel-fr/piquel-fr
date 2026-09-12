import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/browser',
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  timeout: 60_000,
  use: {
    baseURL: process.env.E2E_AUTH_URL ?? 'http://localhost:3000',
    // Authentication artifacts must never be included in screenshots or traces.
    trace: 'off', screenshot: 'off', video: 'off',
    launchOptions: { executablePath: process.env.CHROMIUM_EXECUTABLE },
    ignoreHTTPSErrors: Boolean(process.env.E2E_ALLOW_SELF_SIGNED_TLS)
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }]
});
