// Runs against the production build: `just test-web` builds it first.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { test } from 'node:test';

const authOrigin = 'https://auth.example.test';

/**
 * Starts `node build` with only the given environment, plus a free PORT, and waits
 * until it listens or exits. The server is killed after ten seconds regardless.
 */
async function serve(env: Record<string, string>) {
  const probe = createServer().listen(0);
  await once(probe, 'listening');
  const address = probe.address();
  assert(address && typeof address === 'object');
  probe.close();
  const port = String(address.port);
  const server = spawn(process.execPath, ['build'], {
    cwd: new URL('..', import.meta.url),
    env: { PATH: process.env.PATH, PORT: port, ...env },
    timeout: 10_000
  });
  const closed = once(server, 'close');
  let output = '';
  const listening = new Promise<void>((resolve) => {
    const read = (chunk: Buffer) => {
      output += chunk.toString();
      if (output.includes('Listening')) resolve();
    };
    server.stdout.on('data', read);
    server.stderr.on('data', read);
  });
  await Promise.race([listening, closed]);
  return { server, port, closed, output: () => output };
}

void test('every response carries the auth origin and security headers', async () => {
  const { server, port, closed, output } = await serve({ AUTH_ORIGIN: authOrigin });
  try {
    assert(server.exitCode === null && server.signalCode === null, output());
    for (const path of ['/', '/settings', '/healthz', '/missing']) {
      const response = await fetch(`http://localhost:${port}${path}`);
      const headers = response.headers;
      assert.match(
        headers.get('content-security-policy') ?? '',
        new RegExp(`(^|, )frame-ancestors 'none'; connect-src 'self' ${authOrigin}$`),
        path
      );
      assert.equal(headers.get('x-frame-options'), 'DENY', path);
      assert.equal(headers.get('x-content-type-options'), 'nosniff', path);
      assert.equal(headers.get('referrer-policy'), 'strict-origin-when-cross-origin', path);
      assert.equal(headers.get('strict-transport-security'), 'max-age=31536000', path);
      const html = headers.get('content-type')?.startsWith('text/html') ?? false;
      assert.equal(headers.get('cache-control'), html ? 'no-store' : null, path);
      if (path === '/settings') assert.match(await response.text(), /authOrigin:"https:\/\/auth/);
    }
  } finally {
    server.kill();
    await closed;
  }
});

void test('refuses to start without an HTTPS AUTH_ORIGIN', async () => {
  const invalid = [
    undefined,
    'http://auth.example.test',
    `${authOrigin}/`,
    'http://localhost:3000'
  ];
  for (const value of invalid) {
    const { server, closed, output } = await serve(
      value === undefined ? {} : { AUTH_ORIGIN: value }
    );
    server.kill();
    await closed;
    assert.doesNotMatch(output(), /Listening/, String(value));
    assert.match(output(), /AUTH_ORIGIN must be an https:\/\/ origin/, String(value));
    assert.equal(server.exitCode, 1, String(value));
  }
});
