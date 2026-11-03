// Runs smoke.js under workerd, the Cloudflare Workers runtime: writes a config
// naming every module by its path from the repository root, then `workerd test`.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../../../..');
const files = [
  'packages/auth/test/smoke/smoke.js',
  ...readdirSync(join(root, 'packages/auth/dist'))
    .filter((name) => name.endsWith('.js'))
    .map((name) => `packages/auth/dist/${name}`)
];
const json = [
  'tests/sdk-vectors/discovery/valid.json',
  'tests/sdk-vectors/tokens/access-valid.json'
];
const directory = mkdtempSync(join(tmpdir(), 'piquel-auth-smoke-'));
const embed = (file) => JSON.stringify(relative(directory, join(root, file)));
const modules = [
  ...files.map((file) => `(name = ${JSON.stringify(file)}, esModule = embed ${embed(file)})`),
  ...json.map((file) => `(name = ${JSON.stringify(file)}, json = embed ${embed(file)})`)
];
const config = join(directory, 'smoke.capnp');
writeFileSync(
  config,
  `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [(name = "smoke", worker = (
    modules = [${modules.join(', ')}],
    compatibilityDate = "2026-10-01"
  ))]
);
`
);
const { status } = spawnSync('workerd', ['test', config], { stdio: 'inherit' });
rmSync(directory, { recursive: true });
process.exit(status ?? 1);
