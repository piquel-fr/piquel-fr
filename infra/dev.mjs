import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

// The local daemon must be able to read this checkout and the manifest repository.
const run = (program, args, options = {}) => execFileSync(program, args, {
  encoding: 'utf8', ...options,
});
const root = run('git', ['rev-parse', '--show-toplevel']).trim();
const commit = run('git', ['rev-parse', 'HEAD']).trim();
const state = resolve(root, '.piqueld');
const repository = resolve(state, 'manifest');
const ctl = process.env.PIQUELCTL ?? 'piquelctl';
const ctlArgs = ['--timeout', '20m'];
if (process.env.PIQUELD_SOCKET) ctlArgs.push('--socket', process.env.PIQUELD_SOCKET);
const mode = process.argv[2];
if (mode && mode !== '--init') throw new Error('Usage: node infra/dev.mjs [--init]');
if (!process.env.AUTH_DATABASE_URL) throw new Error('Set AUTH_DATABASE_URL to your development PostgreSQL URL (sslmode=verify-full).');

// Read configuration from HEAD too: uncommitted code and manifest edits are excluded.
const manifest = JSON.parse(run('git', ['show', `${commit}:infra/dev.json`]));
manifest.spec.manifest = {
  path: 'application.json', repository: { url: repository, branch: 'main' },
};
for (const service of manifest.spec.services) {
  service.source.repository = { url: root, branch: 'main', commit };
}
manifest.spec.services.find(service => service.name === 'auth')
  .environment.AUTH_DATABASE_URL = process.env.AUTH_DATABASE_URL;

process.umask(0o077);
mkdirSync(repository, { recursive: true });
run('git', ['init', '--quiet', '--initial-branch=main', repository]);
writeFileSync(resolve(repository, 'application.json'), JSON.stringify(manifest, null, 2) + '\n');
run('git', ['-C', repository, 'add', 'application.json']);
run('git', ['-C', repository, '-c', 'user.name=piquel-fr dev',
  '-c', 'user.email=dev@localhost', '-c', 'commit.gpgsign=false',
  'commit', '--quiet', '--allow-empty', '-m', `Deploy ${commit}`]);

if (mode === '--init') {
  // piquelctl apply accepts TOML; repository retrieval also accepts JSON.
  const path = resolve(state, 'bootstrap.toml');
  writeFileSync(path, `api_version = ${JSON.stringify(manifest.api_version)}
kind = ${JSON.stringify(manifest.kind)}
[metadata]
name = ${JSON.stringify(manifest.metadata.name)}
[spec.manifest]
path = "application.json"
[spec.manifest.repository]
url = ${JSON.stringify(repository)}
branch = "main"
`);
  run(ctl, [...ctlArgs, 'apply', '--file', path, '--yes'], { stdio: 'inherit' });
}
console.log(`Deploying ${commit} to ${manifest.metadata.name}`);
run(ctl, [...ctlArgs, 'deploy', manifest.metadata.name, '--yes'], { stdio: 'inherit' });
