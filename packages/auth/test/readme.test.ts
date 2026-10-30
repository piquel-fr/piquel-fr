/** The README's code that a type-checked file backs. */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

test("the README's SvelteKit hook is the one examples/sveltekit type-checks", async () => {
  const read = (path: string) => readFile(new URL(path, import.meta.url), 'utf8');
  const readme = await read('../README.md');
  const hook = await read('../examples/sveltekit/server/src/hooks.server.ts');
  assert.ok(readme.includes('```ts\n' + hook.trimEnd() + '\n```'));
});
