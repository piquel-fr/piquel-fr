// Type-aware lint rules for every TypeScript, Svelte and JavaScript file in the
// workspace. Formatting is Prettier's job, so conflicting style rules are off.
import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import svelte from 'eslint-plugin-svelte';
import { defineConfig } from 'eslint/config';
import ts from 'typescript-eslint';

export default defineConfig(
  {
    ignores: ['**/build/', '**/.svelte-kit/', 'target/', 'test-results/', 'playwright-report/']
  },
  js.configs.recommended,
  ts.configs.strictTypeChecked,
  ts.configs.stylisticTypeChecked,
  svelte.configs.recommended,
  prettier,
  svelte.configs.prettier,
  {
    languageOptions: {
      parserOptions: {
        // Each file uses its nearest tsconfig.json. Svelte configs are outside
        // SvelteKit's generated project, so they use the default project.
        projectService: { allowDefaultProject: ['apps/*/svelte.config.js'] },
        extraFileExtensions: ['.svelte'],
        tsconfigRootDir: import.meta.dirname
      }
    },
    rules: {
      // TypeScript already reports undefined identifiers, including browser and
      // Node globals, so ESLint's environment-unaware check only adds noise.
      'no-undef': 'off'
    }
  },
  {
    files: ['**/*.svelte'],
    languageOptions: { parserOptions: { parser: ts.parser } }
  }
);
