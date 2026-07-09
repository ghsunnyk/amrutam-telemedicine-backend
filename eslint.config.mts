import js from '@eslint/js'
import { defineConfig, globalIgnores } from 'eslint/config'
import globals from 'globals'
import tseslint from 'typescript-eslint'

export default defineConfig([
  globalIgnores(['dist/**', 'node_modules/**', 'src/generated/**', 'coverage/**']),

  {
    files: ['**/*.ts', '**/*.mts'],
    plugins: { js },
    extends: ['js/recommended', tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      // This is a Node service. `globals.browser` would make `window` and `document`
      // resolve, hiding a whole class of "wrong runtime" mistakes.
      globals: globals.node,
      parserOptions: {
        // Root-level config files are outside `tsconfig.json#include`, so the project
        // service has no program for them. Let it synthesise a default one.
        projectService: { allowDefaultProject: ['*.config.ts', '*.config.mts'] },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' },
      ],
      // `any` erases the type safety the rest of the codebase depends on. At an
      // external boundary that genuinely returns unknown shapes, use `unknown` and narrow.
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports', fixStyle: 'inline-type-imports' },
      ],
      // A dropped promise in a request handler is a silently swallowed error and,
      // in a transaction, a connection leak.
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/await-thenable': 'error',
      '@typescript-eslint/no-misused-promises': ['error', { checksVoidReturn: { arguments: false } }],
      '@typescript-eslint/require-await': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/restrict-template-expressions': 'off',

      /**
       * `Math.random()` is not a CSPRNG. Its output is predictable from a handful of
       * observed values, which for a token, a hold id or a recovery code is game over.
       * The one legitimate use — jitter in retry backoff — is exempted inline.
       */
      'no-restricted-properties': [
        'error',
        {
          object: 'Math',
          property: 'random',
          message: 'Not a CSPRNG. Use node:crypto randomBytes/randomUUID for anything security-relevant.',
        },
      ],

      // `config/env.ts` must report a bad config before the logger exists.
      'no-console': ['error', { allow: ['error'] }],
      eqeqeq: ['error', 'always', { null: 'ignore' }],
    },
  },

  // Retry jitter is the one place Math.random is correct: it decorrelates sleeps and
  // has no security property. See docs/architecture.md §Retry & Backoff.
  {
    files: ['src/db/prisma.ts'],
    rules: { 'no-restricted-properties': 'off' },
  },

  // Scripts and tests are allowed to be chattier and looser.
  {
    files: ['prisma/**/*.ts', 'tests/**/*.ts', '*.config.ts', '*.config.mts'],
    rules: {
      'no-console': 'off',
      'no-restricted-properties': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-floating-promises': 'off',
    },
  },
])
