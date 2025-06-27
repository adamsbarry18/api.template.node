// ESLint configuration for Node.js Express TypeScript project (ESLint v9+)
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import importPlugin from 'eslint-plugin-import';
import nodePlugin from 'eslint-plugin-n';
import securityPlugin from 'eslint-plugin-security';

export default tseslint.config(
  // Base recommended configurations
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,

  {
    // Global ignores
    ignores: [
      'api/**',
      'dist/**',
      'build/**',
      'coverage/**',
      'node_modules/**',
      '*.d.ts',
      '**/*.js', // Ignore compiled JS files
      'eslint.config.js',
      'jest.config.js',
      'vitest.config.*',
      'vite.config.*',
      '.prettierrc.js',
    ],
  },

  {
    // Main configuration for TypeScript files
    files: ['src/**/*.{ts,tsx}', '*.ts', '*.tsx'],

    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: import.meta.dirname,
        sourceType: 'module',
        ecmaVersion: 'latest',
      },
      globals: {
        // Node.js globals
        __dirname: 'readonly',
        __filename: 'readonly',
        Buffer: 'readonly',
        console: 'readonly',
        global: 'readonly',
        process: 'readonly',
        setImmediate: 'readonly',
        clearImmediate: 'readonly',
      },
    },

    plugins: {
      '@typescript-eslint': tseslint.plugin,
      import: importPlugin,
      n: nodePlugin,
      security: securityPlugin,
    },

    settings: {
      'import/resolver': {
        typescript: {
          project: './tsconfig.json',
          alwaysTryTypes: true,
        },
        node: {
          extensions: ['.js', '.jsx', '.ts', '.tsx'],
        },
      },
      'import/parsers': {
        '@typescript-eslint/parser': ['.ts', '.tsx'],
      },
    },

    rules: {
      // === TypeScript Rules ===
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'warn',
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/consistent-type-imports': [
        'warn',
        {
          prefer: 'type-imports',
          fixStyle: 'separate-type-imports',
        },
      ],
      '@typescript-eslint/consistent-type-exports': 'warn',
      '@typescript-eslint/no-duplicate-enum-values': 'off', // eslint@typescript-eslint/no-duplicate-enum-values
      '@typescript-eslint/no-for-in-array': 'error',
      '@typescript-eslint/prefer-nullish-coalescing': 'warn',
      '@typescript-eslint/prefer-optional-chain': 'warn',
      '@typescript-eslint/strict-boolean-expressions': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off', // eslint@typescript-eslint/no-unsafe-assignment
      '@typescript-eslint/no-unsafe-call': 'warn',
      '@typescript-eslint/no-unsafe-member-access': 'off', // eslint@typescript-eslint/no-unsafe-member-access
      '@typescript-eslint/no-unsafe-return': 'warn',
      '@typescript-eslint/no-unsafe-enum-comparison': 'off', // Désactivé par demande de l'utilisateur
      '@typescript-eslint/restrict-template-expressions': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unused-expressions': 'off',
      '@typescript-eslint/no-unsafe-function-type': 'off',
      // === Import Rules ===
      /*'import/order': [
        'error',
        {
          groups: ['builtin', 'external', 'internal', 'parent', 'sibling', 'index'],
          'newlines-between': 'always',
          alphabetize: {
            order: 'asc',
            caseInsensitive: true,
          },
        },
      ],*/
      'import/no-unresolved': 'error',
      'import/named': 'error',
      'import/default': 'error',
      'import/namespace': 'error',
      'import/no-duplicates': 'error',
      'import/no-unused-modules': 'warn',
      // 'import/no-cycle': 'error',
      'import/no-self-import': 'error',
      'import/no-extraneous-dependencies': [
        'error',
        {
          devDependencies: [
            '**/*.test.{ts,js}',
            '**/*.spec.{ts,js}',
            '**/test/**',
            '**/tests/**',
            '**/__tests__/**',
            'jest.config.*',
            'vitest.config.*',
            'eslint.config.*',
          ],
        },
      ],

      // === Node.js Rules ===
      'n/no-missing-import': 'off', // Handled by TypeScript
      'n/no-unsupported-features/es-syntax': 'off', // Using TypeScript compilation
      'n/no-process-exit': 'error',
      'n/no-deprecated-api': 'error',
      'n/prefer-global/process': 'error',
      'n/prefer-global/buffer': 'error',
      'n/prefer-global/console': 'error',

      // === Security Rules ===
      'security/detect-object-injection': 'warn',
      'security/detect-non-literal-regexp': 'warn',
      'security/detect-unsafe-regex': 'error',
      'security/detect-buffer-noassert': 'error',
      'security/detect-child-process': 'warn',
      'security/detect-disable-mustache-escape': 'error',
      'security/detect-eval-with-expression': 'error',
      'security/detect-no-csrf-before-method-override': 'error',
      'security/detect-non-literal-fs-filename': 'warn',
      'security/detect-non-literal-require': 'warn',
      'security/detect-possible-timing-attacks': 'warn',
      'security/detect-pseudoRandomBytes': 'error',

      // === General JavaScript Rules ===
      'no-console': 'warn',
      'no-debugger': 'error',
      'no-alert': 'error',
      'no-var': 'error',
      'prefer-const': 'error',
      'prefer-arrow-callback': 'error',
      'arrow-spacing': 'error',
      'no-duplicate-imports': 'off', // Handled by import/no-duplicates
      'no-unused-vars': 'off', // Handled by @typescript-eslint/no-unused-vars
      'no-undef': 'off', // Handled by TypeScript
      'no-redeclare': 'off', // Handled by TypeScript
      'no-dupe-class-members': 'off', // Handled by TypeScript
      'no-prototype-builtins': 'off', // à revoir

      // === Code Quality Rules ===
      eqeqeq: ['error', 'always'],
      // curly: ['error', 'all'],
      'no-throw-literal': 'error',
      'prefer-promise-reject-errors': 'error',
      'no-return-await': 'off', // Conflicts with @typescript-eslint/return-await
      '@typescript-eslint/return-await': 'off',

      // === Naming Conventions ===
      '@typescript-eslint/naming-convention': [
        'warn',
        // Variables, functions: camelCase
        {
          selector: 'variableLike',
          format: ['camelCase'],
          leadingUnderscore: 'allow',
        },
        // Constants: UPPER_CASE or camelCase
        {
          selector: 'variable',
          modifiers: ['const'],
          format: ['camelCase', 'UPPER_CASE'],
        },
        // Functions: camelCase
        {
          selector: 'function',
          format: ['camelCase'],
        },
        // Parameters: camelCase
        {
          selector: 'parameter',
          format: ['camelCase'],
          leadingUnderscore: 'allow',
        },
        // Classes, interfaces, types, enums: PascalCase
        {
          selector: 'typeLike',
          format: ['PascalCase'],
        },
        // Class properties and methods: camelCase
        {
          selector: ['classProperty', 'classMethod'],
          format: ['camelCase'],
          leadingUnderscore: 'allow',
        },
        // Object properties: camelCase (with flexibility for API responses)
        {
          selector: 'objectLiteralProperty',
          format: ['camelCase', 'snake_case', 'UPPER_CASE', 'PascalCase'], // Ajout de PascalCase
          leadingUnderscore: 'allow',
        },
        // Type parameters: PascalCase
        {
          selector: 'typeParameter',
          format: ['PascalCase'],
        },
        // Enum members: PascalCase
        {
          selector: 'enumMember',
          format: ['PascalCase', 'UPPER_CASE'],
        },
      ],
    },
  },

  {
    // Configuration for test files
    files: ['**/*.test.{ts,tsx}', '**/*.spec.{ts,tsx}', '**/test/**/*.{ts,tsx}'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      'security/detect-object-injection': 'off',
      'no-console': 'off',
    },
  },

  {
    // Configuration for configuration files
    files: ['*.config.{ts,js}', '*.config.*.{ts,js}'],
    rules: {
      'import/no-extraneous-dependencies': 'off',
      '@typescript-eslint/no-var-requires': 'off',
    },
  },
);
