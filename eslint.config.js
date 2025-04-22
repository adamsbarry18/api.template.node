// ESLint configuration for a TypeScript (Node.js) project (ESLint v9+)
import tseslint from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';

export default {
  ignores: ['dist', 'node_modules', 'vitest.config.mts'],
  files: ['src/**/*.ts'],
  languageOptions: {
    parser: tsParser,
    parserOptions: {
      project: './tsconfig.json',
      sourceType: 'module',
      ecmaVersion: 2022,
    },
  },
  plugins: {
    '@typescript-eslint': tseslint,
  },
  rules: {
    // Place your custom rules here, or leave empty for defaults
    'no-unused-vars': 'off',
    '@typescript-eslint/no-unused-vars': 'warn',
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/no-explicit-any': 'off',
  },
};
