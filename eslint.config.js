// ESLint configuration for a TypeScript (Node.js) project (ESLint v9+)
import tseslint from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';

export default {
  ignores: [
    'dist',
    'node_modules',
    'vitest.config.mts',
    'dist/**',
    'coverage/**',
    '/build/**',
    '**/.*/',
    '/vite.config.ts',
    '*.d.ts',
    'eslint.config.js',
    '.prettierrc.js',
  ],
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
    // Désactivées car gérées par les règles @typescript-eslint équivalentes et plus précises
    'no-undef': 'off',
    'no-dupe-class-members': 'off',
    'no-prototype-builtins': 'off',
    // Place your custom rules here, or leave empty for defaults
    'no-unused-vars': 'off',
    '@typescript-eslint/no-unused-vars': 'warn',
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/no-explicit-any': 'off',
    '@typescript-eslint/explicit-module-boundary-types': 'warn', // Recommande les types pour les exports de module
    '@typescript-eslint/no-non-null-assertion': 'warn', // Avertissement pour les assertions non-null `!`
    '@typescript-eslint/no-floating-promises': 'error', // Exige la gestion des Promises (await, .then(), .catch())
    '@typescript-eslint/no-misused-promises': 'error', // Empêche l'utilisation incorrecte des Promises (ex: dans un if)
    '@typescript-eslint/consistent-type-imports': 'warn', // Préfère `import type` quand possible
    '@typescript-eslint/no-duplicate-enum-values': 'off', // Détecte les valeurs d'enum dupliquées
    '@typescript-eslint/no-for-in-array': 'error',

    // --- Conventions de Nommage ---
    '@typescript-eslint/naming-convention': [
      'warn', // Avertissement si non respecté
      // Variables, Fonctions: camelCase, UPPER_CASE (pour constantes)
      {
        selector: 'variableLike',
        format: ['camelCase', 'UPPER_CASE'],
        leadingUnderscore: 'allow',
      },
      // Paramètres de fonction: camelCase
      {
        selector: 'parameter',
        format: ['camelCase'],
        leadingUnderscore: 'allow',
      },
      // Classes, Interfaces, Types, Enums: PascalCase
      {
        selector: 'typeLike',
        format: ['PascalCase'],
      },
      // Propriétés et Méthodes d'objet/classe: camelCase
      {
        selector: ['property', 'method', 'classProperty', 'classMethod'],
        format: ['camelCase'],
        leadingUnderscore: 'allow', // Permet les propriétés privées commençant par _ si pas de #
      },
      // Propriétés d'objet littéral (si elles ne sont pas toujours en camelCase, ajustez)
      {
        selector: 'objectLiteralProperty',
        format: ['camelCase', 'PascalCase', 'UPPER_CASE', 'snake_case'], // Exemple: permettre snake_case pour clés API/DB
        leadingUnderscore: 'allow',
        filter: { regex: '(__html|__dangerouslySetInnerHTML)', match: false }, // Exclure les noms spécifiques si nécessaire
      },
      // Variables globales (constantes) : UPPER_CASE ou camelCase (selon le cas)
      {
        selector: 'variable',
        modifiers: ['global', 'const'],
        format: ['UPPER_CASE', 'camelCase'],
      },
      // Types génériques : PascalCase
      {
        selector: 'typeParameter',
        format: ['PascalCase'],
        prefix: ['T', 'K', 'V', 'E', 'U'], // Optionnel: restreindre les préfixes communs
      },
    ],
  },
};
