module.exports = {
  parser: "@typescript-eslint/parser",
  parserOptions: {
    project: "tsconfig.json", // Important pour les règles qui nécessitent les types
    tsconfigRootDir: __dirname,
    sourceType: "module",
  },
  plugins: ["@typescript-eslint/eslint-plugin", "prettier"],
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended", // Règles recommandées pour TS
    "plugin:prettier/recommended", // Intègre Prettier avec ESLint
  ],
  root: true,
  env: {
    node: true,
    jest: true, // Ou 'vitest/globals' si vous utilisez le plugin vitest
  },
  ignorePatterns: [".eslintrc.js", "dist/", "node_modules/", "*.d.ts"],
  rules: {
    // Règles spécifiques (ajoutez/modifiez selon vos préférences)
    "@typescript-eslint/interface-name-prefix": "off",
    "@typescript-eslint/explicit-function-return-type": "warn", // Suggère de typer les retours de fonction
    "@typescript-eslint/explicit-module-boundary-types": "off", // Peut être activé pour forcer les types aux limites des modules
    "@typescript-eslint/no-explicit-any": "warn", // Rappelle d'éviter 'any'
    "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_" }], // Avertit sur les vars non utilisées (sauf si préfixées par _)
    "prettier/prettier": "error", // Signale les erreurs Prettier comme des erreurs ESLint
    "no-console": ["warn", { allow: ["warn", "error", "info"] }], // Avertit sur console.log, autorise warn/error/info
  },
  // Si vous utilisez Vitest et son plugin eslint
  // overrides: [
  //   {
  //     files: ['**/*.test.ts'],
  //     plugins: ['vitest'],
  //     extends: ['plugin:vitest/recommended'],
  //     rules: {
  //       // Règles spécifiques aux tests Vitest
  //     },
  //   },
  // ],
};
