import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  plugins: [tsconfigPaths()], // Active le plugin pour les alias
  test: {
    globals: true, // Permet d'utiliser describe, it, etc. sans import
    environment: 'node', // Environnement de test Node.js
    setupFiles: ['./tests/setup.ts'], // Fichier de configuration global pour les tests (optionnel)
    coverage: {
      provider: 'v8', // Ou 'istanbul'
      reporter: ['text', 'json', 'html'], // Rapports de couverture
      exclude: [
        // Exclure certains fichiers de la couverture
        'node_modules/**',
        'dist/**',
        'src/config/**',
        'src/database/**',
        'src/lib/logger.ts',
        'src/server.ts',
        'src/app.ts', // Souvent difficile à tester unitairement en entier
        'src/common/errors/**',
        '**/*.d.ts',
        'tests/**',
      ],
    },
    // Si vous séparez les tests E2E:
    // include: ['tests/unit/**/*.test.ts', 'tests/integration/**/*.test.ts'],
  },
});

// Optionnel: Créez vitest.config.e2e.ts si vous voulez une config séparée
// import { defineConfig, mergeConfig } from 'vitest/config'
// import viteConfig from './vitest.config'
//
// export default mergeConfig(viteConfig, defineConfig({
//   test: {
//     include: ['tests/e2e/**/*.test.ts'],
//     setupFiles: ['./tests/e2e-setup.ts'], // Setup spécifique E2E si besoin
//     // Peut nécessiter un timeout plus long pour les tests E2E
//     testTimeout: 30000, // 30 secondes
//   },
// }))
