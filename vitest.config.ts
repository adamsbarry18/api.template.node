import { defineConfig } from 'vitest/config';
import { resolve } from 'path'; // Importer resolve pour définir l'alias

// Supprimer l'importation de vite-tsconfig-paths
// const tsconfigPathsPromise = import('vite-tsconfig-paths').then(m => m.default);

// Exporter directement la configuration
export default defineConfig({
  // Supprimer le plugin tsconfigPaths()
  // plugins: [tsconfigPaths()],
  resolve: {
    alias: {
      // Définir manuellement l'alias basé sur tsconfig.json
      '@': resolve(__dirname, './src'),
    },
  },
  test: {
    globals: true, // Permet d'utiliser describe, it, etc. sans import
    environment: 'node', // Environnement de test Node.js
    // setupFiles: ['./tests/setup.ts'], // Fichier de configuration global pour les tests (optionnel) - Commenté car le fichier n'existe pas
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

// Astuce : pour lancer les tests d'un seul module :
// npm run test:module --MODULE=users

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
