import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    globals: true,
    environment: 'node',
    root: './',
    setupFiles: ['src/tests/globalSetup.ts'],
    include: [
      'src/modules/**/*.spec.ts',
      'src/modules/**/__tests__/**/*.ts',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: ['node_modules/**', 'dist/**', 'src/server.ts', 'src/app.ts'],
    },
    testTimeout: 20000,
    hookTimeout: 60000,
    maxConcurrency: 1
  },
});

