import { beforeAll, afterAll } from 'vitest';
import { initializedApiRouter } from '@/api/index';
import { AppDataSource } from '@/database/data-source';
import logger from '@/lib/logger';
import request from 'supertest';
import app from '@/app';

// Export admin credentials and token for use in tests
export const adminCredentials = {
  email: 'mabarry2018@gmail.com',
  password: '123456PAM$45789asdss',
};
export let adminToken: string;

// Increase timeout for beforeAll hook
beforeAll(async () => {
  logger.info('Executing global test setup...');
  try {
    // 1. Initialize Database Connection
    if (!AppDataSource.isInitialized) {
      logger.info('Initializing TypeORM DataSource for tests...');
      await AppDataSource.initialize();
      logger.info('Database initialized.');
    }

    // Pas de dropDatabase, pas de synchronize, pas de chargement SQL ici

    // 2. Wait for API router
    logger.info('Waiting for dynamic route registration...');
    await initializedApiRouter;
    logger.info('✅ Dynamic routes registration complete.');

    // Admin login for tests
    try {
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .send(adminCredentials);

      const token = loginRes.body?.data?.token;
      if (loginRes.status !== 200 || !token) {
        logger.error(
          { status: loginRes.status, body: loginRes.body },
          'Admin login failed: response details'
        );
        throw new Error('Admin login failed in global setup');
      }
      adminToken = token;
      logger.info('✅ Admin token acquired for tests.');
    } catch (err) {
      logger.error(err, '❌ Failed to login as admin in global setup.');
      throw err;
    }

    logger.info('✅ Global test setup finished successfully.');

  } catch (error) {
    logger.error(error, '❌ Error during global test setup.');
    throw error; // Let Vitest see the actual error
  }
}, 60000); // 60 second timeout for the entire hook

/**
 * Global Teardown
 * Runs once after all test suites have finished.
 */
afterAll(async () => {
  logger.info('Executing global test teardown...');
  try {
     // Close database connection
     if (AppDataSource.isInitialized) {
       await AppDataSource.destroy();
       logger.info('✅ TypeORM DataSource destroyed.');
     }
     // Add other cleanup tasks here (e.g., close Redis connection if used)
     logger.info('✅ Global test teardown complete.');
  } catch (error) {
     logger.error(error, '❌ Error during global test teardown.');
  }
});