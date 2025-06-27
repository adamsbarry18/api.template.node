import request from 'supertest';
import { beforeAll, afterAll } from 'vitest';

import app from '@/app';
import { Errors } from '@/common/errors/httpErrors';
import { appDataSource } from '@/database/data-source';
import { redisClient, initializeRedis } from '@/lib/redis';
import logger from '@/lib/logger';

export const adminCredentials = {
  email: 'user.test1@example.com',
  password: 'Password123!',
};
export let adminToken: string;
beforeAll(async () => {
  // Assume DB and Redis are ready (docker-compose + test-with-clean-db.sh)

  if (!appDataSource.isInitialized) {
    logger.info('Initializing shared connections...');
    await appDataSource.initialize();
  }
  if (!redisClient?.isReady) {
    await initializeRedis();
  }

  // Login admin and get token
  const loginRes = await request(app).post('/api/v1/auth/login').send(adminCredentials);
  const token = loginRes.body?.data?.token;
  if (loginRes.status !== 200 || !token) {
    throw new Errors.AuthenticateError('Admin login failed in global setup');
  }
  adminToken = token;
}, 20000);

afterAll(async () => {
  if (appDataSource.isInitialized) {
    await appDataSource.destroy();
  }
});
