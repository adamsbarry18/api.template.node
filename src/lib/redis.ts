import { createClient, type RedisClientType } from 'redis';

import config from '@/config';

import logger from './logger';

let redisClient: RedisClientType;
let isRedisReady = false;

const initializeRedis = async (): Promise<void> => {
  if (isRedisReady) return;

  try {
    redisClient = createClient({
      url: config.REDIS_URL,
      socket: {
        connectTimeout: 5000,
        reconnectStrategy: (retries) => Math.min(retries * 50, 1000),
      },
    });

    redisClient.on('connect', () => {
      logger.info('Connecting to Redis...');
    });

    redisClient.on('ready', () => {
      isRedisReady = true;
      logger.info('Redis client ready.');
    });

    redisClient.on('error', (err) => {
      isRedisReady = false;
      logger.error(err, 'Redis client error');
    });

    redisClient.on('end', () => {
      isRedisReady = false;
      logger.warn('Redis client connection ended.');
    });

    await redisClient.connect();
  } catch (error) {
    logger.error(error, 'Failed to initialize Redis connection.');
  }
};

const getRedisClient = (): RedisClientType | null => {
  if (!redisClient || !isRedisReady) {
    logger.warn('Redis client requested but not ready or not initialized.');
    if (!redisClient) {
      initializeRedis().catch((err) => logger.error(err, 'Error during lazy Redis initialization'));
    }
    return null;
  }
  return redisClient;
};

export { redisClient, initializeRedis, getRedisClient, isRedisReady };
