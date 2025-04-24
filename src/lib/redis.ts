import { createClient, type RedisClientType } from 'redis';

import config from '@/config';

import logger from './logger';

const redisUrl = `redis://${config.REDIS_HOST}:${config.REDIS_PORT}`;

let redisClient: RedisClientType;
let isRedisReady = false;

const initializeRedis = async (): Promise<void> => {
  if (isRedisReady) return;

  try {
    redisClient = createClient({
      url: redisUrl,
      password: config.REDIS_PASSWORD,
      database: config.REDIS_DB,
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
      // Envisager une stratégie de sortie ou de monitoring si Redis est critique
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

// Fonction pour obtenir le client (assure que l'initialisation est tentée)
// Note: Dans un scénario réel, il serait mieux de s'assurer que Redis est prêt
// avant d'accepter des requêtes qui en dépendent.
const getRedisClient = (): RedisClientType | null => {
  if (!redisClient || !isRedisReady) {
    logger.warn('Redis client requested but not ready or not initialized.');
    // Tenter de réinitialiser si pas déjà fait (simple tentative)
    if (!redisClient) {
      initializeRedis().catch((err) => logger.error(err, 'Error during lazy Redis initialization'));
    }
    return null; // Retourne null si pas prêt
  }
  return redisClient;
};

export { redisClient, initializeRedis, getRedisClient, isRedisReady };

// Optionnel: Exporter directement le client si vous gérez l'attente de connexion au démarrage
// export default redisClient; // Attention: pourrait être undefined au début
