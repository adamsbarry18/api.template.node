import logger from '@/lib/logger';
import { InternalServerError } from '../errors/httpErrors';
import { redisClient } from '@/lib/redis';

export class RedisClient {
  private static throwIfUnavailable() {
    if (!redisClient) {
      logger.error('Redis indisponible.');
      throw new InternalServerError('Service temporairement indisponible (Redis).');
    }
  }

  static async get(key: string): Promise<string | null> {
    this.throwIfUnavailable();
    try {
      return await redisClient.get(key);
    } catch (error) {
      logger.error(`Erreur lors de la récupération de la clé ${key}: ${error}`);
      throw new InternalServerError('Erreur d’accès au cache.');
    }
  }

  static async setEx(key: string, seconds: number, value: string): Promise<void> {
    this.throwIfUnavailable();
    try {
      await redisClient.setEx(key, seconds, value);
    } catch (error) {
      logger.error(`Erreur lors de la définition de la clé ${key}: ${error}`);
      throw new InternalServerError('Erreur de mise en cache.');
    }
  }

  static async del(key: string): Promise<void> {
    this.throwIfUnavailable();
    try {
      await redisClient.del(key);
    } catch (error) {
      logger.error(`Erreur lors de la suppression de la clé ${key}: ${error}`);
      throw new InternalServerError('Erreur de suppression du cache.');
    }
  }
}
