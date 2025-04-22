import http from 'http';
import os from 'os';

import app from './app'; 
import config from './config'; 
import logger from './lib/logger'; 
import { AppDataSource } from './database/data-source'; 
import { initializeRedis, getRedisClient } from './lib/redis';


const hostname = os.hostname();
const READINESS_PROBE_DELAY_MS = 15 * 1000; 
const SHUTDOWN_TIMEOUT_MS = 10 * 1000; 

let server: http.Server;
let isShuttingDown = false; 

// --- Gestion Globale des Erreurs Processus Node ---
process.on('unhandledRejection', (reason: unknown, promise: Promise<unknown>) => {
  logger.fatal({ promise, reason }, '💥 Unhandled Rejection at Promise. Forcing shutdown...');
  // Tenter un arrêt propre, mais forcer après un délai
  gracefulShutdown('unhandledRejection').catch(() => process.exit(1)); // Ne pas laisser une erreur ici empêcher la sortie
  setTimeout(() => {
    logger.fatal('Graceful shutdown timed out after unhandledRejection. Forcing exit.');
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);
});

process.on('uncaughtException', (error: Error) => {
  logger.fatal(error, '💥 Uncaught Exception thrown. Forcing shutdown...');
  // Tenter un arrêt propre, mais forcer après un délai (l'état peut être corrompu)
  gracefulShutdown('uncaughtException').catch(() => process.exit(1));
  setTimeout(() => {
    logger.fatal('Graceful shutdown timed out after uncaughtException. Forcing exit.');
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);
});

/**
 * Initialise les connexions externes (BDD, Redis, etc.).
 * @throws {Error} Si une initialisation critique échoue.
 */
async function initializeExternalConnections(): Promise<void> {
  logger.info('Initializing external connections...');
  try {
    // 1. TypeORM (Critique)
    if (!AppDataSource.isInitialized) {
      await AppDataSource.initialize();
      logger.info('✅ TypeORM DataSource initialized successfully.');
    } else {
      logger.info('ℹ️ TypeORM DataSource was already initialized.');
    }

    // 2. Redis (Non critique pour le démarrage de base, mais log l'erreur)
    try {
      await initializeRedis();
      if (getRedisClient()?.isOpen) {
        logger.info('✅ Redis connection initialized successfully.');
      } else {
        logger.warn('⚠️ Redis connection failed or unavailable during initialization.');
      }
    } catch (redisError: unknown) {
      logger.error({ err: redisError }, '❌ Error during Redis initialization.');
    }


    logger.info('External connections initialization complete.');
  } catch (error: unknown) {
    logger.fatal(
      { err: error },
      '❌ Critical error during external connections initialization. Exiting.',
    );
    throw error; 
  }
}

/**
 * Gère l'arrêt propre de l'application.
 * @param signal Le signal reçu ou la raison de l'arrêt.
 */
async function gracefulShutdown(signal: NodeJS.Signals | string): Promise<void> {
  if (isShuttingDown) {
    logger.warn(`Shutdown already in progress. Received another signal: ${signal}`);
    return;
  }
  isShuttingDown = true;
  logger.warn(`Received ${signal}. Starting graceful shutdown at ${new Date().toISOString()}...`);
  // setStatus('stopping'); // Si vous avez un système de statut

  // 1. Arrêter le serveur HTTP d'accepter de nouvelles connexions
  if (server) {
    logger.info('Closing HTTP server...');
    server.close((err?: Error) => {
      if (err) {
        logger.error({ err }, 'Error closing HTTP server.');
        // Continuer quand même l'arrêt des connexions
      } else {
        logger.info('✅ HTTP server closed.');
      }
    });
  } else {
    logger.info('HTTP server was not running.');
  }

  // 2. Attendre un délai (pour les sondes K8s readiness) AVANT de fermer les connexions BDD/Redis
  logger.info(`Waiting ${READINESS_PROBE_DELAY_MS / 1000} seconds before closing connections...`);
  await new Promise((resolve) => setTimeout(resolve, READINESS_PROBE_DELAY_MS));

  // 3. Fermer les connexions externes
  logger.info('Closing external connections...');
  let exitCode = 0;

  const closePromises = [];

  // TypeORM
  if (AppDataSource.isInitialized) {
    closePromises.push(
      AppDataSource.destroy()
        .then(() => logger.info('  -> TypeORM connection closed.'))
        .catch((dbError: unknown) => {
          logger.error({ err: dbError }, 'Error closing TypeORM connection.');
          exitCode = 1;
        }),
    );
  }

  // Redis
  const redisClientInstance = getRedisClient();
  if (redisClientInstance) {
    closePromises.push(
      redisClientInstance
        .quit() // Appeler .quit() sur l'instance
        .then(() => logger.info('  -> Redis connection closed.'))
        .catch((redisError: unknown) => {
          logger.error({ err: redisError }, 'Error closing Redis connection.');
          exitCode = 1; // Marquer comme erreur, mais ne pas empêcher la sortie
        }),
    );
  } else {
    logger.info('  -> Redis client was not initialized or already closed.');
  }

  // Attendre la fin de toutes les fermetures
  await Promise.allSettled(closePromises);

  logger.info(`🏁 Graceful shutdown finished. Exiting with code ${exitCode}.`);
  process.exit(exitCode);
}

/**
 * Fonction principale asynchrone pour démarrer le serveur.
 */
async function startServer(): Promise<void> {
  logger.info('=======================================================');
  logger.info(
    `🚀 Starting Application [${config.NODE_ENV}] on ${hostname} (PID: ${process.pid})...`,
  );
  logger.info('=======================================================');
  

  // Initialiser les connexions externes AVANT de démarrer le serveur HTTP
  await initializeExternalConnections();

  server = http.createServer(app);

  server.on('error', (error: NodeJS.ErrnoException) => {
    logger.fatal({ err: error }, '❌ HTTP server error');
    if (error.syscall !== 'listen') {
      gracefulShutdown('serverError').catch(() => process.exit(1)); 
      return; 
    }
    switch (error.code) {
      case 'EACCES':
        logger.fatal(`Port ${config.PORT} requires elevated privileges. Exiting.`);
        break;
      case 'EADDRINUSE':
        logger.fatal(`Port ${config.PORT} is already in use. Exiting.`);
        break;
      default:
        logger.fatal(`Unhandled listen error: ${error.code}. Exiting.`);
    }
    process.exit(1); 
  });

  server.listen(config.PORT, config.HOST, () => {
    const redisClient = getRedisClient();
    const apiUrl = config.API_URL || `http://${config.HOST}:${config.PORT}`;

    logger.info('=======================================================');
    logger.info(`✅ Server listening on http://${config.HOST}:${config.PORT}`);
    logger.info(`✅ API Docs available at ${apiUrl}/api-docs`);
    logger.info(`   Environment: ${config.NODE_ENV}`);
    logger.info(`   Database: ${config.DB_TYPE} on ${config.DB_HOST}:${config.DB_PORT}:${config.DB_NAME} (${AppDataSource.isInitialized ? 'Connected' : 'Disconnected'})`);
    logger.info(`   Redis: ${redisClient?.isOpen ? 'Connected' : 'Disconnected'} to ${config.REDIS_HOST}:${config.REDIS_PORT}`);
    logger.info('=======================================================');
    
  });

  // Attacher les handlers de signaux pour le graceful shutdown
  const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGQUIT'];
  signals.forEach((signal) => {
    process.on(signal, () => gracefulShutdown(signal));
  });
}

// --- Démarrage de l'Application ---
startServer().catch((error: unknown) => {
  logger.fatal({ err: error }, '💥 Critical error during server startup sequence. Exiting.');
  process.exit(1);
});
