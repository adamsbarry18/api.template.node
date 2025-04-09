// src/server.ts
import http from 'http';
import os from 'os';

import app from './app'; // Assurez-vous que app.ts est bien à la racine de src
import config from './config'; // Chemin corrigé
import logger from './lib/logger'; // Chemin corrigé
import { AppDataSource } from './database/data-source'; // Chemin corrigé
import { initializeRedis, getRedisClient } from './lib/redis'; // Chemin corrigé
// import { KeycloakService } from './lib/keycloak.service'; // Si utilisé

const hostname = os.hostname();
const READINESS_PROBE_DELAY_MS = 15 * 1000; // Renommé pour clarté (millisecondes)
const SHUTDOWN_TIMEOUT_MS = 10 * 1000; // Timeout pour forcer l'arrêt si graceful shutdown prend trop de temps

let server: http.Server;
let isShuttingDown = false; // Flag pour éviter les arrêts multiples

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
        // Vérifier si la connexion est ouverte
        logger.info('✅ Redis connection initialized successfully.');
      } else {
        logger.warn('⚠️ Redis connection failed or unavailable during initialization.');
      }
    } catch (redisError: unknown) {
      logger.error({ err: redisError }, '❌ Error during Redis initialization.');
      // Ne pas bloquer le démarrage, mais logger l'erreur
    }

    // 3. Autres initialisations (Keycloak, AWS SDK, etc.)
    // ... (ajouter ici si nécessaire, gérer les erreurs de manière appropriée)
    /* Exemple Keycloak:
    if (config.KEYCLOAK_ENABLED) {
        try {
            const keycloakServiceInstance = await KeycloakService.getInstance();
            await keycloakServiceInstance.initialize(); // Assumer qu'initialize gère la redondance
            if (keycloakServiceInstance.isServiceReady()) {
                logger.info('✅ Keycloak Service initialized and ready.');
            } else {
                 logger.warn('⚠️ Keycloak Service failed to initialize.');
            }
        } catch (keycloakError: unknown) {
            logger.error({ err: keycloakError }, '❌ Error during Keycloak Service initialization.');
        }
    } else {
        logger.info('ℹ️ Keycloak integration is disabled.');
    }
    */

    logger.info('External connections initialization complete.');
  } catch (error: unknown) {
    logger.fatal(
      { err: error },
      '❌ Critical error during external connections initialization. Exiting.',
    );
    throw error; // Relancer pour être attrapé par le startServer catch
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

  // Créer et démarrer le serveur HTTP
  server = http.createServer(app);

  server.on('error', (error: NodeJS.ErrnoException) => {
    logger.fatal({ err: error }, '❌ HTTP server error');
    if (error.syscall !== 'listen') {
      gracefulShutdown('serverError').catch(() => process.exit(1)); // Tenter un arrêt propre
      return; // Ne pas continuer si ce n'est pas une erreur d'écoute
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
    process.exit(1); // Quitter immédiatement pour les erreurs d'écoute critiques
  });

  server.listen(config.PORT, config.HOST, () => {
    logger.info('=======================================================');
    logger.info(`✅ Server listening on http://${config.HOST}:${config.PORT}`);
    logger.info(
      `✅ API Docs available at ${config.API_URL || `http://${config.HOST}:${config.PORT}`}/api-docs`,
    );
    logger.info(`   Environment: ${config.NODE_ENV}`);
    const redisClient = getRedisClient();
    logger.info(`   Redis: ${redisClient?.isOpen ? 'Connected' : 'Disconnected'}`);
    // logger.info(`   Keycloak: ${keycloakServiceInstance?.isServiceReady() ? 'Ready' : (config.KEYCLOAK_ENABLED ? 'Not Ready' : 'Disabled')}`);
    logger.info('=======================================================');
    // setStatus('running'); // Si vous avez un système de statut
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
