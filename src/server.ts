import http from 'http';
import os from 'os';

import app from './app';
import config from './config';
import { appDataSource } from './database/data-source';
import logger from './lib/logger';
import { initializeRedis, getRedisClient } from './lib/redis';

/** The hostname of the machine. */
const hostname = os.hostname();
/** Delay in milliseconds before closing connections during shutdown, allowing readiness probes to fail. */
const READINESS_PROBE_DELAY_MS = 15 * 1000;
/** Timeout in milliseconds for the graceful shutdown process before forcing exit. */
const SHUTDOWN_TIMEOUT_MS = 10 * 1000;

/** The HTTP server instance. */
let server: http.Server;
/** Flag indicating if the shutdown process has started. */
let isShuttingDown = false;

/**
 * Global handler for unhandled promise rejections.
 * Logs the error and initiates a graceful shutdown.
 */
process.on('unhandledRejection', (reason: unknown, promise: Promise<unknown>) => {
  logger.fatal({ promise, reason }, '💥 Unhandled Rejection at Promise. Forcing shutdown...');
  gracefulShutdown('unhandledRejection').catch(() => process.exit(1));
  setTimeout(() => {
    logger.fatal('Graceful shutdown timed out after unhandledRejection. Forcing exit.');
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);
});

/**
 * Global handler for uncaught exceptions.
 * Logs the error and initiates a graceful shutdown.
 */
process.on('uncaughtException', (error: Error) => {
  logger.fatal(error, '💥 Uncaught Exception thrown. Forcing shutdown...');
  gracefulShutdown('uncaughtException').catch(() => process.exit(1));
  setTimeout(() => {
    logger.fatal('Graceful shutdown timed out after uncaughtException. Forcing exit.');
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);
});

/**
 * Initializes external connections (Database, Redis, etc.).
 * @throws {Error} If a critical initialization fails (e.g., database connection).
 */
async function initializeExternalConnections(): Promise<void> {
  logger.info('Initializing external connections...');
  try {
    // Initialize TypeORM (critical)
    if (!appDataSource.isInitialized) {
      await appDataSource.initialize();
      logger.info('✅ TypeORM DataSource initialized successfully.');
    } else {
      logger.info('ℹ️ TypeORM DataSource was already initialized.');
    }

    // Initialize Redis (non-critical for basic startup, log errors)
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
    throw error; // Re-throw critical errors to stop the startup process
  }
}

/**
 * Handles the graceful shutdown of the application.
 * Closes the HTTP server and external connections.
 * @param {NodeJS.Signals | string} signal - The signal received or the reason for shutdown.
 */
async function gracefulShutdown(signal: NodeJS.Signals | string): Promise<void> {
  if (isShuttingDown) {
    logger.warn(`Shutdown already in progress. Received another signal: ${signal}`);
    return;
  }
  isShuttingDown = true;
  logger.warn(`Received ${signal}. Starting graceful shutdown at ${new Date().toISOString()}...`);

  // 1. Stop the HTTP server from accepting new connections
  if (server) {
    logger.info('Closing HTTP server...');
    server.close((err?: Error) => {
      if (err) {
        logger.error({ err }, 'Error closing HTTP server.');
      } else {
        logger.info('✅ HTTP server closed.');
      }
    });
  } else {
    logger.info('HTTP server was not running.');
  }

  // 2. Wait for a delay (e.g., for K8s readiness probes) BEFORE closing DB/Redis connections
  logger.info(`Waiting ${READINESS_PROBE_DELAY_MS / 1000} seconds before closing connections...`);
  await new Promise((resolve) => setTimeout(resolve, READINESS_PROBE_DELAY_MS));

  // 3. Close external connections
  logger.info('Closing external connections...');
  let exitCode = 0;
  const closePromises = [];

  // Close TypeORM connection
  if (appDataSource.isInitialized) {
    closePromises.push(
      appDataSource.destroy()
        .then(() => logger.info('  -> TypeORM connection closed.'))
        .catch((dbError: unknown) => {
          logger.error({ err: dbError }, 'Error closing TypeORM connection.');
          exitCode = 1;
        }),
    );
  }

  // Close Redis connection
  const redisClientInstance = getRedisClient();
  if (redisClientInstance) {
    closePromises.push(
      redisClientInstance
        .quit()
        .then(() => logger.info('  -> Redis connection closed.'))
        .catch((redisError: unknown) => {
          logger.error({ err: redisError }, 'Error closing Redis connection.');
          exitCode = 1;
        }),
    );
  } else {
    logger.info('  -> Redis client was not initialized or already closed.');
  }

  // Wait for all close operations to settle
  await Promise.allSettled(closePromises);

  logger.info(`🏁 Graceful shutdown finished. Exiting with code ${exitCode}.`);
  process.exit(exitCode);
}

/**
 * Main asynchronous function to start the server.
 * Initializes connections, creates the HTTP server, and starts listening.
 */
async function startServer(): Promise<void> {
  logger.info('=======================================================');
  logger.info(
    `🚀 Starting Application [${config.NODE_ENV}] on ${hostname} (PID: ${process.pid})...`,
  );
  logger.info('=======================================================');

  // Initialize external connections BEFORE starting the HTTP server
  await initializeExternalConnections();

  // Create HTTP server
  // eslint-disable-next-line @typescript-eslint/no-misused-promises
  server = http.createServer(app);

  // Handle server errors (e.g., port in use)
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
    process.exit(1); // Exit immediately for listen errors
  });

  // Start listening for connections
  server.listen(config.PORT, config.HOST, () => {
    const redisClient = getRedisClient();
    const apiUrl = config.API_URL || `http://${config.HOST}:${config.PORT}`;

    logger.info('=======================================================');
    logger.info(`✅ Server listening on http://${config.HOST}:${config.PORT}`);
    logger.info(`✅ API Docs available at ${apiUrl}/api-docs`);
    logger.info(`   Environment: ${config.NODE_ENV}`);
    logger.info(
      `   Database: ${config.DB_TYPE} on ${config.DB_HOST}:${config.DB_PORT}:${config.DB_NAME} (${appDataSource.isInitialized ? 'Connected' : 'Disconnected'})`,
    );
    logger.info(
      `   Redis: ${redisClient?.isOpen ? 'Connected' : 'Disconnected'} to ${config.REDIS_HOST}:${config.REDIS_PORT}`,
    );
    logger.info('=======================================================');
  });

  // Attach signal handlers for graceful shutdown
  const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGQUIT'];
  signals.forEach((signal) => {
    process.on(signal, () => {
      void gracefulShutdown(signal);
    });
  });
}

// --- Application Startup ---
startServer().catch((error: unknown) => {
  logger.fatal({ err: error }, '💥 Critical error during server startup sequence. Exiting.');
  process.exit(1);
});
