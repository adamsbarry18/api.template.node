import os from 'os';

import compression from 'compression';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import passport from 'passport';
import swaggerUi from 'swagger-ui-express';

import { initializedApiRouter } from '@/api';

import { NotFoundError } from '@/common/errors/httpErrors';
import { errorHandler } from '@/common/middleware/errorHandler';
import { jsendMiddleware } from '@/common/middleware/JSend';
import config from '@/config';
import logger from '@/lib/logger';
import swaggerSpec from '@/lib/openapi';

import { passportAuthenticationMiddleware } from './common/middleware/authentication';
import type { NextFunction, Request, Response } from './config/http';
import express from 'express';

const HOSTNAME = os.hostname();

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(
  cors({
    origin: config.CORS_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  }),
);
app.use(compression());
app.use(cookieParser());

const bodyLimit = '5mb';
app.use(express.json({ limit: bodyLimit }));
app.use(express.urlencoded({ extended: true, limit: bodyLimit }));

app.set('query parser', 'extended');

app.use((req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();
  const ip = req.ip ?? req.socket.remoteAddress;
  const { method, originalUrl } = req;

  res.on('finish', () => {
    if (originalUrl?.startsWith('/api-docs')) {
      return;
    }
    const duration = Date.now() - start;
    const { statusCode } = res;
    const host = req.headers.host ?? config.HOST ?? 'localhost';
    const protocol = req.protocol || 'http';
    const baseUrl = config.API_URL?.trim()
      ? config.API_URL.replace(/\/$/, '')
      : `${protocol}://${host}`;
    const fullUrl = `${baseUrl}${originalUrl || req.url}`;
    const logMessage = `${ip} - "${method} ${fullUrl} HTTP/${req.httpVersion}" ${statusCode} ${duration}ms`;

    if (statusCode >= 500) {
      logger.error(logMessage);
    } else if (statusCode >= 400) {
      logger.warn(logMessage);
    } else {
      logger.info(logMessage);
    }
  });
  next();
});

app.use(jsendMiddleware);

app.use((req: Request, res: Response, next: NextFunction) => {
  res.header('X-Server', HOSTNAME);
  res.header('X-Env', config.NODE_ENV || 'development');
  res.header('X-App-Version', process.env.npm_package_version ?? 'local');
  next();
});

passportAuthenticationMiddleware();
app.use(passport.initialize());

// API Documentation (Swagger/OpenAPI)
app.use(
  '/api-docs',
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec, {
    customSiteTitle: 'API Documentation',
    swaggerOptions: {
      persistAuthorization: true,
      defaultModelsExpandDepth: -1,
      docExpansion: 'none',
      filter: true,
    },
    customCss: '.swagger-ui .topbar { display: none }',
  }),
);

// Root Route (Health Check / Status)
app.get('/', (req: Request, res: Response) => {
  res.status(200).jsend.success({
    message: `API is running in ${config.NODE_ENV} mode`,
    timestamp: new Date().toISOString(),
    server: HOSTNAME,
    version: process.env.npm_package_version ?? 'local',
  });
});

(async () => {
  try {
    logger.info('Waiting for API router initialization...');
    const apiRouter = await initializedApiRouter;
    logger.info('API router initialized. Mounting routes under /api/v1...');
    app.use('/api/v1', apiRouter);
    logger.info('✅ API routes mounted successfully.');

    app.use((req: Request, res: Response, next: NextFunction) => {
      next(
        new NotFoundError(
          `The requested resource was not found on this server: ${req.method} ${req.originalUrl}`,
        ),
      );
    });

    app.use(errorHandler);
  } catch (error) {
    logger.fatal(
      { err: error },
      '❌ Failed to initialize and mount API router. Application might not function correctly.',
    );

    app.use('/api/v1', (req, res, next) => {
      next(new Error('API routes failed to initialize.'));
    });
    app.use((req: Request, res: Response, next: NextFunction) => {
      next(
        new NotFoundError(
          `The requested resource was not found on this server: ${req.method} ${req.originalUrl}`,
        ),
      );
    });
    app.use(errorHandler);
  }
})().catch((error) => {
  logger.fatal({ err: error }, '❌ Unhandled error during async app initialization.');
  throw error;
});

export default app;
