import os from 'os';
import express, { Express, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import passport from 'passport';
import swaggerUi from 'swagger-ui-express';
import compression from 'compression';
import cookieParser from 'cookie-parser';

// Types and Configuration
import { Request, Response } from './config/http';
import config from '@/config';
import logger from '@/lib/logger';
import swaggerSpec from '@/lib/openapi';

// Middleware and Handlers
import { errorHandler } from '@/common/middleware/errorHandler';
import { jsendMiddleware } from '@/common/middleware/JSend';
import { initializePassportAuthentication } from './common/middleware/authentication';

// Main API Router
import apiRouter from '@/api'; // Imports the router defined in api/index.ts

// HTTP Errors
import { NotFoundError } from '@/common/errors/httpErrors';

// Constants
const HOSTNAME = os.hostname();

// Create Express application
const app: Express = express();

// --- Essential Middleware Configuration ---

app.disable('x-powered-by'); // Security: Hide technology stack
app.use(helmet()); // Security: Set various HTTP headers

// CORS (Cross-Origin Resource Sharing)
app.use(
  cors({
    origin: config.CORS_ORIGIN, // Configure allowed origins
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    // IMPORTANT: 'Authorization' must be allowed for Bearer tokens
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  }),
);

app.use(compression()); // Performance: Gzip compression
app.use(cookieParser()); // Parse Cookies

// Request Body Parsing
const bodyLimit = '5mb'; // Size limit for JSON and URL-encoded bodies
app.use(express.json({ limit: bodyLimit }));
app.use(express.urlencoded({ extended: true, limit: bodyLimit }));

// --- Custom Middlewares ---

// HTTP Request Logging
app.use((req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();
  const ip = req.ip || req.socket.remoteAddress;
  const { method, originalUrl } = req;

  res.on('finish', () => {
    // Do not log requests for Swagger docs itself
    if (originalUrl.startsWith('/api-docs')) {
      return;
    }
    const duration = Date.now() - start;
    const { statusCode } = res;
    const host = req.headers.host || config.HOST || 'localhost';
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

// Response Standardization (JSend)
app.use(jsendMiddleware);

// Custom Headers (Server, Env, Version)
app.use((req: Request, res: Response, next: NextFunction) => {
  res.header('X-Server', HOSTNAME);
  res.header('X-Env', config.NODE_ENV || 'development');
  res.header('X-App-Version', process.env.npm_package_version || 'local'); // Version from package.json
  next();
});

// --- Authentication Initialization (Passport) ---
initializePassportAuthentication();
app.use(passport.initialize());

// --- Route Definitions ---

// API Documentation (Swagger/OpenAPI)
app.use(
  '/api-docs',
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec, {
    customSiteTitle: 'API Documentation',
    swaggerOptions: {
      persistAuthorization: true, // Keep authorization after refresh
      defaultModelsExpandDepth: -1, // Hide models by default
      docExpansion: 'none', // Collapse all sections by default
      filter: true, // Enable filtering
    },
    customCss: '.swagger-ui .topbar { display: none }', // Hide Swagger UI top bar
  }),
);

// Root Route (Health Check / Status)
app.get('/', (req: Request, res: Response) => {
  // Use standardized JSend response
  res.status(200).jsend.success({
    message: `API is running in ${config.NODE_ENV} mode`,
    timestamp: new Date().toISOString(),
    server: HOSTNAME,
    version: process.env.npm_package_version || 'local',
  });
});

// --- Mount Main API Router ---
// Mount all routes defined in './api/index.ts' under the '/api/v1' prefix
// !! NO global authentication middleware applied here !!
// Authentication is handled at the route level via decorators and `registerRoutes`
app.use('/api/v1', apiRouter);

// --- Final Error Handling ---

// 404 Handler: Catches requests that didn't match any previous route
app.use((req: Request, res: Response, next: NextFunction) => {
  const error = new NotFoundError(
    `The requested resource was not found on this server: ${req.method} ${req.originalUrl}`,
  );
  next(error); // Pass the error to the global error handler
});

// Global Error Handler: The very last middleware
// Catches all errors passed via next(error)
app.use(errorHandler); // Use the custom error handler

// Export the configured `app` instance for the main server (e.g., src/server.ts)
export default app;
