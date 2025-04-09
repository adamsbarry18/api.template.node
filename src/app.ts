import os from 'os';
import express, { Express, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import passport from 'passport';
import swaggerUi from 'swagger-ui-express';
import compression from 'compression';
import cookieParser from 'cookie-parser';

// Utilisation des types étendus Request/Response
import { Request, Response } from './common/http';
import config from './config';
import logger from './lib/logger';
import { errorHandler } from './common/middleware/errorHandler';
import { NotFoundError } from './common/errors/httpErrors';
import swaggerSpec from './lib/openapi';
import { configurePassport } from './config/passport';
import { jsendMiddleware } from './common/middleware/JSend';
import apiRouter from './api';
import jwtAuthentication from './common/middleware/jwtAuthentication';

const insecurePaths = [/\/api\/v1\/login/, /\/api\/v1\/password/];

const HOSTNAME = os.hostname();

// Création de l'application Express
const app: Express = express();

// --- Configuration des Middlewares ---

// Désactiver l'en-tête X-Powered-By pour des raisons de sécurité
app.disable('x-powered-by');

// Sécurité : Helmet (En-têtes de sécurité)
app.use(helmet());

// CORS : Contrôle les accès cross-origin
app.use(
  cors({
    origin: config.CORS_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  }),
);

// Performance : Compression des réponses
app.use(compression());

// Parsing : Cookies
app.use(cookieParser());

// Parsing : Body (JSON et URL-encoded)
const bodyLimit = '5mb';
app.use(express.json({ limit: bodyLimit }));
app.use(express.urlencoded({ extended: true, limit: bodyLimit }));

// Logging : Requêtes HTTP (Middleware Personnalisé)
app.use((req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();
  const ip = req.ip || req.socket.remoteAddress;
  const { method, originalUrl } = req;

  res.on('finish', () => {
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

// Standardisation des réponses : JSend
// Attache res.jsend.success, res.jsend.fail, res.jsend.error
app.use(jsendMiddleware);

// Headers personnalisés
app.use((req: Request, res: Response, next: NextFunction) => {
  res.header('X-Server', HOSTNAME);
  res.header('X-Env', config.NODE_ENV || 'development');
  // Récupérer la version depuis package.json serait mieux
  res.header('X-App-Version', process.env.npm_package_version || 'local');
  next();
});

// Authentification : Passport
configurePassport();
app.use(passport.initialize());

// --- Routes ---

// Documentation API (Swagger/OpenAPI)
app.use(
  '/api-docs',
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec, {
    customSiteTitle: 'API Documentation',
  }),
);

// Route racine (Health Check / Statut)
// Utilise res.jsend.success
app.get('/', (req: Request, res: Response) => {
  res.status(200).jsend.success({
    message: `API is running in ${config.NODE_ENV} mode`,
    timestamp: new Date().toISOString(),
    server: HOSTNAME,
    version: process.env.npm_package_version || 'local',
  });
});

// Montage du routeur API principal (/api/v1)
// Note: L'exemple utilisait un middleware JWT spécifique. Ici, on suppose que
// les stratégies Passport configurées dans configurePassport() gèrent l'authentification
// et que les middlewares d'autorisation sont appliqués dans apiRouter ou ses sous-routes.

const jwtMiddleware = (jwtAuthentication(config.JWT_SECRET) as any).unless({ path: insecurePaths });
app.use('/api/v1', apiRouter);

// --- Gestion Finale des Erreurs ---

// 404 Handler: Gère les routes non trouvées
// Utilise res.jsend.error via le errorHandler global
app.use((req: Request, res: Response, next: NextFunction) => {
  const error = new NotFoundError(
    `The requested resource was not found on this server: ${req.method} ${req.originalUrl}`,
  );
  next(error); // Passe l'erreur au gestionnaire global
});

// Gestionnaire d'Erreurs Global: Le dernier middleware
// Utilise maintenant res.jsend.error grâce aux modifications précédentes
app.use(errorHandler);

// Exporter l'instance `app` configurée
export default app;
