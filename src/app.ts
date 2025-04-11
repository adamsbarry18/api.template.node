import os from 'os';
import express, { Express, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import passport from 'passport'; // Import Passport
import swaggerUi from 'swagger-ui-express';
import compression from 'compression';
import cookieParser from 'cookie-parser';

// Types et Configuration
import { Request, Response } from './common/http'; // Vos types étendus
import config from '@/config';
import logger from '@/lib/logger';
import swaggerSpec from '@/lib/openapi'; // Ou './lib/swagger' selon le nom de fichier réel

// Middlewares et Gestionnaires
import { errorHandler } from '@/common/middleware/errorHandler';
import { jsendMiddleware } from '@/common/middleware/JSend'; // Middleware JSend
import { configurePassport } from '@/config/passport'; // Configuration de Passport JWT

// Routeur API Principal
import apiRouter from '@/api'; // Importe le routeur défini dans api/index.ts

// Erreurs HTTP
import { NotFoundError } from '@/common/errors/httpErrors';

// Constantes
const HOSTNAME = os.hostname();
// const insecurePaths = [...] // N'est plus nécessaire ici, géré par l'absence de @authorize sur les routes publiques

// Création de l'application Express
const app: Express = express();

// --- Configuration des Middlewares Essentiels ---

app.disable('x-powered-by'); // Sécurité
app.use(helmet()); // Sécurité (Headers HTTP)

// CORS (Cross-Origin Resource Sharing)
app.use(
  cors({
    origin: config.CORS_ORIGIN, // Configurer les origines autorisées
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    // IMPORTANT: 'Authorization' doit être autorisé pour les Bearer tokens
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  }),
);

app.use(compression()); // Performance (Compression Gzip)
app.use(cookieParser()); // Parsing des Cookies

// Parsing du Corps des Requêtes (Body)
const bodyLimit = '5mb'; // Limite de taille pour JSON et URL-encoded
app.use(express.json({ limit: bodyLimit }));
app.use(express.urlencoded({ extended: true, limit: bodyLimit }));

// --- Middlewares Personnalisés ---

// Logging des Requêtes HTTP
app.use((req: Request, res: Response, next: NextFunction) => {
  // (Code du middleware de logging inchangé)
  const start = Date.now();
  const ip = req.ip || req.socket.remoteAddress;
  const { method, originalUrl } = req;

  res.on('finish', () => {
    // Ne pas logger les requêtes pour la doc Swagger elle-même
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

// Standardisation des Réponses (JSend)
app.use(jsendMiddleware);

// Headers Personnalisés (Server, Env, Version)
app.use((req: Request, res: Response, next: NextFunction) => {
  res.header('X-Server', HOSTNAME);
  res.header('X-Env', config.NODE_ENV || 'development');
  res.header('X-App-Version', process.env.npm_package_version || 'local'); // Version depuis package.json
  next();
});

// --- Initialisation de l'Authentification (Passport) ---
configurePassport(); // Configure la stratégie JWT (maintenant avec Bearer et check Redis)
app.use(passport.initialize()); // Initialise Passport pour chaque requête

// --- Définition des Routes ---

// Documentation API (Swagger/OpenAPI)
app.use(
  '/api-docs',
  swaggerUi.serve, // Sert les fichiers statiques de Swagger UI
  swaggerUi.setup(swaggerSpec, {
    // Utilise la spécification générée
    customSiteTitle: 'API Documentation', // Titre de la page
    // explorer: true, // Optionnel: afficher la barre d'exploration
  }),
);

// Route Racine (Health Check / Statut)
app.get('/', (req: Request, res: Response) => {
  // Utilise la réponse standardisée JSend
  res.status(200).jsend.success({
    message: `API is running in ${config.NODE_ENV} mode`,
    timestamp: new Date().toISOString(),
    server: HOSTNAME,
    version: process.env.npm_package_version || 'local',
  });
});

// --- Montage du Routeur API Principal ---
// Monte toutes les routes définies dans './api/index.ts' sous le préfixe '/api/v1'
// !! PAS de middleware d'authentification global appliqué ici !!
// L'authentification est gérée au niveau de chaque route via les décorateurs et `registerRoutes`
app.use('/api/v1', apiRouter);

// --- Gestion Finale des Erreurs ---

// 404 Handler: Gère les routes non trouvées
// Ce middleware est atteint si aucune route précédente n'a correspondu
app.use((req: Request, res: Response, next: NextFunction) => {
  const error = new NotFoundError(
    `The requested resource was not found on this server: ${req.method} ${req.originalUrl}`,
  );
  next(error); // Passe l'erreur au gestionnaire global
});

// Gestionnaire d'Erreurs Global: Le dernier middleware
// Il attrape toutes les erreurs passées via next(error)
app.use(errorHandler); // Utilise votre gestionnaire d'erreurs personnalisé

// Exporter l'instance `app` configurée pour le serveur principal (ex: src/server.ts)
export default app;
