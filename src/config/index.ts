// src/config/index.ts
import dotenv from 'dotenv';
import path from 'path';
import { z } from 'zod';
import 'reflect-metadata'; // Nécessaire pour TypeORM ou certains décorateurs
// Import logger removed to break circular dependency

// ---- Chargement des Fichiers .env ----
// Priorité : .env.development, .env.production, etc. > .env (base)
const nodeEnv = process.env.NODE_ENV || 'development';
const envPathSpecific = path.resolve(process.cwd(), `.env.${nodeEnv}`);
const envPathBase = path.resolve(process.cwd(), '.env');

dotenv.config({ path: envPathSpecific }); // Charge le .env spécifique à l'environnement
dotenv.config({ path: envPathBase, override: false }); // Charge le .env de base sans écraser les valeurs spécifiques

// ---- Schéma de Validation Zod ----
const envSchema = z
  .object({
    // --- Général ---
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    PORT: z.coerce.number().int().positive().default(3000),
    HOST: z
      .string()
      .ip({ version: 'v4' })
      .default('0.0.0.0')
      .describe('IP address to bind the server to'),
    API_URL: z
      .string()
      .url()
      .optional()
      .describe('Public base URL of the API (for docs, links), e.g., http://localhost:3000'),
    FRONTEND_URL: z
      .string()
      .url()
      .optional()
      .describe(
        'Base URL of the frontend application (for email links), e.g., http://localhost:8080',
      ),

    // --- Base de Données (TypeORM) ---
    DB_TYPE: z.enum(['postgres', 'mysql', 'mariadb', 'sqlite', 'mssql']).default('postgres'),
    DB_HOST: z.string().min(1),
    DB_PORT: z.coerce.number().int().positive(),
    DB_USERNAME: z.string().min(1),
    DB_PASSWORD: z.string().optional(), // Mot de passe optionnel (pour dev local ou auth différente)
    DB_DATABASE: z.string().min(1),
    DB_SYNCHRONIZE: z.coerce
      .boolean()
      .default(false)
      .describe('!! DANGER !! Set to false in production. Use migrations instead.'),
    DB_LOGGING: z.coerce.boolean().default(false).describe('Log SQL queries executed by TypeORM'),

    // --- Authentification & Sécurité ---
    JWT_SECRET: z
      .string()
      .min(32, { message: 'JWT_SECRET must be at least 32 characters long for security' }),
    JWT_EXPIRATION_SECONDS: z.coerce
      .number()
      .int()
      .positive()
      .default(60 * 60 * 24)
      .describe('Access Token expiration in seconds (default: 1 day)'), // 1 jour
    // JWT_REFRESH_EXPIRATION_SECONDS: z.coerce.number().int().positive().default(60 * 60 * 24 * 7).describe('Refresh Token expiration in seconds (default: 7 days)'), // Si vous utilisez des refresh tokens
    PASSWORD_EXPIRY_DAYS: z.coerce
      .number()
      .int()
      .positive()
      .default(90)
      .describe('Number of days after which user password expires'),
    PASSWORD_RESET_CODE_TTL_SECONDS: z.coerce
      .number()
      .int()
      .positive()
      .default(60 * 60 * 24 * 3)
      .describe('TTL for password reset/confirmation codes in Redis (default: 3 days)'), // 3 jours

    // --- Redis ---
    REDIS_HOST: z.string().default('localhost'),
    REDIS_PORT: z.coerce.number().int().positive().default(6379),
    REDIS_PASSWORD: z.string().optional(),
    REDIS_DB: z.coerce.number().int().min(0).optional().default(0),
    // Organisation des clés Redis
    REDIS_KEYS_TOKEN_INVALIDATION_PREFIX: z
      .string()
      .default('backend:token_invalidation:')
      .describe('Prefix for storing invalidated JWTs'),
    REDIS_KEYS_USER_PERMISSIONS_PREFIX: z
      .string()
      .default('user:')
      .describe('Prefix for user permissions cache key'),
    REDIS_KEYS_USER_PERMISSIONS_SUFFIX: z
      .string()
      .default(':permissions')
      .describe('Suffix for user permissions cache key'),
    REDIS_KEYS_PWD_CONFIRM_PREFIX: z
      .string()
      .default('confirm-password:')
      .describe('Prefix for password confirmation codes'),
    REDIS_KEYS_PWD_RESET_PREFIX: z
      .string()
      .default('reset-password:')
      .describe('Prefix for password reset codes'),
    // TTL pour le cache des autorisations
    AUTH_CACHE_TTL_SECONDS: z.coerce
      .number()
      .int()
      .positive()
      .default(60 * 15)
      .describe('TTL for cached user permissions in Redis (default: 15 minutes)'), // 15 minutes

    // --- CORS ---
    CORS_ORIGIN: z
      .string()
      .default('*')
      .describe(
        'Allowed origins for CORS requests (use * with caution, specify frontend URL(s) in production)',
      ),

    // --- Logging ---
    LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),

    // --- Email (Nodemailer) ---
    MAIL_HOST: z.string().optional(),
    MAIL_PORT: z.coerce.number().int().positive().optional(),
    MAIL_SECURE: z.coerce
      .boolean()
      .optional()
      .default(false)
      .describe('Use TLS for connection (true for 465, false for 587/STARTTLS)'),
    MAIL_USER: z.string().optional(),
    MAIL_PASS: z.string().optional(),
    MAIL_FROM: z.string().email().optional().default('noreply@example.com'), // Default changed to just email
  })
  .refine(
    (data) => {
      // Validation critique : synchronize ne DOIT PAS être true en production
      if (data.NODE_ENV === 'production' && data.DB_SYNCHRONIZE === true) {
        console.error('❌ FATAL SECURITY RISK: DB_SYNCHRONIZE cannot be true in production!');
        return false; // Bloque le démarrage
      }
      return true;
    },
    { message: 'DB_SYNCHRONIZE must be false in production environment' },
  )
  .refine((data) => {
    // Assurer que API_URL et FRONTEND_URL sont définis si nécessaires (ex: pour les docs et les emails)
    // Vous pouvez rendre cette validation plus stricte si ces URLs sont toujours requises.
    if (!data.API_URL && data.NODE_ENV !== 'test') {
      console.warn(
        '⚠️ WARNING: API_URL is not defined in .env. API Documentation links might be incorrect.',
      );
    }
    if (!data.FRONTEND_URL && data.NODE_ENV !== 'test') {
      console.warn(
        '⚠️ WARNING: FRONTEND_URL is not defined in .env. Email links might be incorrect.',
      );
    }
    return true;
  });

// --- Validation et Export ---
let config: z.infer<typeof envSchema>;

try {
  // Valider process.env contre le schéma Zod
  config = envSchema.parse(process.env);
  // Afficher un message de succès (optionnel)
  console.info(`[Config] Configuration loaded successfully for NODE_ENV=${config.NODE_ENV}`); // Use console here
} catch (error) {
  // Si la validation échoue, afficher les erreurs détaillées et quitter
  if (error instanceof z.ZodError) {
    console.error(
      '❌ Invalid environment variables configuration:',
      JSON.stringify(error.format(), null, 2), // Affiche les erreurs par champ
    );
  } else {
    console.error('❌ Unexpected error parsing environment variables:', error);
  }
  // Quitter le processus pour empêcher l'application de démarrer avec une config invalide
  process.exit(1);
}

// Exporter l'objet de configuration validé et typé
export default config;

// Exporter le type pour pouvoir l'utiliser ailleurs (ex: dans les services)
export type AppConfig = typeof config;
