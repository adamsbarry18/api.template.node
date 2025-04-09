// src/config/index.ts
import dotenv from 'dotenv';
import path from 'path';
import { z } from 'zod';
import 'reflect-metadata';

// Construire le chemin vers le fichier .env approprié basé sur NODE_ENV
// Ex: .env.production, .env.development, ou juste .env
const envPath = path.resolve(
  process.cwd(),
  `.env${process.env.NODE_ENV ? `.${process.env.NODE_ENV}` : ''}`,
);
dotenv.config({ path: envPath });
// Charger aussi le .env de base s'il existe (pour les valeurs par défaut, ne pas écraser)
dotenv.config({ path: path.resolve(process.cwd(), '.env'), override: false });

// Schéma de validation Zod pour les variables d'environnement
const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    PORT: z.coerce.number().int().positive().default(3000),
    HOST: z.string().default('0.0.0.0'), // Écoute sur toutes les interfaces par défaut

    // --- Variables TypeORM ---
    DB_TYPE: z.enum(['postgres', 'mysql', 'mariadb', 'sqlite', 'mssql']).default('postgres'), // Valide les types supportés
    DB_HOST: z.string().min(1),
    DB_PORT: z.coerce.number().int().positive(),
    DB_USERNAME: z.string().min(1),
    DB_PASSWORD: z.string().optional(), // Mot de passe est optionnel
    DB_DATABASE: z.string().min(1),
    DB_SYNCHRONIZE: z.coerce.boolean().default(false),
    DB_LOGGING: z.coerce.boolean().default(false),
    // --- Fin Variables TypeORM ---

    // Authentification (JWT)
    JWT_SECRET: z.string().min(1, { message: 'JWT_SECRET is required' }),
    JWT_EXPIRES_IN: z.string().min(1).default('1d'),

    // Redis
    REDIS_HOST: z.string().default('localhost'),
    REDIS_PORT: z.coerce.number().int().positive().default(6379),
    REDIS_PASSWORD: z.string().optional(), // Mot de passe est optionnel
    REDIS_DB: z.coerce.number().int().min(0).optional().default(0), // DB Redis (0 par défaut)

    // CORS
    CORS_ORIGIN: z.string().default('*'), // Ou une URL spécifique: 'http://localhost:8080'

    // Logging
    LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),

    // Swagger / API Docs
    API_URL: z
      .string()
      .url()
      .optional()
      .describe('Base URL for API documentation, e.g., http://localhost:3000'),

    // Nodemailer (optionnel, à configurer si besoin d'envoyer des emails)
    MAIL_HOST: z.string().optional(),
    MAIL_PORT: z.coerce.number().int().positive().optional(),
    MAIL_SECURE: z.coerce.boolean().optional().default(false), // true pour le port 465, false pour les autres (comme 587 avec STARTTLS)
    MAIL_USER: z.string().optional(), // Utilisateur SMTP
    MAIL_PASS: z.string().optional(), // Mot de passe SMTP
    MAIL_FROM: z.string().email().optional().default('"MyApp" <noreply@example.com>'), // Email expéditeur par défaut
  })
  .refine(
    (data) => {
      // !! Sécurité importante : Interdire synchronize en production !!
      if (data.NODE_ENV === 'production' && data.DB_SYNCHRONIZE === true) {
        console.error('❌ FATAL: DB_SYNCHRONIZE must be false in production environment!');
        return false; // Rend la validation invalide
      }
      return true;
    },
    { message: 'DB_SYNCHRONIZE cannot be true in production' },
  );

// Validation des variables d'environnement chargées (process.env)
const parsedEnv = envSchema.safeParse(process.env);

if (!parsedEnv.success) {
  console.error(
    '❌ Invalid environment variables:',
    JSON.stringify(parsedEnv.error.format(), null, 4),
  );
  // Quitter si la configuration est invalide
  process.exit(1);
}

// Exporter l'objet de configuration validé et typé
const config = parsedEnv.data;

export default config;

// Export du type pour utilisation ailleurs si nécessaire
export type AppConfig = typeof config;
