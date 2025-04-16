import dotenv from 'dotenv';
import path from 'path';
import { z } from 'zod';
import 'reflect-metadata';

// Priority: .env.development, .env.production, etc. > .env (base)
/**
 * @description Configuration loading from .env files.
 * @priority Specific environment files (.env.development, .env.production) > base .env file.
 */
const nodeEnv = process.env.NODE_ENV || 'development';
const envPathSpecific = path.resolve(process.cwd(), `.env.${nodeEnv}`);
const envPathBase = path.resolve(process.cwd(), '.env');

dotenv.config({ path: envPathSpecific }); // Load environment-specific .env
dotenv.config({ path: envPathBase, override: false }); // Load base .env without overriding specific values

// ---- Zod Validation Schema ----
/**
 * @description Zod schema for environment variable validation.
 * @remarks Defines the structure and validation rules for all environment variables.
 */
const envSchema = z
  .object({
    // --- General ---
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    PORT: z.coerce.number().int().positive().default(3000),
    HOST: z
      .string()
      .ip({ version: 'v4' })
      .default('0.0.0.0')
      .describe('IP address to bind the server to'),
    API_URL: z.string().url().optional(),
    FRONTEND_URL: z.string().url().optional(),

    // --- Database (TypeORM) ---
    DB_TYPE: z.enum(['postgres', 'mysql', 'mariadb', 'sqlite', 'mssql']).default('postgres'),
    DB_HOST: z.string().min(1),
    DB_PORT: z.coerce.number().int().positive(),
    DB_USERNAME: z.string().min(1),
    DB_PASSWORD: z.string().optional(),
    DB_DATABASE: z.string().min(1),
    DB_SYNCHRONIZE: z.coerce.boolean().default(false),
    DB_LOGGING: z.coerce.boolean().default(false).describe('Log SQL queries executed by TypeORM'),

    // --- Authentication & Security ---
    JWT_SECRET: z
      .string()
      .min(32, { message: 'JWT_SECRET must be at least 32 characters long for security' }),
    JWT_EXPIRATION_SECONDS: z.coerce
      .number()
      .int()
      .positive()
      .default(60 * 60 * 24)
      .describe('Access Token expiration in seconds (default: 1 day)'), // 1 day
    // JWT_REFRESH_EXPIRATION_SECONDS: z.coerce.number().int().positive().default(60 * 60 * 24 * 7).describe('Refresh Token expiration in seconds (default: 7 days)'), // If using refresh tokens
    PASSWORD_EXPIRY_DAYS: z.coerce.number().int().positive().default(90),
    PASSWORD_RESET_CODE_TTL_SECONDS: z.coerce
      .number()
      .int()
      .positive()
      .default(60 * 60 * 24 * 3), // 3 days

    // --- Redis ---
    REDIS_HOST: z.string().default('localhost'),
    REDIS_PORT: z.coerce.number().int().positive().default(6379),
    REDIS_PASSWORD: z.string().optional(),
    REDIS_DB: z.coerce.number().int().min(0).optional().default(0),

    // TTL for authorization cache
    AUTH_CACHE_TTL_SECONDS: z.coerce
      .number()
      .int()
      .positive()
      .default(60 * 15), // 15 minutes

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
    MAIL_SECURE: z.coerce.boolean().optional().default(false),
    MAIL_USER: z.string().optional(),
    MAIL_PASS: z.string().optional(),
    MAIL_FROM: z.string().email().optional(),
  })
  .refine(
    (data) => {
      if (data.NODE_ENV === 'production' && data.DB_SYNCHRONIZE === true) {
        console.error('❌ FATAL SECURITY RISK: DB_SYNCHRONIZE cannot be true in production!');
        return false;
      }
      return true;
    },
    { message: 'DB_SYNCHRONIZE must be false in production environment' },
  )
  .refine((data) => {
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

/**
 * @description Validates environment variables against the schema and exports the configuration.
 * @throws {Error} If environment variable validation fails, the process will exit.
 */
let config: z.infer<typeof envSchema>;

try {
  config = envSchema.parse(process.env);
  console.info(`[Config] Configuration loaded successfully for NODE_ENV=${config.NODE_ENV}`); // Use console here
} catch (error) {
  if (error instanceof z.ZodError) {
    console.error(
      '❌ Invalid environment variables configuration:',
      JSON.stringify(error.format(), null, 2),
    );
  } else {
    console.error('❌ Unexpected error parsing environment variables:', error);
  }
  process.exit(1);
}

export default config;

export type AppConfig = typeof config;
