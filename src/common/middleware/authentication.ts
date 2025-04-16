import { AnyZodObject, ZodError } from 'zod';
import {
  Strategy as JwtStrategy,
  ExtractJwt,
  StrategyOptions,
  VerifiedCallback,
} from 'passport-jwt';
import passport from 'passport';
import { NextFunction, Request, Response } from '@/config/http';
import {
  ForbiddenError,
  InternalServerError,
  UnauthorizedError,
  HttpError,
  ServiceUnavailableError,
  ValidationError,
} from '@/common/errors/httpErrors';
import logger from '@/lib/logger';
import { CustomJwtPayload } from '@/common/types';
import { AuthenticatedUser } from '@/config/http';
import config from '@/config';
import { AuthService } from '@/modules/auth/services/auth.services';
import { UsersService } from '@/modules/users/services/users.services';

const options: StrategyOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: config.JWT_SECRET,
  passReqToCallback: true,
};

const authService = new AuthService();
const userService = new UsersService();

export const initializePassportAuthentication = (): void => {
  passport.use(
    new JwtStrategy(
      options,
      async (req: Request, payload: CustomJwtPayload, done: VerifiedCallback) => {
        const rawToken = ExtractJwt.fromAuthHeaderAsBearerToken()(req as any);
        try {
          if (await authService.isTokenInvalidated(rawToken)) {
            return done(null, false, { message: 'Token invalidated or expired.' });
          }

          const userId = payload.sub;
          if (!userId || typeof userId !== 'number') {
            return done(null, false, { message: 'Invalid token payload structure.' });
          }
          const user = await userService.findById(userId);
          if (user) {
            const authenticatedUser = { ...user, authToken: rawToken };
            return done(null, authenticatedUser);
          } else {
            logger.warn(`User not found (ID: ${userId}) for active token. Invalidating token.`);
            authService
              .logout(rawToken)
              .catch((err) => logger.error(err, 'Error during automatic token logout.'));
            return done(null, false, { message: 'User not found or disabled.' });
          }
        } catch (error) {
          if (error instanceof ServiceUnavailableError) {
            return done(error, false);
          }
          logger.error(error, 'Unexpected error during JWT strategy execution.');
          return done(error, false);
        }
      },
    ),
  );

  logger.info('Passport JWT strategy configured (token + Redis invalidation check).');
};

/**
 * Middleware: requireAuth
 * Ensures the request is authenticated via JWT. Attaches the user object to `req.user`.
 */
export const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  passport.authenticate(
    'jwt',
    { session: false },
    (err: any, user: AuthenticatedUser | false, info: any) => {
      if (err) {
        if (err instanceof HttpError) return next(err);
        logger.error(err, 'Internal error during Passport authentication.');
        return next(new InternalServerError('Authentication processing error.', err));
      }
      if (!user) {
        const message = info?.message || 'Unauthorized access';
        logger.warn(`JWT Authentication failed: ${message}. URL: ${req.originalUrl}`);
        return next(new UnauthorizedError(message));
      }
      req.user = user;
      logger.debug(`User ${req.user.id} authenticated. URL: ${req.originalUrl}`);
      next();
    },
  )(req, res, next);
};

/**
 * Middleware Factory: requireLevel
 * Checks if the authenticated user has the required security level or higher.
 * @param requiredLevel The minimum security level required.
 */
export const requireLevel =
  (requiredLevel: number) =>
  (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      logger.error('requireLevel called without prior authentication (req.user missing).');
      return next(new UnauthorizedError('Authentication context missing.'));
    }
    if (req.user.level < requiredLevel) {
      logger.warn(
        `Access denied for user ${req.user.id}: insufficient level (${req.user.level}). Required: ${requiredLevel}. URL: ${req.originalUrl}`,
      );
      return next(new ForbiddenError(`Insufficient security level. Required: ${requiredLevel}.`));
    }
    logger.debug(
      `Level check successful for user ${req.user.id} (Level ${req.user.level} >= Required ${requiredLevel}).`,
    );
    next();
  };

/**
 * Middleware Factory: requirePermission
 * Checks if the authenticated user has a specific permission (feature + action).
 * @param featureName The name of the feature.
 * @param actionName The name of the action within the feature.
 */
export const requirePermission =
  (featureName: string, actionName: string) =>
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user?.id) {
      logger.error(
        `Permission check [${featureName}:${actionName}] attempted without authenticated user.`,
      );
      return next(new UnauthorizedError('Authentication required to check permissions.'));
    }
    try {
      const hasPerm = await authService.checkAuthorisation(req.user.id, featureName, actionName);
      if (!hasPerm) {
        logger.warn(
          `Access denied: User ${req.user.id} lacks permission ${featureName}:${actionName}. URL: ${req.originalUrl}`,
        );
        return next(new ForbiddenError(`Required permission: ${featureName}:${actionName}`));
      }
      logger.debug(`Permission ${featureName}:${actionName} granted for user ${req.user.id}.`);
      next();
    } catch (error) {
      logger.error(
        error,
        `Error during permission check (${featureName}:${actionName}) for user ${req.user.id}.`,
      );
      next(
        error instanceof HttpError
          ? error
          : new InternalServerError('Error processing permissions.', error),
      );
    }
  };

/**
 * Middleware Factory: validateRequest
 * Validates request body, query parameters, and route parameters against a Zod schema.
 * Replaces request properties with validated/transformed data.
 * @param schema The Zod schema to validate against.
 */
export const validateRequest =
  (schema: AnyZodObject) =>
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const parsed = await schema.parseAsync({
        body: req.body,
        query: req.query,
        params: req.params,
      });
      req.body = parsed.body ?? req.body;
      req.query = parsed.query ?? req.query;
      req.params = parsed.params ?? req.params;

      next();
    } catch (error) {
      if (error instanceof ZodError) {
        next(new ValidationError('Validation failed', error.format()));
      } else {
        next(error);
      }
    }
  };
