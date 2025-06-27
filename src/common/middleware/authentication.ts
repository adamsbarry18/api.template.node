import passport from 'passport';
import type { User as UserEntity } from '@/modules/users/models/users.entity';
import {
  Strategy as JwtStrategy,
  ExtractJwt,
  type StrategyOptions as JwtStrategyOptions,
  type VerifiedCallback as JwtVerifiedCallback,
} from 'passport-jwt';
import {
  Strategy as GoogleStrategy,
  type Profile as GoogleProfile,
  type VerifyCallback as GoogleVerifyCallback,
} from 'passport-google-oauth20';
import { type AnyZodObject, ZodError } from 'zod';

import {
  ForbiddenError,
  UnauthorizedError,
  ServiceUnavailableError,
  ValidationError,
  ServerError,
  BaseError,
} from '@/common/errors/httpErrors';
import type { CustomJwtPayload } from '@/common/types';
import config from '@/config';
import type { NextFunction, Request, Response, AuthenticatedUser } from '@/config/http';
import logger from '@/lib/logger';
import { AuthorizationService } from '@/modules/auth/services/authorization.service';
import { LoginService } from '@/modules/auth/services/login.services';
import { UsersService } from '@/modules/users/services/users.services';
import { Service } from '@/common/utils/Service';

type JwtStrategyOptionsWithRequest = JwtStrategyOptions & {
  passReqToCallback: true;
};

const jwtOptions: JwtStrategyOptionsWithRequest = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: config.JWT_SECRET,
  passReqToCallback: true,
};

const loginService = LoginService.getInstance();
const userService = UsersService.getInstance();
const authorizationService = AuthorizationService.getInstance();

export function passportAuthenticationMiddleware(): void {
  // JWT Strategy
  passport.use(
    new JwtStrategy(
      jwtOptions,
      (req: Request, payload: CustomJwtPayload, done: JwtVerifiedCallback) => {
        const verify = async (): Promise<void> => {
          const rawToken = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
          if (!rawToken) {
            done(null, false, { message: 'No Bearer token provided.' });
            return;
          }
          try {
            if (await loginService.isTokenInvalidated(rawToken)) {
              done(null, false, { message: 'Token invalidated or expired.' });
              return;
            }

            const userId = payload.sub;
            if (!userId || typeof userId !== 'number') {
              done(null, false, { message: 'Invalid token payload structure.' });
              return;
            }
            const userApiResponse = await userService.findById(userId);

            if (!userApiResponse) {
              try {
                await loginService.logout(rawToken);
              } catch (err) {
                logger.error(err, 'Error during automatic token logout for non-existent user.');
              }
              done(null, false, { message: 'User not found.' });
              return;
            }

            if (!userApiResponse.isActive) {
              try {
                await loginService.logout(rawToken);
              } catch (err) {
                logger.error(err, 'Error during automatic token logout for inactive user.');
              }
              done(null, false, { message: 'Account is inactive.' });
              return;
            }

            if (
              userApiResponse.permissionsExpireAt &&
              new Date(userApiResponse.permissionsExpireAt).getTime() < Date.now()
            ) {
              try {
                await loginService.logout(rawToken);
              } catch (err) {
                logger.error(err, 'Error during automatic token logout for expired permissions.');
              }
              done(null, false, { message: 'Account permissions have expired.' });
              return;
            }
            const authenticatedUser: AuthenticatedUser = {
              ...(userApiResponse as any),
              id: userId,
              sub: userId,
              authToken: rawToken,
            };
            done(null, authenticatedUser);
          } catch (error) {
            if (error instanceof ServiceUnavailableError) {
              done(error, false);
            } else {
              logger.error(error, 'Unexpected error during JWT strategy execution.');
              done(error, false);
            }
          }
        };

        verify().catch((err) => {
          logger.error(err, 'Unhandled error in JWT strategy verify function.');
          done(err, false);
        });
      },
    ),
  );

  // Google OAuth2.0 Strategy
  if (config.GOOGLE_CLIENT_ID && config.GOOGLE_CLIENT_SECRET && config.GOOGLE_CALLBACK_URL) {
    passport.use(
      new GoogleStrategy(
        {
          clientID: config.GOOGLE_CLIENT_ID,
          clientSecret: config.GOOGLE_CLIENT_SECRET,
          callbackURL: config.GOOGLE_CALLBACK_URL,
        },
        // Outer callback function is synchronous and returns void
        (
          _accessToken: string,
          _refreshToken: string | undefined,
          profile: GoogleProfile,
          done: GoogleVerifyCallback,
        ): void => {
          // Inner async function to handle the promise-based logic
          const processGoogleAuth = async () => {
            try {
              logger.info(
                { googleProfileId: profile.id, email: profile.emails?.[0]?.value },
                'Google OAuth: Profile received',
              );

              const userEntityInstance: UserEntity =
                await userService.findOrCreateByGoogleProfile(profile);

              if (!userEntityInstance?.id) {
                logger.error(
                  'findOrCreateByGoogleProfile did not return a valid user entity with an ID.',
                );
                done(
                  new ServerError('Failed to process user profile after Google authentication.'),
                  false,
                );
                return;
              }

              const authenticatedUser = userEntityInstance as AuthenticatedUser;
              authenticatedUser.sub = userEntityInstance.id;

              done(null, authenticatedUser);
            } catch (error) {
              logger.error(
                error,
                'Error in Google OAuth strategy during findOrCreateByGoogleProfile',
              );
              if (error instanceof BaseError) {
                done(error, false);
              } else {
                done(
                  new ServerError('An unexpected error occurred during Google authentication.'),
                  false,
                );
              }
            }
          };
          void processGoogleAuth();
        },
      ),
    );
  }
}

/**
 * Middleware: requireAuth
 * Ensures the request is authenticated via JWT. Attaches the user object to `req.user`.
 */
export const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  // eslint-disable-next-line
  passport.authenticate(
    'jwt',
    { session: false },
    (err: any, user: AuthenticatedUser | false, info: any) => {
      if (err) {
        if (err instanceof BaseError) return next(err);
        logger.error(err, 'Internal error during Passport authentication.');
        return next(new ServerError('Authentication processing error.'));
      }
      if (!user) {
        const message = info?.message ?? 'Unauthorized access';
        logger.warn(`JWT Authentication failed: ${message}. URL: ${req.originalUrl}`);
        return next(new UnauthorizedError(message));
      }
      req.user = user;
      Service.setUser(user);
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
    const userLevel = typeof req.user.level === 'number' ? req.user.level : 0;
    if (userLevel < requiredLevel) {
      logger.warn(
        `Access denied for user ${req.user.id}: insufficient level (${userLevel}). Required: ${requiredLevel}. URL: ${req.originalUrl}`,
      );
      return next(new ForbiddenError(`Insufficient security level. Required: ${requiredLevel}.`));
    }
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
      const hasPerm = await authorizationService.checkAuthorisation(
        req.user.id,
        featureName,
        actionName,
      );
      if (!hasPerm) {
        logger.warn(
          `Access denied: User ${req.user.id} lacks permission ${featureName}:${actionName}. URL: ${req.originalUrl}`,
        );
        return next(new ForbiddenError(`Required permission: ${featureName}:${actionName}`));
      }
      next();
    } catch (error) {
      logger.error(
        error,
        `Error during permission check (${featureName}:${actionName}) for user ${req.user.id}.`,
      );
      next(
        error instanceof BaseError
          ? error
          : new ServerError(`Error processing permissions. ${error}`),
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
        next(new ValidationError(JSON.stringify(error.format())));
      } else {
        next(error);
      }
    }
  };

/**
 * Middleware: requireInternalUser
 * Ensures the request is authenticated and the user is an internal user.
 * You can adapt the logic (e.g., user.isInternal, user.level, etc.).
 */
export const requireInternalUser = (req: Request, res: Response, next: NextFunction): void => {
  if (!req.user) {
    return next(new UnauthorizedError('Authentication required for internal route.'));
  }
  const isInternal = typeof req.user.internal === 'boolean' ? req.user.internal : false;
  if (!isInternal) {
    logger.warn(
      `Internal route access denied for user ${req.user.id}: not internal. URL: ${req.originalUrl}`,
    );
    return next(new ForbiddenError('Internal access only.'));
  }
  next();
};
