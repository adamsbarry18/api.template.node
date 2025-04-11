import {
  Strategy as JwtStrategy,
  ExtractJwt,
  StrategyOptions,
  VerifiedCallback,
} from 'passport-jwt';
import passport from 'passport';
import config from '.';
import { NextFunction } from '@/common/http';
import { ForbiddenError, InternalServerError, UnauthorizedError } from '@/common/errors/httpErrors';
import { SecurityLevel } from '@/modules/users/models/users.types';
import logger from '@/lib/logger';
import { IsNull } from 'typeorm';
import { AppDataSource } from '@/database/data-source';
import { User } from '@/modules/users/models/users.entity';
import { Request, Response } from '@/common/http';
import { AuthService } from '@/modules/auth/services/auth.services';

const options: StrategyOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: config.JWT_SECRET,
  passReqToCallback: true,
};

const authService = new AuthService();

export const configurePassport = (): void => {
  passport.use(
    new JwtStrategy(options, async (req: Request, payload: any, done: VerifiedCallback) => {
      const rawToken = ExtractJwt.fromAuthHeaderAsBearerToken()(req as any);

      try {
        // 1. Vérifier si le token est invalidé dans Redis
        if (await authService.isTokenInvalidated(rawToken)) {
          logger.warn(
            `JWT Auth rejected: Token is invalidated (blacklisted). Token starts with ${rawToken?.substring(0, 10)}...`,
          );
          return done(null, false, { message: 'Token has been invalidated (logout).' });
        }

        // 2. Vérifier le payload
        const userId = payload.id;
        if (!userId || typeof userId !== 'number') {
          logger.warn('Invalid JWT payload: missing or invalid "id" field.');
          return done(null, false, { message: 'Invalid token payload structure.' });
        }
        const userRepository = AppDataSource.getRepository(User);
        const user = await userRepository.findOne({
          select: [
            'id',
            'uid',
            'email',
            'name',
            'surname',
            'level',
            'internal',
            'language',
            'color',
            'preferences',
            'passwordUpdatedAt',
            'passwordStatus',
            'internalLevel',
            'createdAt',
            'updatedAt',
            'authorisationOverrides',
            'permissionsExpireAt',
          ],
          where: {
            id: userId,
            deletedAt: IsNull(),
          },
        });

        // 4. Retourner le résultat
        if (user) {
          // Optionnel mais utile : Attacher le token brut à req.user
          const userWithToken = user as any & { authToken: string | null };
          userWithToken.authToken = rawToken;
          return done(null, userWithToken);
        } else {
          logger.warn(`User not found or deleted for ID ${userId} during JWT auth.`);
          return done(null, false, { message: 'User associated with token not found or invalid.' });
        }
      } catch (error) {
        logger.error(error, 'Error during JWT strategy execution.');
        return done(error, false);
      }
    }),
  );
  logger.info(
    'Passport JWT strategy configured (using Authorization: Bearer and Redis invalidation check).',
  );
};

/**
 * Middleware pour exiger une authentification JWT valide.
 */
export const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  passport.authenticate('jwt', { session: false }, (err: any, user: User | false, info: any) => {
    if (err) {
      return next(new InternalServerError('Authentication error', err));
    }
    if (!user) {
      const message = info?.message || 'Unauthorized';
      if (info instanceof Error) logger.warn(`JWT Auth failed: ${info.message}`);
      else if (info?.message) logger.warn(`JWT Auth failed: ${info.message}`);
      else logger.warn(`JWT Auth failed: ${message}`);
      return next(new UnauthorizedError(message));
    }
    req.user = user;
    next();
  })(req, res, next);
};

export const requireLevel =
  (requiredLevel: SecurityLevel) =>
  (req: Request, res: Response, next: NextFunction): void => {
    const userLevel = req.user?.level as SecurityLevel;

    if (req.user === undefined || userLevel === undefined || userLevel === null) {
      logger.warn(
        `User security level not found on req.user (ID: ${req.user?.id}). Access denied.`,
      );
      return next(new ForbiddenError('User security level not available. Access denied.'));
    }

    if (userLevel < requiredLevel) {
      logger.warn(
        `User ${req.user.id} has insufficient security level. Required: ${requiredLevel}, User has: ${userLevel}.`,
      );
      return next(
        new ForbiddenError(`Insufficient security level. Required level: ${requiredLevel}.`),
      );
    }
    next();
  };
