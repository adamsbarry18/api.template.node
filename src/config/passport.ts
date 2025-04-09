import { Strategy as JwtStrategy, ExtractJwt, StrategyOptions } from 'passport-jwt';
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

const options: StrategyOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // Extrait le token du header 'Authorization: Bearer <token>'
  secretOrKey: config.JWT_SECRET,
  // issuer: 'optional: your issuer', // Optionnel: si vous définissez un issuer lors de la signature
};

export const configurePassport = (): void => {
  passport.use(
    new JwtStrategy(options, async (payload, done) => {
      try {
        const userId = payload.sub;
        if (!userId || typeof userId !== 'number') {
          logger.warn('Invalid JWT payload: missing or invalid "sub" (userId).');
          return done(null, false, { message: 'Invalid token payload' });
        }

        // Utiliser le Repository TypeORM pour chercher l'utilisateur
        const userRepository = AppDataSource.getRepository(User);
        const user = await userRepository.findOne({
          // Sélectionner les champs nécessaires pour req.user, **incluant level**
          select: [
            'id',
            'uid',
            'email',
            'name',
            'surname',
            'level',
            'internal',
            'language',
            // Exclure 'password', 'deletedAt', 'authorisationOverrides' etc.
          ],
          where: {
            id: userId,
            deletedAt: IsNull(), // Vérifier soft delete
          },
          // Charger d'autres relations si nécessaire pour les permissions plus tard
          // relations: ['roles'] // Si vous aviez une relation roles
        });

        if (user) {
          // Important : S'assurer que l'objet retourné ici correspond bien à Express.User étendu
          return done(null, user as Express.User);
        } else {
          logger.warn(`User not found or deleted for ID ${userId} during JWT auth.`);
          return done(null, false, { message: 'User not found or invalid' });
        }
      } catch (error) {
        logger.error(error, 'Error during JWT strategy execution.');
        return done(error, false);
      }
    }),
  );
  logger.info('Passport JWT strategy configured.');
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
