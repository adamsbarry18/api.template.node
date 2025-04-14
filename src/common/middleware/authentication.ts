import {
  Strategy as JwtStrategy,
  ExtractJwt,
  StrategyOptions,
  VerifiedCallback,
} from 'passport-jwt';
import passport from 'passport';
import { NextFunction, Request, Response } from '@/common/http';
import {
  ForbiddenError,
  InternalServerError,
  UnauthorizedError,
  HttpError,
  ServiceUnavailableError,
} from '@/common/errors/httpErrors';
import logger from '@/lib/logger';
import { CustomJwtPayload } from '@/common/types';
import { AuthenticatedUser } from '@/common/http';
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
            return done(null, false, { message: 'Token invalidé ou expiré.' });
          }

          const userId = payload.sub;
          if (!userId || typeof userId !== 'number') {
            return done(null, false, { message: 'Structure du payload invalide.' });
          }
          const user = await userService.findById(userId);
          if (user) {
            const authenticatedUser = { ...user, authToken: rawToken };
            return done(null, authenticatedUser);
          } else {
            logger.warn(`Utilisateur introuvable (ID: ${userId}) pour le token actif.`);
            authService
              .logout(rawToken)
              .catch((err) => logger.error(err, 'Erreur lors du logout automatique.'));
            return done(null, false, { message: 'Utilisateur introuvable ou désactivé.' });
          }
        } catch (error) {
          if (error instanceof ServiceUnavailableError) {
            return done(error, false);
          }
          logger.error(error, 'Erreur inattendue durant la stratégie JWT.');
          return done(error, false);
        }
      },
    ),
  );

  logger.info('Stratégie Passport JWT configurée (vérification via token et Redis).');
};

// Middleware requireAuth : Exige l’authentification pour accéder aux endpoints protégés.
export const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  passport.authenticate(
    'jwt',
    { session: false },
    (err: any, user: AuthenticatedUser | false, info: any) => {
      if (err) {
        if (err instanceof HttpError) return next(err);
        logger.error(err, 'Erreur interne lors de l’authentification Passport.');
        return next(new InternalServerError('Erreur de traitement de l’authentification.', err));
      }
      if (!user) {
        const message = info?.message || 'Accès non autorisé';
        logger.warn(`Authentification JWT échouée: ${message}. URL: ${req.originalUrl}`);
        return next(new UnauthorizedError(message));
      }
      req.user = user;
      logger.debug(`Utilisateur ${req.user.id} authentifié. URL: ${req.originalUrl}`);
      next();
    },
  )(req, res, next);
};

// Middleware requireLevel : Vérifie que l’utilisateur dispose d’un niveau de sécurité suffisant.
export const requireLevel =
  (requiredLevel: number) =>
  (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      logger.error('requireLevel appelé sans authentification préalable (req.user manquant).');
      return next(new UnauthorizedError('Contexte d’authentification manquant.'));
    }
    if ((req.user as CustomJwtPayload).level < requiredLevel) {
      logger.warn(
        `Accès refusé pour l’utilisateur ${req.user.id}: niveau insuffisant. Requis: ${requiredLevel}.`,
      );
      return next(new ForbiddenError(`Niveau de sécurité insuffisant. Requis: ${requiredLevel}.`));
    }
    logger.debug(`Vérification de niveau réussie pour l’utilisateur ${req.user.id}.`);
    next();
  };

// Middleware requirePermission : Vérifie qu’un utilisateur possède une permission spécifique.
export const requirePermission =
  (featureName: string, actionName: string) =>
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user?.id) {
      logger.error(
        `Vérification de permission [${featureName}:${actionName}] sans utilisateur authentifié.`,
      );
      return next(new UnauthorizedError('Authentification requise pour vérifier les permissions.'));
    }
    try {
      const hasPerm = await authService.checkAuthorisation(req.user.id, featureName, actionName);
      if (!hasPerm) {
        logger.warn(
          `Accès refusé: l’utilisateur ${req.user.id} n’a pas la permission ${featureName}:${actionName}. URL: ${req.originalUrl}`,
        );
        return next(new ForbiddenError(`Permission requise: ${featureName}:${actionName}`));
      }
      logger.debug(
        `Permission ${featureName}:${actionName} accordée pour l’utilisateur ${req.user.id}.`,
      );
      next();
    } catch (error) {
      logger.error(
        error,
        `Erreur durant la vérification de la permission ${featureName}:${actionName} pour l’utilisateur ${req.user.id}.`,
      );
      next(
        error instanceof HttpError
          ? error
          : new InternalServerError('Erreur lors du traitement des permissions.', error),
      );
    }
  };
