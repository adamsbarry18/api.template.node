import { Request, Response, NextFunction } from '../http';
import { ForbiddenError, UnauthorizedError } from '../errors/httpErrors';
import logger from '@/lib/logger';
import { AuthorisationsService } from '../../modules/authorisations/authorization.services';

// Instancier le service (ou l'injecter si DI)
const authorisationsService = new AuthorisationsService();

/**
 * Middleware pour vérifier une permission spécifique (feature/action).
 * Doit être utilisé APRÈS requireAuth.
 * @param featureName - Nom de la fonctionnalité (ex: 'user').
 * @param actionName - Nom de l'action (ex: 'create', 'read').
 */
export const requirePermission =
  (featureName: string, actionName: string) =>
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user) {
      // Sécurité : requireAuth doit avoir été appelé avant
      return next(new UnauthorizedError('Authentication required before checking permissions.'));
    }

    try {
      // Appeler la méthode du service d'autorisation
      // Cette méthode lit maintenant user.level et user.authorisationOverrides
      const hasPermission = await authorisationsService.checkPermission(
        req.user.id,
        featureName,
        actionName,
      );

      if (!hasPermission) {
        logger.warn(`User ${req.user.id} denied permission for ${featureName}:${actionName}`);
        return next(
          new ForbiddenError(`Missing required permission: ${featureName}:${actionName}`),
        );
      }

      // Permission accordée
      next();
    } catch (error) {
      logger.error(
        error,
        `Error checking permission ${featureName}:${actionName} for user ${req.user.id}`,
      );
      // Transmettre l'erreur au gestionnaire global
      next(error);
    }
  };
