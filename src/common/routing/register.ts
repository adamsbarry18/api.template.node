import { Router, RequestHandler } from 'express';
import { globalMetadataStorage, RouteMetadataArgs } from './metadata.storage';
import { validateRequest } from '../middleware/validation';
import { Request, Response, NextFunction } from '../http';
import { requireAuth, requireLevel } from '@/config/passport';
import logger from '@/lib/logger';
import { requirePermission } from '../middleware/authorization';
import {
  parseFiltering,
  parsePagination,
  parseSearch,
  parseSorting,
} from '../middleware/queryParssing';

/**
 * Enregistre les routes définies par les décorateurs d'une classe Controller sur un routeur Express.
 * @param router Le routeur Express sur lequel enregistrer les routes.
 * @param ControllerClass La classe Controller contenant les décorateurs (son constructeur).
 * @param options Options pour contrôler l'enregistrement (ex: ignorer les internes).
 */
export function registerRoutes(
  router: Router,
  ControllerClass: { new (...args: any[]): any },
  options: { ignoreInternal?: boolean } = { ignoreInternal: true },
): void {
  let instance: any;
  try {
    instance = new ControllerClass();
  } catch (error) {
    logger.error(error, `Failed to instantiate controller ${ControllerClass.name}.`);
    return;
  }

  const routes = globalMetadataStorage.getRoutesForTarget(ControllerClass);

  if (!routes || routes.length === 0) {
    logger.debug(`No routes defined with decorators found for controller ${ControllerClass.name}`);
    return;
  }

  routes.forEach((routeMeta: RouteMetadataArgs) => {
    if (!routeMeta.method || !routeMeta.path || !routeMeta.handlerName) {
      logger.warn(
        `  Skipping incomplete route metadata for ${ControllerClass.name}: ${JSON.stringify(routeMeta)}`,
      );
      return;
    }

    if (options.ignoreInternal && routeMeta.isInternal) {
      logger.info(
        `  Skipping internal route: ${routeMeta.method.toUpperCase()} ${routeMeta.path} -> ${ControllerClass.name}.${String(routeMeta.handlerName)}`,
      );
      return;
    }

    const handler = instance[routeMeta.handlerName];

    if (typeof handler !== 'function') {
      logger.error(
        `  Handler ${String(routeMeta.handlerName)} for route ${routeMeta.method.toUpperCase()} ${routeMeta.path} in ${ControllerClass.name} is not a function. Skipping.`,
      );
      return;
    }

    // Construire le tableau des middlewares spécifiques à la méthode
    const methodMiddlewares: RequestHandler[] = [];

    // 1. Authentification & Autorisation
    const authRule = routeMeta.authorization;
    if (authRule) {
      methodMiddlewares.push(requireAuth); // Toujours requis si @authorize est utilisé

      if (authRule.level !== undefined) {
        methodMiddlewares.push(requireLevel(authRule.level)); // Vérification par niveau
      } else if (authRule.feature && authRule.action) {
        // Vérification par permission spécifique (feature/action)
        methodMiddlewares.push(requirePermission(authRule.feature, authRule.action));
      }
    }

    // 2. Validation Zod
    if (routeMeta.validationSchema) {
      methodMiddlewares.push(validateRequest(routeMeta.validationSchema));
    }

    // 3. Middlewares de Parsing de Query (ajoutés conditionnellement)
    if (routeMeta.canPaginate) {
      methodMiddlewares.push(parsePagination);
    }
    if (routeMeta.sortableFields !== undefined && routeMeta.sortableFields !== false) {
      // Passe les champs autorisés au middleware si c'est un tableau
      methodMiddlewares.push(parseSorting(routeMeta.sortableFields));
    }
    if (routeMeta.filterableFields !== undefined && routeMeta.filterableFields !== false) {
      methodMiddlewares.push(parseFiltering(routeMeta.filterableFields));
    }
    if (routeMeta.searchableFields !== undefined && routeMeta.searchableFields !== false) {
      methodMiddlewares.push(parseSearch(routeMeta.searchableFields));
    }

    // 4. Handler final du contrôleur (wrapper)
    const finalHandlerWrapper: RequestHandler = async (
      req: Request,
      res: Response,
      next: NextFunction,
    ) => {
      try {
        await Promise.resolve(handler.call(instance, req, res, next));
      } catch (error) {
        next(error);
      }
    };
    methodMiddlewares.push(finalHandlerWrapper);

    // Enregistrement de la route
    try {
      router[routeMeta.method](routeMeta.path, ...methodMiddlewares);
    } catch (error) {
      logger.error(
        error,
        `  Failed to register route: ${routeMeta.method.toUpperCase()} ${routeMeta.path} for ${ControllerClass.name}.${String(routeMeta.handlerName)}`,
      );
    }
  });
}
