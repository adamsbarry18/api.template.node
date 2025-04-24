import { Router, RequestHandler } from 'express';
import { globalMetadataStorage, RouteMetadataArgs } from './metadata.storage';
import { Request, Response, NextFunction } from '../../config/http';
import logger from '../../lib/logger';
import {
  requireAuth,
  requireLevel,
  requirePermission,
  validateRequest,
  requireInternalUser, // <-- ajout
} from '../middleware/authentication';
import {
  parseFiltering,
  parsePagination,
  parseSearch,
  parseSorting,
} from '../middleware/queryParssing';

/**
 * Registers routes defined by decorators within a Controller class onto an Express router.
 * @param {Router} router The Express router to register routes on.
 * @param {Function} ControllerClass The Controller class constructor containing the decorators.
 * @param {object} [options] Options to control registration (e.g., ignore internal routes).
 * @param {boolean} [options.ignoreInternal=true] Whether to skip routes marked with `@internal`.
 */
export function registerRoutes(
  router: Router,
  ControllerClass: { new (...args: any[]): any },
  options: { ignoreInternal?: boolean } = { ignoreInternal: false },
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

    // Build the array of middlewares specific to this method/route
    const methodMiddlewares: RequestHandler[] = [];

    // Step 1: Internal route protection
    if (routeMeta.isInternal) {
      methodMiddlewares.push(requireAuth, requireInternalUser);
    }
    // Step 2: Authorization (if defined by @authorize)
    else if (routeMeta.authorization) {
      methodMiddlewares.push(requireAuth);
      const authRule = routeMeta.authorization;
      if (authRule.level !== undefined) {
        methodMiddlewares.push(requireLevel(authRule.level));
      } else if (authRule.feature && authRule.action) {
        methodMiddlewares.push(requirePermission(authRule.feature, authRule.action));
      }
    }
    // Step 3: Zod Validation (if defined by @validate)
    if (routeMeta.validationSchema) {
      methodMiddlewares.push(validateRequest(routeMeta.validationSchema));
    }

    // Step 4: Query Parsing Middlewares (added conditionally based on decorators like @paginate, @sortable, etc.)
    if (routeMeta.canPaginate) {
      methodMiddlewares.push(parsePagination);
    }
    if (routeMeta.sortableFields !== undefined && routeMeta.sortableFields !== false) {
      methodMiddlewares.push(parseSorting(routeMeta.sortableFields));
    }
    if (routeMeta.filterableFields !== undefined && routeMeta.filterableFields !== false) {
      methodMiddlewares.push(parseFiltering(routeMeta.filterableFields));
    }
    if (routeMeta.searchableFields !== undefined && routeMeta.searchableFields !== false) {
      methodMiddlewares.push(parseSearch(routeMeta.searchableFields));
    }

    // Step 5: Final Controller Handler (wrapped to catch async errors)
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
