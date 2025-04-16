import { AnyZodObject } from 'zod';
import { RequestHandler } from 'express';
import { AuthorisationRule } from '@/modules/users/models/users.types';

/** Defines the allowed HTTP methods for routes. */
export type HttpMethod = 'get' | 'post' | 'put' | 'patch' | 'delete';

/**
 * Interface defining the structure of metadata collected for a specific route (controller method).
 */
export interface RouteMetadataArgs {
  path: string;
  method: HttpMethod;
  handlerName: string | symbol;
  target: Function;
  isInternal?: boolean;
  authorization?: AuthorisationRule;
  validationSchema?: AnyZodObject;
  canPaginate?: boolean;
  sortableFields?: string[] | boolean;
  filterableFields?: string[] | boolean;
  searchableFields?: string[] | boolean;
}

/**
 * Interface defining the structure of metadata collected for a controller class (e.g., class-level middleware).
 */
export interface ClassMetadataArgs {
  target: Function;
  middlewares: RequestHandler[];
}

/**
 * Stores metadata collected from decorators (@route, @authorize, @validate, @middleware, etc.)
 * for controller classes and their methods. This metadata is used during the route registration process.
 */
export class MetadataStorage {
  private routes: RouteMetadataArgs[] = [];
  private classMiddlewares: ClassMetadataArgs[] = [];

  /**
   * Adds or merges route metadata collected from method decorators.
   * If metadata for the same target/handler already exists, it merges the new arguments.
   * @param {RouteMetadataArgs} args Metadata arguments for the route.
   */
  addRoute(args: RouteMetadataArgs) {
    const existingIndex = this.routes.findIndex(
      (r) => r.target === args.target && r.handlerName === args.handlerName,
    );
    if (existingIndex === -1) {
      this.routes.push(args);
    } else {
      Object.assign(this.routes[existingIndex], args);
    }
  }

  /**
   * Retrieves all route metadata associated with a specific controller class constructor.
   * @param {Function} target The controller class constructor.
   * @returns {RouteMetadataArgs[]} An array of route metadata for the target class.
   */
  getRoutesForTarget(target: Function): RouteMetadataArgs[] {
    return this.routes.filter((route) => route.target === target);
  }

  /**
   * Updates existing route metadata or creates a partial entry if none exists yet.
   * This allows decorators like `@paginate` or `@authorize` to be applied before the main `@Get`/`@Post` decorator.
   * @param {Function} target The controller class constructor.
   * @param {string | symbol} handlerName The name of the controller method.
   * @param {Partial<RouteMetadataArgs>} update The partial metadata to merge or add.
   */
  updateRouteMetadata(
    target: Function,
    handlerName: string | symbol,
    update: Partial<RouteMetadataArgs>,
  ) {
    let route = this.routes.find((r) => r.target === target && r.handlerName === handlerName);
    if (route) {
      Object.assign(route, update);
    } else {
      this.routes.push({ target, handlerName, ...update } as RouteMetadataArgs);
    }
  }

  /**
   * Adds a middleware function to be applied at the class level (for all routes in the controller).
   * @param {Function} target The controller class constructor.
   * @param {RequestHandler} middleware The middleware function to add.
   */
  addClassMiddleware(target: Function, middleware: RequestHandler) {
    let classMeta = this.classMiddlewares.find((cm) => cm.target === target);
    if (!classMeta) {
      classMeta = { target, middlewares: [] };
      this.classMiddlewares.push(classMeta);
    }
    classMeta.middlewares.push(middleware);
  }

  /**
   * Retrieves all middleware functions associated with a specific controller class constructor.
   * @param {Function} target The controller class constructor.
   * @returns {RequestHandler[]} An array of class-level middleware functions, or an empty array if none.
   */
  getClassMiddlewares(target: Function): RequestHandler[] {
    return this.classMiddlewares.find((cm) => cm.target === target)?.middlewares ?? [];
  }
}

/**
 * Global singleton instance of MetadataStorage used by decorators and the route registration process.
 */
export const globalMetadataStorage = new MetadataStorage();
