import { type RequestHandler } from 'express';
import { type AnyZodObject } from 'zod';

import { type AuthorisationRule } from '@/modules/users/models/users.entity';

import { globalMetadataStorage, type HttpMethod } from './metadata.storage';
import logger from '../../lib/logger';

/**
 * Decorator to define a route on a controller method.
 * @param {HttpMethod} method HTTP method (get, post, etc.).
 * @param {string} path Route path (e.g., '/:id').
 */
export function route(method: HttpMethod, path: string): MethodDecorator {
  return (target: any, propertyKey: string | symbol) => {
    globalMetadataStorage.addRoute({
      target: target.constructor, // Target the class constructor
      handlerName: propertyKey,
      method,
      path,
    });
  };
}

// Shortcuts for common HTTP methods
// eslint-disable-next-line @typescript-eslint/naming-convention, @typescript-eslint/explicit-module-boundary-types
export const Get = (path: string) => route('get', path);
// eslint-disable-next-line @typescript-eslint/naming-convention, @typescript-eslint/explicit-module-boundary-types
export const Post = (path: string) => route('post', path);
// eslint-disable-next-line @typescript-eslint/naming-convention, @typescript-eslint/explicit-module-boundary-types
export const Put = (path: string) => route('put', path);
// eslint-disable-next-line @typescript-eslint/naming-convention, @typescript-eslint/explicit-module-boundary-types
export const Patch = (path: string) => route('patch', path);
// eslint-disable-next-line @typescript-eslint/naming-convention, @typescript-eslint/explicit-module-boundary-types
export const Delete = (path: string) => route('delete', path);

/**
 * Decorator to define authorization rules for a route.
 * Applies `requireAuth` middleware, followed by either `requireLevel` or `requirePermission`.
 * @param {AuthorisationRule} rule - An `AuthorisationRule` object ({ level: ... } OR { feature: ..., action: ... }).
 */
export function authorize(rule: AuthorisationRule): MethodDecorator {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    // Validate that the rule is correctly formed
    const hasLevel = rule.level !== undefined && rule.level !== null;
    const hasFeatureAction = !!rule.feature && !!rule.action;

    if (!hasLevel && !hasFeatureAction) {
      logger.error(
        `@authorize decorator on ${target.constructor.name}.${String(propertyKey)} requires either 'level' or both 'feature' and 'action'.`,
      );
      return;
    }
    if (hasLevel && hasFeatureAction) {
      logger.error(
        `@authorize decorator on ${target.constructor.name}.${String(propertyKey)} cannot have both 'level' and 'feature/action'.`,
      );
      return;
    }
    // Store the rule (which contains either level or feature/action)
    globalMetadataStorage.updateRouteMetadata(target.constructor, propertyKey, {
      authorization: rule,
    });
  };
}

/**
 * Decorator to mark a controller method as internal.
 * The registration logic will decide what to do with it (e.g., not expose it publicly).
 */
export function internal(): MethodDecorator {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    globalMetadataStorage.updateRouteMetadata(target.constructor, propertyKey, {
      isInternal: true,
    });
  };
}

/**
 * Decorator to attach a Zod validation schema to a route.
 * @param {AnyZodObject} schema Zod schema to validate { body, query, params }.
 */
export function validate(schema: AnyZodObject): MethodDecorator {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    globalMetadataStorage.updateRouteMetadata(target.constructor, propertyKey, {
      validationSchema: schema,
    });
  };
}

/**
 * Enables pagination, sorting, filtering, and searching for the route.
 * Stores flags or configurations in the metadata.
 * This is a convenience decorator that combines `sortable`, `filterable`, and `searchable`.
 */
export function paginate(
  options: {
    sortable?: boolean | string[];
    filterable?: boolean | string[];
    searchable?: boolean | string[];
  } = { sortable: true, filterable: true, searchable: true },
): MethodDecorator {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    globalMetadataStorage.updateRouteMetadata(target.constructor, propertyKey, {
      canPaginate: true,
    });
    if (options.sortable) sortable(options.sortable)(target, propertyKey, descriptor);
    if (options.filterable) filterable(options.filterable)(target, propertyKey, descriptor);
    if (options.searchable) searchable(options.searchable)(target, propertyKey, descriptor);
  };
}

/**
 * Enables sorting for the route.
 * @param {boolean | string[]} [allowedFields=true] - `true` (all fields), `false` (disabled), or `string[]` (allowed fields).
 */
export function sortable(allowedFields: boolean | string[] = true): MethodDecorator {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    globalMetadataStorage.updateRouteMetadata(target.constructor, propertyKey, {
      sortableFields: allowedFields,
    });
  };
}

/**
 * Enables full-text search for the route.
 * @param {boolean | string[]} [allowedFields=true] - `true` (search enabled, specific fields depend on implementation),
 *                                                  `false` (disabled), or `string[]` (potentially hints which fields are searchable).
 */
export function searchable(allowedFields: boolean | string[] = true): MethodDecorator {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    globalMetadataStorage.updateRouteMetadata(target.constructor, propertyKey, {
      searchableFields: allowedFields,
    });
  };
}

/**
 * Enables filtering for the route.
 * @param {boolean | string[]} [allowedFields=true] - `true` (all fields), `false` (disabled), or `string[]` (allowed fields).
 */
export function filterable(allowedFields: boolean | string[] = true): MethodDecorator {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    globalMetadataStorage.updateRouteMetadata(target.constructor, propertyKey, {
      filterableFields: allowedFields,
    });
  };
}

/**
 * Class Decorator to add middleware to all routes within the controller.
 * @param {RequestHandler} fn - The Express middleware function to add.
 */
export function middleware(fn: RequestHandler): ClassDecorator {
  return function (target: any) {
    if (typeof fn !== 'function') {
      logger.error(`Invalid middleware provided to @middleware decorator for class ${target.name}`);
      return;
    }
    globalMetadataStorage.addClassMiddleware(target, fn);
  };
}
