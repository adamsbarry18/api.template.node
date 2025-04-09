import { AnyZodObject } from 'zod';
import { globalMetadataStorage, HttpMethod } from './metadata.storage';
import { RequestHandler } from 'express';
import { AuthorisationRule } from '@/modules/users/models/users.types';
import logger from '@/lib/logger';

/**
 * Décorateur pour définir une route sur une méthode de contrôleur.
 * @param method Méthode HTTP (get, post, etc.)
 * @param path Chemin de la route (ex: '/:id')
 */
export function route(method: HttpMethod, path: string): MethodDecorator {
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    globalMetadataStorage.addRoute({
      target: target.constructor, // Cible le constructeur de la classe
      handlerName: propertyKey,
      method,
      path,
    });
  };
}

// Raccourcis pour les méthodes HTTP courantes
export const Get = (path: string) => route('get', path);
export const Post = (path: string) => route('post', path);
export const Put = (path: string) => route('put', path);
export const Patch = (path: string) => route('patch', path);
export const Delete = (path: string) => route('delete', path);

/**
 * Décorateur pour définir les règles d'autorisation d'une route.
 * Applique `requireAuth` puis soit `requireLevel`, soit `requirePermission`.
 * @param rule - Un objet `AuthorisationRule` ({ level: ... } OU { feature: ..., action: ... }).
 */
export function authorize(rule: AuthorisationRule): MethodDecorator {
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    // Valider que la règle est correctement formée
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
    // Stocker la règle (qui contient soit level, soit feature/action)
    globalMetadataStorage.updateRouteMetadata(target.constructor, propertyKey, {
      authorization: rule,
    });
  };
}

/**
 * Décorateur pour marquer une méthode de contrôleur comme interne.
 * La logique d'enregistrement décidera quoi faire avec (ex: ne pas l'exposer publiquement).
 */
export function internal(): MethodDecorator {
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    globalMetadataStorage.updateRouteMetadata(target.constructor, propertyKey, {
      isInternal: true,
    });
  };
}

/**
 * Décorateur pour attacher un schéma de validation Zod à une route.
 * @param schema Schéma Zod pour valider { body, query, params }.
 */
export function validate(schema: AnyZodObject): MethodDecorator {
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    globalMetadataStorage.updateRouteMetadata(target.constructor, propertyKey, {
      validationSchema: schema,
    });
  };
}

/**
 * Active la pagination, le tri, le filtrage et la recherche pour la route.
 * Stocke des flags ou des configurations dans les métadonnées.
 */
export function paginate(
  options: {
    sortable?: boolean | string[];
    filterable?: boolean | string[];
    searchable?: boolean | string[];
  } = { sortable: true, filterable: true, searchable: true },
): MethodDecorator {
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
 * Active le tri pour la route.
 * @param allowedFields - `true` (tous champs), `false` (désactivé), ou `string[]` (champs autorisés).
 */
export function sortable(allowedFields: boolean | string[] = true): MethodDecorator {
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    globalMetadataStorage.updateRouteMetadata(target.constructor, propertyKey, {
      sortableFields: allowedFields,
    });
  };
}

/**
 * Active la recherche textuelle pour la route.
 * @param allowedFields - `true` (tous champs), `false` (désactivé), ou `string[]` (champs autorisés pour la recherche).
 */
export function searchable(allowedFields: boolean | string[] = true): MethodDecorator {
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    globalMetadataStorage.updateRouteMetadata(target.constructor, propertyKey, {
      searchableFields: allowedFields,
    });
  };
}

/**
 * Active le filtrage pour la route.
 * @param allowedFields - `true` (tous champs), `false` (désactivé), ou `string[]` (champs autorisés pour le filtrage).
 */
export function filterable(allowedFields: boolean | string[] = true): MethodDecorator {
  return (target: any, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    globalMetadataStorage.updateRouteMetadata(target.constructor, propertyKey, {
      filterableFields: allowedFields,
    });
  };
}

/**
 * Décorateur de Classe pour ajouter un middleware à toutes les routes du contrôleur.
 * @param fn - Le middleware Express à ajouter.
 */
export function middleware(fn: RequestHandler): ClassDecorator {
  // Utiliser 'any' car ClassDecorator cible une fonction constructeur
  return function (target: any) {
    // Vérifier que fn est bien une fonction middleware
    if (typeof fn !== 'function') {
      logger.error(`Invalid middleware provided to @middleware decorator for class ${target.name}`);
      return;
    }
    globalMetadataStorage.addClassMiddleware(target, fn);
  };
}
