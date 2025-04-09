import { AnyZodObject } from 'zod';
import { RequestHandler } from 'express';
import { AuthorisationRule } from '@/modules/users/models/users.types';

export type HttpMethod = 'get' | 'post' | 'put' | 'patch' | 'delete';

// Structure des métadonnées pour une route spécifique (méthode)
export interface RouteMetadataArgs {
  path: string;
  method: HttpMethod;
  handlerName: string | symbol;
  target: Function; // Constructeur de la classe Controller
  isInternal?: boolean;
  // Stocke la règle d'autorisation (soit level, soit feature/action)
  authorization?: AuthorisationRule;
  validationSchema?: AnyZodObject;
  // Ajouter des flags pour les autres décorateurs
  canPaginate?: boolean;
  sortableFields?: string[] | boolean; // true = tous champs, string[] = champs spécifiques
  filterableFields?: string[] | boolean;
  searchableFields?: string[] | boolean;
}

// Ajouter une structure pour les métadonnées de classe (pour @middleware)
export interface ClassMetadataArgs {
  target: Function;
  middlewares: RequestHandler[];
}

export class MetadataStorage {
  private routes: RouteMetadataArgs[] = [];
  private classMiddlewares: ClassMetadataArgs[] = []; // Stockage pour @middleware

  // --- addRoute, getRoutesForTarget, updateRouteMetadata (légèrement adaptés) ---
  addRoute(args: RouteMetadataArgs) {
    const existingIndex = this.routes.findIndex(
      (r) => r.target === args.target && r.handlerName === args.handlerName,
    );
    if (existingIndex === -1) {
      this.routes.push(args);
    } else {
      // Fusionner si un autre décorateur ajoute des infos
      Object.assign(this.routes[existingIndex], args);
    }
  }

  getRoutesForTarget(target: Function): RouteMetadataArgs[] {
    return this.routes.filter((route) => route.target === target);
  }

  updateRouteMetadata(
    target: Function,
    handlerName: string | symbol,
    update: Partial<RouteMetadataArgs>,
  ) {
    let route = this.routes.find((r) => r.target === target && r.handlerName === handlerName);
    if (route) {
      Object.assign(route, update);
    } else {
      // Créer une entrée partielle si nécessaire (ex: @paginate avant @Get)
      this.routes.push({ target, handlerName, ...update } as RouteMetadataArgs);
    }
  }

  // --- Méthodes pour les middlewares de classe ---
  addClassMiddleware(target: Function, middleware: RequestHandler) {
    let classMeta = this.classMiddlewares.find((cm) => cm.target === target);
    if (!classMeta) {
      classMeta = { target, middlewares: [] };
      this.classMiddlewares.push(classMeta);
    }
    classMeta.middlewares.push(middleware);
  }

  getClassMiddlewares(target: Function): RequestHandler[] {
    return this.classMiddlewares.find((cm) => cm.target === target)?.middlewares ?? [];
  }
}

export const globalMetadataStorage = new MetadataStorage();
