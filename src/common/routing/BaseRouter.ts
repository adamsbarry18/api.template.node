import { Request, Response, NextFunction } from '@/common/http';
import { Logger } from 'pino';
import logger from '@/lib/logger';
import { FilterInfo, PaginationInfo, SortInfo } from '../middleware/queryParssing';

/**
 * Étend l'interface Request d'Express pour inclure les propriétés
 * ajoutées par nos middlewares de parsing.
 */
interface RequestWithQueryInfo extends Request {
  pagination?: PaginationInfo;
  sorting?: SortInfo[];
  filters?: FilterInfo[];
  searchQuery?: string;
  // Inclure 'allow' si vous l'utilisez toujours (ce concept venait de l'ancien Router)
  // allow?: { pagination?: boolean, sort?: boolean, filters?: boolean, search?: boolean };
}

/**
 * Structure de réponse succès standardisée
 */
interface SuccessResponse<T> {
  status: 'success';
  data: T;
  meta?: {
    pagination?: PaginationInfo; // Inclut potentiellement totalItems/totalPages
    sorting?: SortInfo[];
    filters?: FilterInfo[];
    searchQuery?: string;
  };
}

/**
 * Classe de base abstraite pour les contrôleurs, fournissant des utilitaires communs.
 */
export abstract class BaseRouter {
  // Logger protégé, initialisé directement avec l'instance importée
  protected readonly logger: Logger = logger;

  /**
   * Exécute une fonction métier asynchrone, formate la réponse succès standardisée
   * (incluant les métadonnées de requête si présentes) et délègue les erreurs au
   * gestionnaire global via next().
   *
   * @param res Objet Response d'Express
   * @param req Objet Request d'Express (typé avec nos infos de query)
   * @param next Fonction NextFunction d'Express
   * @param promiseFn Fonction retournant une promesse avec le résultat métier.
   * @param statusCode Code HTTP de succès (défaut: 200, utiliser 201 pour création).
   */
  protected async pipe<T>(
    res: Response,
    // Utiliser notre type Request étendu ici
    req: RequestWithQueryInfo,
    next: NextFunction,
    promiseFn: () => Promise<T>,
    statusCode = 200,
  ): Promise<void> {
    try {
      const result = await promiseFn();

      // Gérer les succès sans contenu (ex: après DELETE ou si le service retourne null/undefined)
      if (result === null || result === undefined) {
        if (statusCode === 204) {
          // Code 204 No Content: réponse vide
          res.status(204).send();
          return;
        } else {
          // Pour les autres codes (ex: 200), envoyer succès avec data: null
          res.status(statusCode).json({ status: 'success', data: null });
          return;
        }
      }

      // Construire les métadonnées à partir de req si elles existent
      const meta: SuccessResponse<T>['meta'] = {};
      let hasMetadata = false;
      // Vérifier l'existence des propriétés sur req (maintenant correctement typé)
      if (req.pagination) {
        meta.pagination = req.pagination;
        hasMetadata = true;
      }
      if (req.sorting) {
        meta.sorting = req.sorting;
        hasMetadata = true;
      }
      if (req.filters) {
        meta.filters = req.filters;
        hasMetadata = true;
      }
      if (req.searchQuery) {
        meta.searchQuery = req.searchQuery;
        hasMetadata = true;
      }

      // Construire le corps de la réponse succès
      const responseBody: SuccessResponse<T> = {
        status: 'success',
        data: result,
        ...(hasMetadata && { meta: meta }), // Ajouter meta si non vide
      };

      // Envoyer la réponse JSON
      res.status(statusCode).json(responseBody);
    } catch (error) {
      // Gérer les erreurs attrapées durant l'exécution de promiseFn
      // Log l'erreur avec le logger de l'instance (maintenant correctement typé)
      this.logger.error(error, `Error during piped execution for ${req.method} ${req.path}`);
      // Déléguer au gestionnaire d'erreurs global via next()
      next(error);
    }
  }

  // Ajoutez ici d'autres méthodes utilitaires si nécessaire
  // protected getUserFromRequest(req: RequestWithQueryInfo): Express.User | undefined {
  //    return req.user;
  // }
}
