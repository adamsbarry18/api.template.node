import { Request, Response, NextFunction } from '@/common/http';
import logger from '@/lib/logger';
import { BadRequestError } from '../errors/httpErrors';

const DEFAULT_PAGE_LIMIT = 10;
const MAX_PAGE_LIMIT = 100;

/** Interface pour les informations de pagination attachées à req */
export interface PaginationInfo {
  limit: number;
  offset: number;
  page: number;
}
/** Interface pour les informations de tri attachées à req */
export interface SortInfo {
  field: string;
  direction: 'ASC' | 'DESC';
}
/** Interface pour les informations de filtre attachées à req */
export interface FilterInfo {
  field: string;
  operator: string; // Ex: eq, ne, gt, lt, contains, etc. (à définir)
  value: any;
}
// Étendre l'interface Request d'Express
declare global {
  namespace Express {
    interface Request {
      pagination?: PaginationInfo;
      sorting?: SortInfo[]; // Permettre le tri multiple
      filters?: FilterInfo[]; // Permettre les filtres multiples
      searchQuery?: string;
    }
  }
}

/** Middleware pour parser la pagination (page, limit) */
export const parsePagination = (req: Request, res: Response, next: NextFunction): void => {
  try {
    const page = parseInt((req.query.page as string) || '1', 10);
    const limit = parseInt((req.query.limit as string) || `${DEFAULT_PAGE_LIMIT}`, 10);

    if (isNaN(page) || page < 1) {
      throw new BadRequestError('Invalid "page" query parameter. Must be a positive integer.');
    }
    if (isNaN(limit) || limit < 1 || limit > MAX_PAGE_LIMIT) {
      throw new BadRequestError(
        `Invalid "limit" query parameter. Must be an integer between 1 and ${MAX_PAGE_LIMIT}.`,
      );
    }

    req.pagination = {
      limit: limit,
      page: page,
      offset: (page - 1) * limit,
    };
    next();
  } catch (error) {
    next(error); // Passe à l'errorHandler global
  }
};

/** Middleware pour parser le tri (sortBy, sortOrder) */
export const parseSorting =
  (allowedFields: boolean | string[] = true) =>
  (req: Request, res: Response, next: NextFunction): void => {
    try {
      const sortBy = req.query.sortBy as string;
      const sortOrderQuery = ((req.query.sortOrder as string) || 'ASC').toUpperCase();

      if (!sortBy) {
        // Pas de tri demandé
        return next();
      }

      // Valider sortOrder
      if (sortOrderQuery !== 'ASC' && sortOrderQuery !== 'DESC') {
        throw new BadRequestError('Invalid "sortOrder" query parameter. Must be "ASC" or "DESC".');
      }
      const sortOrder = sortOrderQuery as 'ASC' | 'DESC';

      // Valider sortBy contre les champs autorisés
      if (Array.isArray(allowedFields) && !allowedFields.includes(sortBy)) {
        throw new BadRequestError(
          `Invalid "sortBy" query parameter. Allowed fields: ${allowedFields.join(', ')}.`,
        );
      }
      // Si allowedFields est false, interdire tout tri (ne devrait pas arriver si le middleware est ajouté conditionnellement)
      if (allowedFields === false) {
        throw new BadRequestError('Sorting is not allowed for this resource.');
      }

      // TODO: Gérer le tri multiple si nécessaire (ex: sortBy=name,createdAt&sortOrder=ASC,DESC)

      req.sorting = [{ field: sortBy, direction: sortOrder }];
      next();
    } catch (error) {
      next(error);
    }
  };

/** Middleware pour parser les filtres (ex: filter[status]=active) - IMPLEMENTATION SIMPLIFIÉE */
export const parseFiltering =
  (allowedFields: boolean | string[] = true) =>
  (req: Request, res: Response, next: NextFunction): void => {
    // Ceci est un exemple très basique. Une vraie implémentation nécessiterait :
    // - Un format de query param standard (ex: filter[field][operator]=value)
    // - Un parsing robuste de ce format
    // - La validation des opérateurs autorisés (eq, ne, gt, lt, contains...)
    // - La validation des champs contre allowedFields
    // - La conversion des types de valeurs (string vers number/boolean/date)

    req.filters = []; // Initialiser
    if (req.query.filter && typeof req.query.filter === 'object') {
      logger.debug({ filtersQuery: req.query.filter }, 'Parsing filters (basic)...');
      // Exemple très simple : filter[email]=test@test.com
      for (const field in req.query.filter) {
        if (Array.isArray(allowedFields) && !allowedFields.includes(field)) {
          logger.warn(`Filtering ignored for unauthorized field: ${field}`);
          continue;
        }
        if (allowedFields === false) continue;

        // Suppose un opérateur 'eq' par défaut pour cet exemple simple
        req.filters.push({
          field: field,
          operator: 'eq', // Simplifié !
          value: req.query.filter[field],
        });
      }
    }
    next();
  };

/** Middleware pour parser la recherche textuelle */
export const parseSearch =
  (allowedFields: boolean | string[] = true) =>
  (req: Request, res: Response, next: NextFunction): void => {
    if (req.query.search && typeof req.query.search === 'string' && allowedFields) {
      req.searchQuery = req.query.search.trim();
      // La logique de quels champs sont fouillés (allowedFields) sera utilisée dans le repository/service
    }
    next();
  };
