import { type Request, type Response, type NextFunction } from '@/config/http';
import logger from '@/lib/logger';

import { BadRequestError } from '../errors/httpErrors';

const DEFAULT_PAGE_LIMIT = 10;
const MAX_PAGE_LIMIT = 100;
export interface PaginationInfo {
  limit: number;
  offset: number;
  page: number;
}
export interface SortInfo {
  field: string;
  direction: 'ASC' | 'DESC';
}
export interface FilterInfo {
  field: string;
  operator: string;
  value: any;
}

/**
 * Middleware to parse pagination parameters (`page`, `limit`) from query string.
 * Attaches a `PaginationInfo` object to `req.pagination`.
 * @throws {BadRequestError} If `page` or `limit` are invalid.
 */
export const parsePagination = (req: Request, res: Response, next: NextFunction): void => {
  try {
    const page = parseInt((req.query.page as string) || '1', 10);
    const limit = parseInt((req.query.limit as string) || String(DEFAULT_PAGE_LIMIT), 10);

    if (isNaN(page) || page < 1) {
      throw new BadRequestError('Invalid "page" query parameter. Must be a positive integer.');
    }

    if (isNaN(limit) || limit < 1 || limit > MAX_PAGE_LIMIT) {
      throw new BadRequestError(
        `Invalid "limit" query parameter. Must be an integer between 1 and ${MAX_PAGE_LIMIT}.`,
      );
    }

    req.pagination = {
      limit,
      page,
      offset: (page - 1) * limit,
    };

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Middleware factory to parse sorting parameters (`sortBy`, `sortOrder`) from query string.
 * Attaches an array of `SortInfo` objects to `req.sorting`.
 * @param {boolean | string[]} [allowedFields=true] List of fields allowed for sorting.
 *        `true` allows any field, `false` disallows sorting, an array specifies allowed fields.
 * @returns {Function} Express middleware function.
 * @throws {BadRequestError} If `sortOrder` is invalid or `sortBy` is not allowed.
 */
export const parseSorting =
  (allowedFields: boolean | string[] = true) =>
  (req: Request, res: Response, next: NextFunction): void => {
    try {
      const sortBy = req.query.sortBy as string;
      if (!sortBy) {
        return next();
      }

      const sortOrderQuery = ((req.query.sortOrder as string) || 'ASC').toUpperCase();

      if (sortOrderQuery !== 'ASC' && sortOrderQuery !== 'DESC') {
        throw new BadRequestError('Invalid "sortOrder" query parameter. Must be "ASC" or "DESC".');
      }

      const sortOrder = sortOrderQuery;
      if (Array.isArray(allowedFields) && !allowedFields.includes(sortBy)) {
        throw new BadRequestError(
          `Invalid "sortBy" query parameter. Allowed fields: ${allowedFields.join(', ')}.`,
        );
      }

      if (allowedFields === false) {
        throw new BadRequestError('Sorting is not allowed for this resource.');
      }

      req.sorting = [{ field: sortBy, direction: sortOrder }];
      next();
    } catch (error) {
      next(error);
    }
  };

/**
 * Middleware factory to parse filtering parameters (e.g., `filter[status]=active`).
 * Attaches an array of `FilterInfo` objects to `req.filters`.
 * Currently supports basic equality filters (`operator: 'eq'`).
 * @param {boolean | string[]} [allowedFields=true] List of fields allowed for filtering.
 *        `true` allows any field, `false` disallows filtering, an array specifies allowed fields.
 * @returns {Function} Express middleware function.
 */
export const parseFiltering =
  (allowedFields: boolean | string[] = true) =>
  (req: Request, res: Response, next: NextFunction): void => {
    req.filters = [];

    if (req.query.filter && typeof req.query.filter === 'object') {
      logger.debug({ filtersQuery: req.query.filter }, 'Parsing filters...');
      for (const field in req.query.filter) {
        if (Array.isArray(allowedFields) && !allowedFields.includes(field)) {
          logger.warn(`Filtering ignored for unauthorized field: ${field}`);
          continue;
        }

        if (allowedFields === false) continue;
        req.filters.push({
          field,
          operator: 'eq',
          value: (req.query.filter as import('qs').ParsedQs)[field],
        });
      }
    }

    next();
  };

/**
 * Middleware factory to parse the search query parameter (`search`).
 * Attaches the search string to `req.searchQuery`.
 * @param {boolean | string[]} [allowedFields=true] Indicates if search is allowed.
 *        The actual fields searched are determined by the service/repository layer.
 *        `true` allows search, `false` disallows it. Array is not used here but kept for consistency.
 * @returns {Function} Express middleware function.
 */
export const parseSearch =
  (allowedFields: boolean | string[] = true) =>
  (req: Request, res: Response, next: NextFunction): void => {
    if (req.query.search && typeof req.query.search === 'string' && allowedFields) {
      req.searchQuery = req.query.search.trim();
    }

    next();
  };
