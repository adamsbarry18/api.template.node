import { type Request, type Response, type NextFunction } from '@/config/http';

import { BadRequestError } from '../errors/httpErrors';

export enum FilterOperator {
  EQ = 'eq',
  LT = 'lt',
  LTE = 'lte',
  GT = 'gt',
  GTE = 'gte',
  IN = 'in',
  CONTAINS = 'contains',
}

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
    const filters: FilterInfo[] = req.filters;

    const queryParams = req.query;

    Object.entries(queryParams).forEach(([field, value]) => {
      // Ignore pagination, sorting, search, and order parameters
      if (['page', 'limit', 'sortBy', 'sortOrder', 'q', 'order'].includes(field)) {
        return;
      }

      // Handle nested filter object format (e.g., ?filter[city]=Paris&filter[isActive]=true)
      if (field === 'filter' && typeof value === 'object') {
        Object.entries(value as Record<string, any>).forEach(([filterField, filterValue]) => {
          if (Array.isArray(allowedFields) && !allowedFields.includes(filterField)) {
            return;
          }

          if (allowedFields === false) return;

          let parsedValue: any = filterValue;
          // Attempt to convert string 'true' or 'false' to boolean
          if (typeof filterValue === 'string') {
            if (filterValue.toLowerCase() === 'true') {
              parsedValue = true;
            } else if (filterValue.toLowerCase() === 'false') {
              parsedValue = false;
            }
          }

          filters.push({
            field: filterField,
            operator: FilterOperator.EQ, // Assuming 'eq' operator for simplicity
            value: parsedValue,
          });
        });
        return;
      }

      // Handle top-level filter parameters (e.g., ?city=Paris&isActive=true)
      if (Array.isArray(allowedFields) && !allowedFields.includes(field)) {
        return;
      }

      if (allowedFields === false) return;

      if (value !== undefined && value !== null) {
        let parsedValue: any = value;
        // Attempt to convert string 'true' or 'false' to boolean
        if (typeof value === 'string') {
          if (value.toLowerCase() === 'true') {
            parsedValue = true;
          } else if (value.toLowerCase() === 'false') {
            parsedValue = false;
          }
        }
        filters.push({
          field,
          operator: FilterOperator.EQ,
          value: parsedValue,
        });
      }
    });
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
    if (req.query.q && typeof req.query.q === 'string' && allowedFields) {
      req.searchQuery = req.query.q.trim();
    }

    next();
  };
