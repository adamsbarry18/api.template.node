import { Request, Response, NextFunction } from '@/common/http';
import logger from '@/lib/logger';
import { BadRequestError } from '../errors/httpErrors';
import { SORT_DIRECTION, FILTER_OPERATOR, deepCopy, isJson } from '@/common/utils';

const DEFAULT_PAGE_LIMIT = 10;
const MAX_PAGE_LIMIT = 100;

// Interfaces mises à jour avec les enums
export interface PaginationInfo {
  limit: number;
  offset: number;
  page: number;
}

export interface SortInfo {
  field: string;
  direction: SORT_DIRECTION;
}

export interface FilterInfo {
  field: string;
  operator: FILTER_OPERATOR;
  value: any;
}

export const parsePagination = (req: Request, res: Response, next: NextFunction): void => {
  try {
    const page = parseInt((req.query.page as string) || '1', 10);
    const limit = parseInt((req.query.limit as string) || `${DEFAULT_PAGE_LIMIT}`, 10);

    if (isNaN(page) || page < 1) throw new BadRequestError('Paramètre "page" invalide');
    if (isNaN(limit)) throw new BadRequestError(`"limit" doit être entre 1 et ${MAX_PAGE_LIMIT}`);

    req.allow.pagination = {
      limit: Math.min(limit, MAX_PAGE_LIMIT),
      page,
      offset: (page - 1) * limit,
    };
    next();
  } catch (error) {
    next(error);
  }
};

export const parseSorting = (allowedFields: boolean | string[] = true) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const sortBy = req.query.sortBy as string;
      const sortOrder = req.query.sortOrder as string;

      if (!sortBy) return next();

      const sortFields = sortBy.split(',').map((f) => f.trim());
      const sortDirections = sortOrder?.split(',').map((d) => d.trim().toLowerCase()) || [];

      if (allowedFields === false) throw new BadRequestError('Tri non autorisé');

      if (Array.isArray(allowedFields)) {
        const invalid = sortFields.find((f) => !allowedFields.includes(f));
        if (invalid) throw new BadRequestError(`Champ de tri invalide: ${invalid}`);
      }

      const sorting: SortInfo[] = sortFields.map((field, i) => {
        let direction = sortDirections[i] || SORT_DIRECTION.ASC;

        if (!Object.values(SORT_DIRECTION).includes(direction as SORT_DIRECTION)) {
          throw new BadRequestError('Direction de tri invalide');
        }

        return {
          field,
          direction: direction as SORT_DIRECTION,
        };
      });

      req.allow.sorting = sorting;
      next();
    } catch (error) {
      next(error);
    }
  };
};

export const parseFiltering = (allowedFields: boolean | string[] = true) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      req.allow.filters = [];
      const filters = req.query.filter;

      if (!filters || typeof filters !== 'object') return next();

      for (const field of Object.keys(filters)) {
        if (allowedFields === false) continue;
        if (Array.isArray(allowedFields) && !allowedFields.includes(field)) continue;

        const fieldFilters = filters[field];
        if (typeof fieldFilters !== 'object') continue;

        for (const [op, value] of Object.entries(fieldFilters)) {
          if (!Object.values(FILTER_OPERATOR).includes(op as FILTER_OPERATOR)) {
            logger.warn(`Opérateur de filtre ignoré: ${op}`);
            continue;
          }

          let parsedValue = value;
          if (typeof value === 'string') {
            if (isJson(value)) {
              parsedValue = deepCopy(JSON.parse(value));
            } else {
              parsedValue = tryParsePrimitive(value);
            }
          }

          req.allow.filters.push({
            field,
            operator: op as FILTER_OPERATOR,
            value: parsedValue,
          });
        }
      }
      next();
    } catch (error) {
      next(error);
    }
  };
};

export const parseSearch = (allowedFields: boolean | string[] = true) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const search = req.query.search as string;

      if (!search) return next();

      if (allowedFields === false || (Array.isArray(allowedFields) && allowedFields.length === 0)) {
        throw new BadRequestError('Recherche non autorisée');
      }

      req.allow.searchQuery = search.trim();
      next();
    } catch (error) {
      next(error);
    }
  };
};

function tryParsePrimitive(value: string): any {
  if (/^\d+$/.test(value)) return parseInt(value, 10);
  if (/^\d+\.\d+$/.test(value)) return parseFloat(value);
  if (value === 'true') return true;
  if (value === 'false') return false;
  return value;
}
