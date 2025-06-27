import { type FindOptionsWhere, type FindOptionsOrder } from 'typeorm';
import { type Request } from '@/config/http';

/**
 * Converts request filters and sorting from middleware into TypeORM FindOptionsWhere and FindOptionsOrder.
 * @param req The Express Request object with parsed filters and sorting.
 * @returns An object containing TypeORM filters and sort options.
 */
export function buildTypeORMCriteria(req: Request): {
  filters: FindOptionsWhere<any>;
  sort: FindOptionsOrder<any>;
} {
  const filters: FindOptionsWhere<any> = {};
  if (req.filters) {
    req.filters.forEach((filter) => {
      // Assuming 'eq' operator for simplicity based on parseFiltering middleware
      (filters as any)[filter.field] = filter.value;
    });
  }

  const sort: FindOptionsOrder<any> = {};
  if (req.sorting) {
    req.sorting.forEach((s) => {
      (sort as any)[s.field] = s.direction;
    });
  }

  return { filters, sort };
}
