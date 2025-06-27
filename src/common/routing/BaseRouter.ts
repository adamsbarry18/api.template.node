import { type Request, type Response, type NextFunction } from '@/config/http';

import { type FilterInfo, type PaginationInfo, type SortInfo } from '../middleware/queryParssing';
import logger from '@/lib/logger';
import config from '@/config';
import { BaseError } from '../errors/httpErrors';

/**
 * Extends the Express Request interface to include properties
 * added by our parsing middlewares.
 */
interface RequestWithQueryInfo extends Request {
  pagination?: PaginationInfo;
  sorting?: SortInfo[];
  filters?: FilterInfo[];
  searchQuery?: string;
}

/**
 * Standardized success response structure (JSend-like).
 */
interface SuccessResponse<T> {
  status: 'success';
  data: T;
  meta?: {
    pagination?: PaginationInfo;
    sorting?: SortInfo[];
    filters?: FilterInfo[];
    searchQuery?: string;
  };
}

/**
 * Abstract base class for controllers, providing common utilities.
 */
export abstract class BaseRouter {
  /**
   * Executes an asynchronous business logic function, formats the standardized success response
   * (including request metadata if present), and delegates errors to the global handler via next().
   *
   * @template T The type of the data returned by the business logic function.
   * @param {Response} res Express Response object.
   * @param {RequestWithQueryInfo} req Express Request object (typed with our query info).
   * @param {NextFunction} next Express NextFunction.
   * @param {() => Promise<T>} promiseFn Function returning a promise with the business result.
   * @param {number} [statusCode=200] Success HTTP status code (default: 200, use 201 for creation).
   */
  protected async pipe<T>(
    res: Response,
    req: RequestWithQueryInfo,
    next: NextFunction,
    promiseFn: () => Promise<T>,
    statusCode = 200,
  ): Promise<void> {
    try {
      const result = await promiseFn();

      if (result === null || result === undefined) {
        if (statusCode === 204) {
          res.status(204).send();
          return;
        } else {
          res.status(statusCode).json({ status: 'success', data: null });
          return;
        }
      }
      const meta: SuccessResponse<T>['meta'] = {};
      let hasMetadata = false;
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
      const responseBody: SuccessResponse<T> = {
        status: 'success',
        data: result,
        ...(hasMetadata && { meta: meta }),
      };
      res.status(statusCode).json(responseBody);
    } catch (error) {
      // En mode test, ne pas logger les erreurs attendues (NotFoundError, BadRequestError, DependencyError)
      const isExpectedTestError =
        config.NODE_ENV === 'test' &&
        error instanceof BaseError &&
        [
          'ERR_NOT_FOUND',
          'ERR_BAD_REQUEST',
          'ERR_FORBIDDEN',
          'ERR_UNAUTHORIZED',
          'ERR_DEPENDENCY',
        ].includes(error.code);

      if (!isExpectedTestError) {
        logger.error(error, `Error during piped execution for ${req.method} ${req.path}`);
      }
      next(error);
    }
  }

  // Add other utility methods here if needed
  // protected getUserFromRequest(req: RequestWithQueryInfo): Express.User | undefined {
  //    return req.user;
  // }
}
