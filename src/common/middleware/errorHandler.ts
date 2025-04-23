import { Request, Response, NextFunction } from '../../config/http';
import {
  BaseError,
  ServerError,
  ValidationError,
  NotFoundError,
  ForbiddenError,
  UnauthorizedError,
  BadRequestError,
  DependencyError,
  ServiceUnavailableError,
} from '../errors/httpErrors';
import logger from '@/lib/logger';
import config from '@/config';
import { ZodError } from 'zod';

export const errorHandler = (err: Error, req: Request, res: Response, next: NextFunction): void => {
  let error: BaseError;

  logger.error(
    {
      err,
      stack: err.stack,
      url: req.originalUrl,
      method: req.method,
      ip: req.ip,
      body: config.NODE_ENV !== 'production' ? req.body : undefined,
      query: req.query,
    },
    `Error occurred: ${err.message}`,
  );

  // Specific handling for Zod errors to provide better client feedback.
  if (err instanceof ZodError) {
    error = new ValidationError(err.errors.map((e) => e.message));
  } else if (err instanceof BaseError) {
    error = err;
  } else {
    error = new ServerError('An unexpected error occurred');
  }

  // Unwrap nested BaseError if present in ServerError.data
  if (error instanceof ServerError && error.data && typeof error.data === 'object') {
    logger.error({ nestedData: error.data }, '[DEBUG] ServerError.data before unwrapping');
    const nested = error.data as any;
    if (
      'status' in nested &&
      typeof nested.status === 'number' &&
      typeof nested.name === 'string' &&
      typeof nested.message === 'string'
    ) {
      switch (nested.name) {
        case 'ForbiddenError':
          error = new ForbiddenError(nested.message);
          break;
        case 'NotFoundError':
          error = new NotFoundError(nested.message);
          break;
        case 'UnauthorizedError':
          error = new UnauthorizedError(nested.message);
          break;
        case 'BadRequestError':
          error = new BadRequestError(nested.message);
          break;
        case 'DependencyError':
          error = new DependencyError(nested.data ?? []);
          break;
        case 'ServiceUnavailableError':
          error = new ServiceUnavailableError(nested.message);
          break;
        case 'ValidationError':
          error = new ValidationError(nested.data ?? nested.message);
          break;
        default:
          // fallback sur le status si le nom n'est pas explicite
          if (nested.status === 403) error = new ForbiddenError(nested.message);
          else if (nested.status === 404) error = new NotFoundError(nested.message);
          else if (nested.status === 401) error = new UnauthorizedError(nested.message);
          else if (nested.status === 400) error = new BadRequestError(nested.message);
          else if (nested.status === 422)
            error = new ValidationError(nested.data ?? nested.message);
          else if (nested.status === 503) error = new ServiceUnavailableError(nested.message);
          else error = new BaseError('ERR_OTHER', nested.message, nested.data ?? null);
      }
    }
    logger.error({ unwrappedError: error }, '[DEBUG] Error after unwrapping');
  }

  // Build the error object for the error response.
  const errorPayload = {
    httpStatus: error.status,
    message:
      config.NODE_ENV === 'production' && error.status === 500
        ? 'Internal Server Error'
        : error.message,
    code: error.code,
    data:
      config.NODE_ENV !== 'production' || error.name === 'ValidationError' ? error.data : undefined,
    stack: config.NODE_ENV !== 'production' ? err.stack : undefined,
  };

  Object.keys(errorPayload).forEach((key) => {
    const k = key as keyof typeof errorPayload;
    if (errorPayload[k] === undefined) {
      delete errorPayload[k];
    }
  });

  res.status(error.status).json({ status: 'error', ...errorPayload });
};
