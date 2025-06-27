import { ZodError } from 'zod';

import config from '@/config';
import logger from '@/lib/logger';

import { type Request, type Response, type NextFunction } from '../../config/http';
import { BaseError, ServerError, ValidationError } from '../errors/httpErrors';

export const errorHandler = (
  err: Error,
  req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction,
): void => {
  let error: BaseError;

  // Log détaillé de l'erreur, même en production
  // Affiche toutes les propriétés de l'objet Error
  // eslint-disable-next-line no-console
  if (config.NODE_ENV === 'production') {
    console.error('Erreur API détaillée:', JSON.stringify(err, Object.getOwnPropertyNames(err)));
  }

  logger.error(
    {
      err: err instanceof Error ? {
        ...err, // d'abord toutes les props custom
        name: err.name,
        message: err.message,
        stack: err.stack,
      } : err,
      url: req.originalUrl,
      method: req.method,
      ip: req.ip,
      body: config.NODE_ENV !== 'production' ? req.body : undefined,
      query: req.query,
    },
    `Error occurred: ${err.message}`,
  );

  if (err instanceof ZodError) {
    error = new ValidationError(err.errors.map((e) => e.message));
  } else if (err instanceof BaseError) {
    error = err;
  } else {
    error = new ServerError('An unexpected error occurred');
  }

  const message =
    config.NODE_ENV === 'production' && error.status >= 500
      ? 'Internal Server Error'
      : error.message;

  const errorPayload: Record<string, any> = {
    message: message,
    code: error.code,
    data:
      error instanceof ValidationError || config.NODE_ENV !== 'production' ? error.data : undefined,
    stack: config.NODE_ENV !== 'production' ? error.stack : undefined,
  };

  Object.keys(errorPayload).forEach((key) => {
    if (errorPayload[key] === undefined) {
      delete errorPayload[key];
    }
  });

  const jsendStatus = error.status >= 500 ? 'error' : 'fail';

  res.status(error.status).json({
    status: jsendStatus,
    ...errorPayload,
  });
};
