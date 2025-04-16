import { Request, Response, NextFunction } from '../../config/http';
import { HttpError, InternalServerError } from '../errors/httpErrors';
import logger from '@/lib/logger';
import config from '@/config';
import { ZodError } from 'zod';

export const errorHandler = (err: Error, req: Request, res: Response, next: NextFunction): void => {
  let error: HttpError;

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
    error = new HttpError(422, 'Validation failed', 'ERR_VALIDATION', err.format());
  } else if (err instanceof HttpError) {
    error = err;
  } else {
    error = new InternalServerError('An unexpected error occurred');
  }

  // Use res.jsend.error to send the standardized response.
  // The logic for masking details in production is handled within the jsendMiddleware itself or here based on NODE_ENV.

  // Set the HTTP status before calling jsend.error.
  res.status(error.status);

  // Build the error object for the JSend response.
  const errorPayload = {
    message:
      config.NODE_ENV === 'production' && error.status === 500
        ? 'Internal Server Error' // Mask internal server error messages in production.
        : error.message,
    code: error.code,
    // Include 'data' only if present and relevant (e.g., validation errors) or in development.
    data:
      config.NODE_ENV !== 'production' || error.name === 'ValidationError' ? error.data : undefined,
    // Include stack trace only in development.
    stack: config.NODE_ENV !== 'production' ? err.stack : undefined,
  };

  // Filter out undefined keys (like stack in production).
  Object.keys(errorPayload).forEach(
    (key) => errorPayload[key] === undefined && delete errorPayload[key],
  );

  // Send the response via jsend.
  // Ensure the Response type is extended to include jsend (typically done via http.ts or a global types file).
  if (res.jsend && typeof res.jsend.error === 'function') {
    res.jsend.error(errorPayload);
  } else {
    // Fallback if jsend is not attached (should not happen if middleware is correctly placed).
    logger.warn('res.jsend.error was not available in errorHandler. Sending raw JSON.');
    res.json({ status: 'error', ...errorPayload });
  }
};
