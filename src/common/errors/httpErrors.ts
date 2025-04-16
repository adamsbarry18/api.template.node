import logger from '@/lib/logger';
import { QueryFailedError } from 'typeorm';

/**
 * Base class for custom HTTP errors.
 * Ensures errors have a status code, an optional application-specific error code,
 * and optional additional data.
 */
export class HttpError extends Error {
  public readonly status: number;
  public readonly code: string;
  public readonly data: unknown | null;

  /**
   * Creates an instance of HttpError.
   * @param {number} status The HTTP status code.
   * @param {string} message The error message.
   * @param {string} [code] Optional application-specific error code.
   * @param {unknown | null} [data=null] Optional additional data.
   */
  constructor(status: number, message: string, code?: string, data: unknown | null = null) {
    super(message);
    this.status = status;
    this.code = code || this.constructor.name;
    this.data = data;
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Represents a 400 Bad Request error.
 */
export class BadRequestError extends HttpError {
  constructor(message = 'Bad Request', data: unknown | null = null) {
    super(400, message, 'ERR_BAD_REQUEST', data);
  }
}

/**
 * Represents a 422 Unprocessable Entity error, typically used for validation failures.
 */
export class ValidationError extends HttpError {
  constructor(message = 'Validation Failed', errors: unknown | null) {
    super(422, message, 'ERR_VALIDATION', errors);
  }
}

/**
 * Represents a 401 Unauthorized error.
 */
export class UnauthorizedError extends HttpError {
  constructor(message = 'Unauthorized') {
    super(401, message, 'ERR_UNAUTHORIZED');
  }
}

/**
 * Represents a 403 Forbidden error.
 */
export class ForbiddenError extends HttpError {
  constructor(message = 'Forbidden') {
    super(403, message, 'ERR_FORBIDDEN');
  }
}

/**
 * Represents a 404 Not Found error.
 */
export class NotFoundError extends HttpError {
  constructor(message = 'Not Found') {
    super(404, message, 'ERR_NOT_FOUND');
  }
}

/**
 * Represents a 409 Conflict error.
 */
export class ConflictError extends HttpError {
  constructor(message = 'Conflict', data: unknown | null = null) {
    super(409, message, 'ERR_CONFLICT', data);
  }
}

/**
 * Represents a 500 Internal Server Error.
 */
export class InternalServerError extends HttpError {
  constructor(message = 'Internal Server Error', data: unknown | null = null) {
    super(500, message, 'ERR_INTERNAL_SERVER', data);
  }
}

/**
 * Represents a 503 Service Unavailable error.
 */
export class ServiceUnavailableError extends HttpError {
  constructor(message = 'Service Unavailable') {
    super(503, message, 'ERR_SERVICE_UNAVAILABLE');
  }
}

/**
 * Utility class to handle common database errors and convert them into appropriate HttpError instances.
 */
export class DatabaseErrorHandler {
  /**
   * Handles database-related errors, attempting to convert them into specific HttpError instances.
   * Logs the original error and throws a specific HttpError (ConflictError, ValidationError, or InternalServerError).
   * This method never returns normally, it always throws.
   *
   * @param {any} error The original error object caught (can be of any type).
   * @param {string} context A string describing the context where the error occurred (e.g., 'UserRepository.createUser').
   * @throws {HttpError} Throws ConflictError, ValidationError, or InternalServerError.
   */
  static handle(error: any, context: string): never {
    logger.error(
      { err: error, dbContext: context },
      `Database error occurred in context: ${context}`,
    );
    if (error instanceof QueryFailedError) {
      if (
        error.driverError?.code === '23505' ||
        error.message.includes('unique constraint') ||
        error.message.includes('duplicate key')
      ) {
        throw new ConflictError(
          `Resource already exists due to unique constraint violation in ${context}.`,
          {
            context,
            detail: error.message,
          },
        );
      }
    }
    if (error instanceof ValidationError) {
      throw error;
    }
    throw new InternalServerError(`Database operation failed in context: ${context}`, {
      context,
      originalError: error instanceof Error ? error.message : String(error), // Extract message safely
    });
  }
}
