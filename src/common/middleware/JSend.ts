import { Request, Response, NextFunction } from '@/config/http';
import { BaseError } from '../errors/httpErrors';
export interface IJSendHelper {
  success(data?: any): void;
  fail(data: any): void;
  error(
    errorData: { message: string; code?: string; data?: any } | string | Error | BaseError,
  ): void;
  partial(data: { data: any; metadata: Record<string, any> }): void;
}

/**
 * Middleware that attaches the `jsend` helper object to the `res` (response) object.
 * This helper provides standardized methods for sending JSend-compliant responses.
 * @param req The Express request object.
 * @param res The Express response object (will be augmented with `res.jsend`).
 * @param next The next middleware function.
 */
export function jsendMiddleware(req: Request, res: Response, next: NextFunction): void {
  const helper: IJSendHelper = {
    /**
     * Sends a JSend 'success' response.
     * @param data Optional payload for the response. Defaults to null.
     */
    success(data: any = null): void {
      if (res.headersSent) return;
      const response = { status: 'success', data };
      res.json(response);
    },

    /**
     * Sends a JSend 'fail' response. Typically used for client-side errors (4xx).
     * Sets status code to 400 if it's currently below 400.
     * @param data Payload containing details about the failure.
     */
    fail(data: any): void {
      if (res.headersSent) return;
      if (res.statusCode < 400) {
        res.status(400);
      }
      const response = { status: 'fail', data };
      res.json(response);
    },

    /**
     * Sends a JSend 'error' response. Typically used for server-side errors (5xx).
     * Sets status code to 500 if it's currently below 500, unless overridden by an BaseError status.
     * Masks internal error details in production unless it's a validation error.
     * @param errorData Can be an error message string, an Error object, an BaseError object,
     *                  or an object with message, code, and data properties.
     */
    error(
      errorData: { message: string; code?: string; data?: any } | string | Error | BaseError,
    ): void {
      if (res.headersSent) return;
      if (res.statusCode < 500 && res.statusCode >= 400) {
        // 4xx: fail
        let response: { status: string; message: string; code?: string; data?: any };
        if (typeof errorData === 'string') {
          response = { status: 'fail', message: errorData };
        } else if (errorData instanceof BaseError) {
          response = {
            status: 'fail',
            message: errorData.message,
            code: errorData.code,
            data:
              process.env.NODE_ENV === 'development' || errorData.name === 'ValidationError'
                ? errorData.data
                : undefined,
          };
        } else if (errorData instanceof Error) {
          response = {
            status: 'fail',
            message:
              process.env.NODE_ENV === 'development'
                ? errorData.message
                : 'A request error occurred',
          };
        } else {
          response = {
            status: 'fail',
            message: errorData.message || 'A request error occurred.',
            code: errorData.code,
            data: errorData.data,
          };
        }
        res.json(response);
        return;
      }
      // 5xx or default: error
      if (res.statusCode < 500) {
        res.status(500);
      }
      let response: { status: string; message: string; code?: string; data?: any };
      if (typeof errorData === 'string') {
        response = { status: 'error', message: errorData };
      } else if (errorData instanceof BaseError) {
        response = {
          status: 'error',
          message: errorData.message,
          code: errorData.code,
          data:
            process.env.NODE_ENV === 'development' || errorData.name === 'ValidationError'
              ? errorData.data
              : undefined,
        };
      } else if (errorData instanceof Error) {
        response = {
          status: 'error',
          message:
            process.env.NODE_ENV === 'development'
              ? errorData.message
              : 'An internal error occurred',
        };
      } else {
        response = {
          status: 'error',
          message: errorData.message || 'An unexpected error occurred.',
          code: errorData.code,
          data: errorData.data,
        };
      }
      res.json(response);
    },
    /**
     * Sends a JSend 'success' response specifically for partial content or paginated results,
     * including metadata alongside the data.
     * @param data An object containing `data` (the main payload) and `metadata`.
     */
    partial(data: { data: any; metadata: Record<string, any> }): void {
      if (res.headersSent) return;
      const response = { status: 'success', ...data };
      res.json(response);
    },
  };

  (res as any).jsend = helper;

  next();
}
