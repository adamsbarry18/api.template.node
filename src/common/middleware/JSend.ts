import { Request, Response, NextFunction } from '@/common/http';
import { HttpError } from '../errors/httpErrors';
export interface IJSendHelper {
  success(data?: any): void;
  fail(data: any): void;
  error(
    errorData: { message: string; code?: string; data?: any } | string | Error | HttpError,
  ): void;
  partial(data: { data: any; metadata: Record<string, any> }): void;
}

// Middleware qui attache l'helper `jsend` à `res`
export function jsendMiddleware(req: Request, res: Response, next: NextFunction): void {
  const helper: IJSendHelper = {
    success(data: any = null): void {
      if (res.headersSent) return;
      const response = { status: 'success', data };
      res.json(response);
    },

    fail(data: any): void {
      if (res.headersSent) return;
      if (res.statusCode < 400) {
        res.status(400);
      }
      const response = { status: 'fail', data };
      res.json(response);
    },

    error(
      errorData: { message: string; code?: string; data?: any } | string | Error | HttpError,
    ): void {
      if (res.headersSent) return;
      if (res.statusCode < 500) {
        res.status(500);
      }

      let response: { status: string; message: string; code?: string; data?: any };

      if (typeof errorData === 'string') {
        response = { status: 'error', message: errorData };
      } else if (errorData instanceof HttpError) {
        response = {
          status: 'error',
          message: errorData.message,
          code: errorData.code,
          data:
            process.env.NODE_ENV === 'development' || errorData.name === 'ValidationError'
              ? errorData.data
              : undefined,
        };
        if (errorData.status && res.statusCode === 500) {
          res.status(errorData.status);
        }
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

    partial(data: { data: any; metadata: Record<string, any> }): void {
      if (res.headersSent) return;
      const response = { status: 'success', ...data };
      res.json(response);
    },
  };

  (res as any).jsend = helper;

  next();
}
