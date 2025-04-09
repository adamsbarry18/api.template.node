import { Request, Response, NextFunction } from '@/common/http';
import { HttpError } from '../errors/httpErrors';

// Définition de l'interface IJsendHelper utilisée dans http.ts
export interface IJSendHelper {
  // Ajouter export ici
  success(data?: any): void;
  fail(data: any): void;
  error(
    errorData: { message: string; code?: string; data?: any } | string | Error | HttpError,
  ): void;
  // Ajouté pour la gestion des réponses partielles avec métadonnées (pagination, etc.)
  partial(data: { data: any; metadata: Record<string, any> }): void;
}

// Middleware qui attache l'helper `jsend` à `res`
export function jsendMiddleware(req: Request, res: Response, next: NextFunction): void {
  const helper: IJSendHelper = {
    success(data: any = null): void {
      if (res.headersSent) return; // Eviter d'envoyer si déjà envoyé
      const response = { status: 'success', data };
      res.json(response);
    },

    fail(data: any): void {
      if (res.headersSent) return;
      // Assurer que status est au moins 400 pour fail
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
      // Assurer que status est au moins 500 pour error
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
          // N'exposer data que si pertinent (ex: ValidationError) ou en dev
          data:
            process.env.NODE_ENV === 'development' || errorData.name === 'ValidationError'
              ? errorData.data
              : undefined,
        };
        // Utiliser le statut de l'erreur si défini
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
          // Ajouter code/data si pertinent et en dev
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

  // Attache l'helper à l'objet Response
  // Il faut étendre le type Response pour inclure `jsend` (fait dans http.ts)
  (res as any).jsend = helper;

  next();
}
