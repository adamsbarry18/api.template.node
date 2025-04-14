import { Request, Response, NextFunction } from '../http';
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

  // Gestion spécifique des erreurs Zod pour une meilleure réponse client
  if (err instanceof ZodError) {
    error = new HttpError(422, 'Validation failed', 'ERR_VALIDATION', err.format());
  } else if (err instanceof HttpError) {
    error = err;
  } else {
    error = new InternalServerError('An unexpected error occurred');
  }

  // Utilisation de res.jsend.error pour envoyer la réponse standardisée
  // La logique de masquage des détails en production est gérée dans jsendMiddleware

  // Définir le statut HTTP avant d'appeler jsend.error
  res.status(error.status);

  // Construire l'objet d'erreur pour jsend
  const errorPayload = {
    message:
      config.NODE_ENV === 'production' && error.status === 500
        ? 'Internal Server Error' // Masquer les messages 500 en prod
        : error.message,
    code: error.code,
    // Inclure 'data' seulement si présent et pertinent (ex: validation) ou en dev
    data:
      config.NODE_ENV !== 'production' || error.name === 'ValidationError' ? error.data : undefined,
    // Inclure la stack seulement en dev
    stack: config.NODE_ENV !== 'production' ? err.stack : undefined,
  };

  // Filtrer les clés undefined (comme stack en prod)
  Object.keys(errorPayload).forEach(
    (key) => errorPayload[key] === undefined && delete errorPayload[key],
  );

  // Envoyer la réponse via jsend
  // Assurez-vous que le type Response est étendu pour inclure jsend (normalement fait via http.ts ou un fichier de types global)
  if (res.jsend && typeof res.jsend.error === 'function') {
    res.jsend.error(errorPayload);
  } else {
    // Fallback si jsend n'est pas attaché (ne devrait pas arriver si le middleware est bien placé)
    logger.warn('res.jsend.error was not available in errorHandler. Sending raw JSON.');
    res.json({ status: 'error', ...errorPayload });
  }
};
