export class HttpError extends Error {
  public readonly status: number;
  public readonly code: string; // Optionnel: code d'erreur applicatif
  public readonly data: unknown | null; // Données supplémentaires

  constructor(status: number, message: string, code?: string, data: unknown | null = null) {
    super(message);
    this.status = status;
    this.code = code || this.constructor.name;
    this.data = data;
    this.name = this.constructor.name; // Nom de la classe pour l'identification
    // On conserve la stack trace pour le logging serveur
    // Error.captureStackTrace(this, this.constructor); // Capture la stack trace correctement
  }
}

export class BadRequestError extends HttpError {
  constructor(message = 'Bad Request', data: unknown | null = null) {
    super(400, message, 'ERR_BAD_REQUEST', data);
  }
}

export class ValidationError extends HttpError {
  constructor(message = 'Validation Failed', errors: unknown | null) {
    super(422, message, 'ERR_VALIDATION', errors); // 422 Unprocessable Entity est courant pour la validation
  }
}

export class UnauthorizedError extends HttpError {
  constructor(message = 'Unauthorized') {
    super(401, message, 'ERR_UNAUTHORIZED');
  }
}

export class ForbiddenError extends HttpError {
  constructor(message = 'Forbidden') {
    super(403, message, 'ERR_FORBIDDEN');
  }
}

export class NotFoundError extends HttpError {
  constructor(message = 'Not Found') {
    super(404, message, 'ERR_NOT_FOUND');
  }
}

export class ConflictError extends HttpError {
  constructor(message = 'Conflict') {
    super(409, message, 'ERR_CONFLICT');
  }
}

export class InternalServerError extends HttpError {
  constructor(message = 'Internal Server Error', data: unknown | null = null) {
    super(500, message, 'ERR_INTERNAL_SERVER', data);
  }
}

export class ServiceUnavailableError extends HttpError {
  constructor(message = 'Service Unavailable') {
    super(503, message, 'ERR_SERVICE_UNAVAILABLE');
  }
}
