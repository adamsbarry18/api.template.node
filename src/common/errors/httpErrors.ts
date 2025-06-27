import type { DependentWrapper } from '../utils/Service';

// Add toJSON to Error prototype if not present
if (!('toJSON' in Error.prototype)) {
  Object.defineProperty(Error.prototype, 'toJSON', {
    value() {
      const alt: { [key: string]: any } = {};
      Object.getOwnPropertyNames(this).forEach((key) => {
        alt[key] = this[key];
      }, this);
      return alt;
    },
    configurable: true,
    writable: true,
  });
}

export enum ErrorStatus {
  ERR_VALIDATION = 400,
  ERR_BAD_REQUEST = 400,
  ERR_PWD_IDENTICAL = 400,
  ERR_DEPENDENCY = 409,
  ERR_UNAUTHORIZED = 401,
  ERR_PWD_EXPIRED = 403,
  ERR_FORBIDDEN = 403,
  ERR_NOT_FOUND = 404,
  ERR_PWD_VALIDATING = 422,
  ERR_OTHER = 500,
  ERR_SERVER_ERROR = 500,
  ERR_SERVICE_UNAVAILABLE = 503,
}

type ErrorCode = keyof typeof ErrorStatus;

export class BaseError extends Error {
  code: ErrorCode;
  message: string;
  status: number;
  data: string | string[] | object | null;

  /**
   * Create a standard API error
   * @param code ErrorStatus code
   * @param message Error message
   * @param data Special data to display
   */
  constructor(
    code: ErrorCode = 'ERR_OTHER',
    message: string | null = 'An error occurred...', // Allow null for message in constructor
    data: string | string[] | object | null = null,
  ) {
    super(message ?? 'An error occurred...'); // Pass a non-null string to super
    this.code = code;
    this.message = message ?? 'An error occurred...'; // Ensure this.message is always a string
    this.status = ErrorStatus.hasOwnProperty(code) ? ErrorStatus[code] : 500;
    this.data = data;
    this.name = this.constructor.name;
    delete this.stack; // Avoid leaking stack for those errors
  }
}

export class ValidationError extends BaseError {
  data!: string | string[];
  constructor(errors: string | string[]) {
    super('ERR_VALIDATION', 'Validation error', errors);
  }
}

export class BadRequestError extends BaseError {
  constructor(info: string | null = null) {
    super('ERR_BAD_REQUEST', 'Bad request', info);
  }
}

export class DependencyError extends BaseError {
  data!: DependentWrapper[];
  constructor(dependents: DependentWrapper[] = []) {
    super('ERR_DEPENDENCY', 'Conflict due to dependencies', dependents);
  }
}

export class UnauthorizedError extends BaseError {
  constructor(info: string | null = null) {
    super('ERR_UNAUTHORIZED', 'Unauthorized', info);
  }
}

export class ForbiddenError extends BaseError {
  constructor(info: string | null = null) {
    super('ERR_FORBIDDEN', 'Forbidden', info);
  }
}

export class NotFoundError extends BaseError {
  constructor(info: string | null = null) {
    super('ERR_NOT_FOUND', 'Not found', info);
  }
}

export class ServerError extends BaseError {
  constructor(info: string | object | null = null) {
    super('ERR_SERVER_ERROR', 'Internal error', info);
  }
}

export class ServiceUnavailableError extends BaseError {
  constructor(info: string | object | null = null) {
    super('ERR_SERVICE_UNAVAILABLE', 'Service unavailable', info);
  }
}

export enum PasswordError {
  PASSWORD_VALIDATING = 'PASSWORD VALIDATING',
  PASSWORD_EXPIRED = 'PASSWORD EXPIRED',
  PASSWORD_IDENTICAL = 'PASSWORD_IDENTICAL',
}

export class AuthenticateError extends BaseError {
  constructor(message: PasswordError | string) {
    if (message === PasswordError.PASSWORD_VALIDATING) {
      super('ERR_PWD_VALIDATING', message);
    } else if (message === PasswordError.PASSWORD_EXPIRED) {
      super('ERR_PWD_EXPIRED', message);
    } else if (message === PasswordError.PASSWORD_IDENTICAL) {
      super('ERR_PWD_IDENTICAL', message);
    } else {
      super('ERR_OTHER', message);
    }
  }
}

export const PARAMETER_ERRORS = {
  PASSWORD_IDENTICAL: 'PASSWORD_IDENTICAL',
};

export class ParameterError extends BaseError {
  constructor(message: string, info: string | null = null) {
    // Determine the code based on the message
    const code =
      message === PARAMETER_ERRORS.PASSWORD_IDENTICAL ? 'ERR_PWD_IDENTICAL' : 'ERR_BAD_REQUEST';
    // Call the BaseError constructor with the determined code and message
    super(code, message, info);
    // Ensure the name is correctly set for this specific error type
    this.name = this.constructor.name;
  }
}
// eslint-disable-next-line @typescript-eslint/naming-convention
export const Errors = {
  BaseError,
  ServerError,
  AuthenticateError,
  DependencyError,
  BadRequestError,
  NotFoundError,
  ValidationError,
  UnauthorizedError,
  ForbiddenError,
  ServiceUnavailableError,
};
