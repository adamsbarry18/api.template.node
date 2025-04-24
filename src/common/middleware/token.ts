import jwt, { type JwtPayload } from 'jsonwebtoken';

import logger from '@/lib/logger';
import { LoginService } from '@/modules/auth/services/login.services';
import { type User } from '@/modules/users/models/users.entity';

import {
  type ExpressMiddleware,
  type NextFunction,
  type Request,
  type Response,
} from '../../config/http';
import { UnauthorizedError } from '../errors/httpErrors';

const loginService = LoginService.getInstance();

logger.info('API:token');

function getToken(req: Request): string | JwtPayload | null {
  if (req.headers) {
    if (req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
        return jwt.decode(parts[1]);
      }
    }
  }
  return null;
}

export default function tokenMiddleware(): ExpressMiddleware {
  logger.info('Decrypt request token middleware');

  return async (req: Request, response: Response, next: NextFunction) => {
    const token = getToken(req) as any;
    if (token && typeof token === 'object') {
      if (!req.user) {
        req.user = {} as User;
      }
      req.user.authToken = token;
      if (token.clientId) {
        req.user.tokenClientId = token.clientId;
      }
      const isInvalidated = await loginService.isTokenInvalidated(token);
      if (isInvalidated) {
        next(new UnauthorizedError('Token invalidated'));
      }
      if (token.exp && token.exp < Date.now() / 1000) {
        next(new Error('Token expired'));
      }
    }
    next();
  };
}
