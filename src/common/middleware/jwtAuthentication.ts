import jwt, { JwtPayload } from 'jsonwebtoken';
import { unless } from 'express-unless';
import type { NextFunction, Request, Response } from '@/common/http';
import type { ExpressMiddleware } from '../http';
import logger from '@/lib/logger';
import { UnauthorizedError } from '../errors/httpErrors';
import { redisClient } from '@/lib/redis';

const REDIS_INVALIDATION_TOKEN_KEY = 'backend:token_invalidation:';

interface CustomJwtPayload extends JwtPayload {
  id: number;
  level: number;
  internal: boolean;
  authToken?: string;
  permissions?: string[];
}

const AUTH_HEADER = 'X-API-key'.toLowerCase();

export async function isTokenInvalidated(token) {
  let res;
  if (redisClient !== null) {
    res = await redisClient.get(`${REDIS_INVALIDATION_TOKEN_KEY}${token}`);
  }
  return !!res;
}

logger.info('API:jwtAuthenticationMiddleware');
export default function (secret: string): ExpressMiddleware {
  const middleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    let token: string;

    if (req.method === 'OPTIONS' && req.headers.hasOwnProperty('access-control-request-headers')) {
      const hasAuthInAccessControl = (req.headers?.['access-control-request-headers'] ?? '')
        .split(',')
        .map((header) => header.trim())
        .includes('authorization');

      if (hasAuthInAccessControl) {
        return next();
      }
    }

    const tokenInHeaders = req.headers?.[AUTH_HEADER];
    const tokenInQuery = req.query?.[AUTH_HEADER];
    if (typeof tokenInHeaders === 'string' && tokenInHeaders !== '') {
      token = tokenInHeaders.trim();
    } else if (typeof tokenInQuery === 'string' && tokenInQuery !== '') {
      token = tokenInQuery.trim();
    } else {
      return next(
        new UnauthorizedError('credentials_required : No Authorization header was found'),
      );
    }
    const isInvalidated = await isTokenInvalidated(token);
    if (isInvalidated) {
      logger.info('Token invalidated', token);
      return next(new UnauthorizedError('Token invalidated'));
    }

    try {
      const decoded = jwt.verify(token, secret) as CustomJwtPayload;
      req.user = decoded;
      req.user.authToken = token;
      next();
    } catch (err: any) {
      let message = 'JWT verification error';
      if (
        err.message.includes('Invalid token') ||
        err.message.includes('jwt malformed') ||
        err.message.includes('invalid signature') ||
        err.message.includes('jwt audience invalid') ||
        err.message.includes('jwt signature is required')
      ) {
        message = 'Invalid token';
      }
      if (err.message.includes('jwt issuer invalid')) {
        message = 'Not authorized token';
      }
      if (err.message.includes('jwt expired')) {
        message = 'Token expired';
      }

      next(new UnauthorizedError(`invalid_token : ${message}`));
    }
  };

  middleware.unless = unless;

  return middleware;
}
