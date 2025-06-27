import { type JwtPayload } from 'jsonwebtoken';
import { type User as UserEntity } from '@/modules/users/models/users.entity';

import { type IJSendHelper } from '../common/middleware/JSend';
import {
  type FilterInfo,
  type PaginationInfo,
  type SortInfo,
} from '../common/middleware/queryParssing';

import type express from 'express';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    /**
     * @interface User
     * @extends UserEntity
     * @description Interface augmentation for Express.User to include custom properties.
     *              Based on UserApiResponse for DTO-like structure, plus auth-specific fields.
     */
    interface User extends UserEntity {
      sub?: number;
      authToken?: string | null;
      token?: JwtPayload;
      tokenClientId?: string;
    }

    /**
     * @interface Request
     * @description Interface augmentation for Express.Request to include custom properties.
     */
    interface Request {
      user?: User;
      pagination?: PaginationInfo;
      sorting?: SortInfo[];
      filters?: FilterInfo[];
      searchQuery?: string;
    }

    /**
     * @interface Response
     * @description Interface augmentation for Express.Response to include custom properties.
     */
    interface Response {
      jsend: IJSendHelper;
    }
  }
}

/**
 * @typedef {Express.User} AuthenticatedUser
 * @description Type alias for Express.User.
 */
export type AuthenticatedUser = Express.User;
/**
 * @typedef {express.Request} Request
 * @description Type alias for express.Request.
 */
export type Request = express.Request;
/**
 * @typedef {express.Response} Response
 * @description Type alias for express.Response.
 */
export type Response = express.Response;
/**
 * @typedef {express.NextFunction} NextFunction
 * @description Type alias for express.NextFunction.
 */
export type NextFunction = express.NextFunction;

/**
 * @typedef {function} ExpressMiddleware
 * @param {Request} request - Express request object.
 * @param {Response} response - Express response object.
 * @param {NextFunction} next - Express next function.
 * @returns {void | Promise<void>}
 * @description Type definition for Express middleware.
 */
export type ExpressMiddleware = (
  request: Request,
  response: Response,
  next: NextFunction,
) => void | Promise<void>;
