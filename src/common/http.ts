import express from 'express';
import { IJSendHelper } from './middleware/JSend';

import { User } from '@/modules/users/models/users.entity';
import { FilterInfo, PaginationInfo, SortInfo } from './middleware/queryParssing';
import { JwtPayload } from 'jsonwebtoken';
export type AuthenticatedUser = User & {
  authToken?: string | null;
  token?: JwtPayload;
  tokenClientId?: string;
};
export interface IRequest extends express.Request {
  user?: AuthenticatedUser;
  allow: {
    pagination?: PaginationInfo;
    sorting?: SortInfo[];
    filters?: FilterInfo[];
    searchQuery?: string;
  };
}
export interface IResponse extends express.Response {
  jsend: IJSendHelper;
}
export type ExpressMiddleware = (request: Request, response: Response, next: NextFunction) => void;

// Exporter les types étendus et NextFunction pour utilisation dans l'application
export type NextFunction = express.NextFunction;
export type Request = IRequest;
export type Response = IResponse;
