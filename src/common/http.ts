import express from 'express';
import { IJSendHelper } from './middleware/JSend';

import { User } from '@/modules/users/models/users.entity';
export type AuthenticatedUser = User & {
  authToken?: string | null;
};
export interface IRequest extends express.Request {
  user?: AuthenticatedUser;
}
export interface IResponse extends express.Response {
  jsend: IJSendHelper;
}
export type ExpressMiddleware = (request: Request, response: Response, next: NextFunction) => void;

// Exporter les types étendus et NextFunction pour utilisation dans l'application
export type NextFunction = express.NextFunction;
export type Request = IRequest;
export type Response = IResponse;
