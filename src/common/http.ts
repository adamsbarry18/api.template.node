import express from 'express';
// Importer l'interface depuis le middleware JSend
import { IJSendHelper } from './middleware/JSend'; // Assurez-vous que le chemin est correct

// Étendre l'interface Request d'Express
export interface IRequest extends express.Request {
  internal: boolean;
  user?: {
    id: number;
    level: number;
    internal: boolean;
    authToken?: string;
    permissions?: string[];
  };
}

// Étendre l'interface Response d'Express pour inclure jsend
export interface IResponse extends express.Response {
  jsend: IJSendHelper;
}

export type ExpressMiddleware = (request: Request, response: Response, next: NextFunction) => void;

// Exporter les types étendus pour utilisation dans l'application
export type NextFunction = express.NextFunction;
export type Request = IRequest;
export type Response = IResponse;
