import { JwtPayload } from 'jsonwebtoken';

export interface CustomJwtPayload extends JwtPayload {
  id: number;
  level: number;
  internal: boolean;
  authToken?: string;
  permissions?: string[];
}
