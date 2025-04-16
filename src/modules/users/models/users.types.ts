import logger from '@/lib/logger';
import { z } from 'zod';
import { InternalServerError, NotFoundError } from '@/common/errors/httpErrors';

export enum SecurityLevel {
  EXTERNAL = 0,
  READER = 1,
  USER = 2,
  INTEGRATOR = 4,
  ADMIN = 5,
}

export enum PasswordStatus {
  ACTIVE = 'ACTIVE',
  VALIDATING = 'VALIDATING',
  EXPIRED = 'EXPIRED',
}

export enum Action {
  CREATE = 'create',
  READ = 'read',
  UPDATE = 'write',
  DELETE = 'delete',
  EXECUTE = 'execute',
}

export type AuthorisationRule =
  | { level: SecurityLevel; feature?: never; action?: never }
  | { level?: never; feature: string; action: Action | string };

// CreateUserInput type and schema
export type CreateUserInput = {
  email: string;
  password: string;
  name: string;
  surname?: string | null;
  level: number;
  internalLevel?: number;
  internal?: boolean;
  color?: string | null;
  passwordStatus?: PasswordStatus;
  preferences?: Record<string, any> | null;
  permissions?: Record<string, any> | null;
  permissionsExpireAt?: Date | null;
};

export type UpdateUserInput = Omit<Partial<CreateUserInput>, 'email'>;

// UserApiResponse type (DTO)
export type UserApiResponse = {
  id: number;
  uid: string | null;
  email: string;
  name: string | null;
  surname: string | null;
  level: number;
  internalLevel: number;
  internal: boolean;
  color: string | null;
  passwordStatus: PasswordStatus;
  createdAt: string | null;
  updatedAt: string | null;
  passwordUpdatedAt: string | null;
  preferences: Record<string, any> | null;
  permissionsExpireAt: string | null;
};

// Interne type for decode overrides
export type DecodedOverrides = Map<number, number>;

// Jwt payload zod schema valid
export const jwtPayloadSchema = z.object({
  sub: z.number().int().positive(),
  level: z.number().int().min(0).optional(),
  internal: z.boolean().optional(),
});
