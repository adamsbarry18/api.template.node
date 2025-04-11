// src/modules/users/models/users.types.ts

import { PermissionsInputMap } from '../../authorisations/authorization.types'; // Importer le type
import { User } from './users.entity';

// SecurityLevel, PasswordStatus, CrudAction, AuthorisationRule (inchangés)
// ... (enums et types précédents) ...
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
type UserBaseDto = Omit<
  User,
  | 'id'
  | 'createdAt'
  | 'updatedAt'
  | 'deletedAt'
  | 'passwordUpdatedAt'
  | 'password'
  | 'authorisationOverrides' // Remplacé par 'permissions'
  // Méthodes TypeORM/BaseEntity
  | 'comparePassword'
  | 'hashPasswordOnInsert'
  | 'hasId'
  | 'save'
  | 'remove'
  | 'softRemove'
  | 'recover'
  | 'reload'
  // Méthode personnalisée
  | 'toApi'
>;

// Input pour la création
export type CreateUserInput = UserBaseDto & {
  password: string;
  permissions?: PermissionsInputMap | null;
  permissionsExpireAt?: Date | string | null;
};
export type UpdateUserInput = Partial<Omit<UserBaseDto, 'email' | 'uid'>> & {
  password?: string;
  permissions?: PermissionsInputMap | null;
  permissionsExpireAt?: Date | string | null;
};

type UserBaseForApi = Omit<
  User,
  | 'password'
  | 'deletedAt'
  | 'authorisationOverrides'
  | 'comparePassword'
  | 'hashPasswordOnInsert'
  | 'hasId'
  | 'save'
  | 'remove'
  | 'softRemove'
  | 'recover'
  | 'reload'
  | 'toApi'
  | 'createdAt'
  | 'updatedAt'
  | 'passwordUpdatedAt'
  | 'permissionsExpireAt'
>;
export type UserApiResponse = UserBaseForApi & {
  createdAt: string | null;
  updatedAt: string | null;
  passwordUpdatedAt: string | null;
  permissionsExpireAt: string | null;
};
