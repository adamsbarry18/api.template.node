import { User } from './users.entity';

export enum SecurityLevel {
  EXTERNAL = 0,
  READER = 1,
  USER = 2,
  INTEGRATOR = 4,
  ADMIN = 5,
}

// Enum pour le statut du mot de passe (doit correspondre à l'entité)
export enum PasswordStatus {
  ACTIVE = 'ACTIVE',
  VALIDATING = 'VALIDATING',
  EXPIRED = 'EXPIRED',
}

// Actions CRUD communes (vous pouvez définir d'autres actions spécifiques)
export enum CrudAction {
  CREATE = 'create',
  READ = 'read',
  UPDATE = 'write', // 'write' correspond souvent à update dans les flags
  DELETE = 'delete', // Nom d'action potentiel, à vérifier dans vos flags
  EXECUTE = 'execute',
  // Ajoutez d'autres actions si nécessaire ('list', 'publish', etc.)
}

// Type pour les règles d'autorisation passées au décorateur
export type AuthorisationRule =
  | { level: SecurityLevel; feature?: never; action?: never }
  | { level?: never; feature: string; action: CrudAction | string };

// --- DTOs (Data Transfer Objects) ---

export type CreateUserInput = Omit<
  User,
  | 'id'
  | 'createdAt'
  | 'updatedAt'
  | 'deletedAt'
  | 'passwordUpdatedAt'
  | 'password'
  | 'comparePassword'
  | 'hashPasswordOnInsert'
  | 'hashPasswordOnUpdate'
  | 'hasId'
  | 'save'
  | 'remove'
  | 'softRemove'
  | 'recover'
  | 'reload'
> & {
  password: string;
  authorisationOverrides?: string | null;
  permissionsExpireAt?: Date | null | string;
};
export type UpdateUserInput = Partial<
  Omit<
    User,
    | 'id'
    | 'uid'
    | 'email'
    | 'createdAt'
    | 'updatedAt'
    | 'deletedAt'
    | 'passwordUpdatedAt'
    | 'password'
    | 'comparePassword'
    | 'hashPasswordOnInsert'
    | 'hashPasswordOnUpdate'
    | 'hasId'
    | 'save'
    | 'remove'
    | 'softRemove'
    | 'recover'
    | 'reload'
  >
> & {
  password?: string;
  authorisationOverrides?: string | null;
  permissionsExpireAt?: Date | null | string;
};

// D'abord, créer un type de base sans les champs sensibles ET les champs de date originaux
type UserBaseForApi = Omit<
  User,
  | 'password'
  | 'deletedAt'
  | 'authorisationOverrides'
  | 'comparePassword'
  | 'hashPasswordOnInsert'
  | 'hashPasswordOnUpdate'
  | 'hasId'
  | 'save'
  | 'remove'
  | 'softRemove'
  | 'recover'
  | 'reload'
  | 'toApi' // Exclure explicitement la méthode toApi
  // Omettre aussi les champs de date pour éviter les conflits de type
  | 'createdAt'
  | 'updatedAt'
  | 'passwordUpdatedAt'
  | 'permissionsExpireAt'
>;

// Ensuite, ajouter les champs de date avec le type string souhaité
export type UserApiResponse = UserBaseForApi & {
  createdAt: string | null;
  updatedAt: string | null;
  passwordUpdatedAt: string | null;
  permissionsExpireAt: string | null;
};
