import { Entity, Column, BeforeInsert, BeforeUpdate, Unique } from 'typeorm';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { Model } from '../../../common/models/Model';

export enum SecurityLevel {
  EXTERNAL = 1,
  READER = 2,
  USER = 3,
  INTEGRATOR = 4,
  ADMIN = 5,
  NOBODY = 999,
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

export const validationInputErrors: string[] = [];

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
  created_time?: Date;
  updated_time?: Date;
};

// Interne type for decode overrides
export type DecodedOverrides = Map<number, number>;

const BCRYPT_SALT_ROUNDS = 10;

// Définition de l'enum déplacée ici
export enum PasswordStatus {
  ACTIVE = 'ACTIVE',
  VALIDATING = 'VALIDATING',
  EXPIRED = 'EXPIRED',
}

/**
 * User entity representing application users
 * @extends Model
 */
@Entity({ name: 'user' })
@Unique(['email'])
export class User extends Model {
  @Column({ type: 'varchar', length: 36, unique: true, nullable: true })
  uid: string | null = null;

  @Column({ type: 'varchar', length: 100 })
  email!: string;

  @Column({ type: 'varchar', length: 255, select: false })
  password!: string;

  // Définition du nom comme obligatoire
  @Column({ type: 'varchar', length: 200 })
  name!: string;

  @Column({ type: 'varchar', length: 200, nullable: true })
  surname: string | null = null;

  @Column({ type: 'int', default: 0 })
  level: number = 0;

  @Column({ type: 'int', name: 'internal_level', default: 0 })
  internalLevel: number = 0;

  @Column({ type: 'boolean', default: false })
  internal: boolean = false;

  @Column({ type: 'varchar', length: 10, nullable: true })
  color: string | null = null;

  @Column({
    type: 'enum',
    enum: PasswordStatus,
    default: PasswordStatus.ACTIVE,
    name: 'password_status',
  })
  passwordStatus: PasswordStatus = PasswordStatus.ACTIVE;

  @Column({ type: 'timestamp', name: 'password_time', default: () => 'CURRENT_TIMESTAMP' })
  passwordUpdatedAt!: Date;

  @Column({ type: 'json', nullable: true })
  preferences: Record<string, any> | null = null;

  @Column({ type: 'varchar', length: 500, nullable: true, name: 'authorisation_overrides' })
  authorisationOverrides: string | null = null;

  @Column({ type: 'timestamp', nullable: true, name: 'permissions_expire_at' })
  permissionsExpireAt: Date | null = null;

  /**
   * Hash la valeur du password avant insertion / mise à jour dans la BDD.
   */
  @BeforeInsert()
  @BeforeUpdate()
  async hashPassword(): Promise<void> {
    if (this.password && !this.password.startsWith('$2b$')) {
      this.password = await bcrypt.hash(this.password, BCRYPT_SALT_ROUNDS);
      this.passwordUpdatedAt = new Date();
    }
  }

  /**
   * Compare un mot de passe en clair avec le hash stocké.
   * @param plainPassword - mot de passe en clair
   * @returns {Promise<boolean>} - true si les mots de passe concordent
   */
  async comparePassword(plainPassword: string): Promise<boolean> {
    if (!this.password) return false;
    return bcrypt.compare(plainPassword, this.password);
  }

  /**
   * Formate les données de l'entité pour une réponse API en excluant les champs sensibles.
   * @returns l'objet formaté pour l'API.
   */
  toApi() {
    const base = super.toApi();
    const res = {
      ...base,
      id: base.id,
      createdAt: base.createdAt,
      updatedAt: base.updatedAt,
      uid: this.uid,
      email: this.email,
      name: this.name,
      surname: this.surname,
      level: this.level,
      internalLevel: this.internalLevel,
      internal: this.internal,
      color: this.color,
      passwordStatus: this.passwordStatus,
      passwordUpdatedAt: Model.formatISODate(this.passwordUpdatedAt),
      preferences: this.preferences,
      permissionsExpireAt: Model.formatISODate(this.permissionsExpireAt),
    };

    delete (res as any).password;
    return res;
  }

  /**
   * Vérifie si l'utilisateur a des droits administrateurs.
   * @returns {boolean} - true si le niveau de l'utilisateur est 5
   */
  isAdmin(): boolean {
    return this.level === 5;
  }

  /**
   * Validates the entity's required attributes and constraints using Zod.
   * Checks for presence and basic format of email, name, level, and password.
   *
   * @returns {boolean} True if the entity instance is valid according to the schema, false otherwise.
   * Logs validation errors internally if validation fails.
   */
  isValid(): boolean {
    const userValidationSchema = z.object({
      email: z
        .string({ required_error: 'Email is required.' })
        .email({ message: 'Invalid email address format.' })
        .min(1, { message: 'Email cannot be empty.' }),
      name: z
        .string({ required_error: 'Name is required.' })
        .min(1, { message: 'Name cannot be empty.' }),
      level: z
        .number({ required_error: 'Level is required.' })
        .int({ message: 'Level must be an integer.' })
        .min(0, { message: 'Level must be a non-negative integer.' })
        .max(5, { message: 'Level must be at most 5.' }),
      password: z
        .string({ required_error: 'Password is required.' })
        .min(1, { message: 'Password cannot be empty.' }),
    });

    const result = userValidationSchema.safeParse(this);

    if (!result.success) {
      // Pour chaque erreur, on récupère le path (champ concerné) et le message
      validationInputErrors.length = 0;
      validationInputErrors.push(
        ...result.error.issues.map((issue) => {
          const fieldName = issue.path.join('.') || 'Field';
          return `${fieldName}: ${issue.message}`;
        }),
      );
      return false;
    }
    validationInputErrors.length = 0;
    return true;
  }
}
