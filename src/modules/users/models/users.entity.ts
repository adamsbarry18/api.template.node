import bcrypt from 'bcryptjs';
import { Entity, Column, BeforeInsert, BeforeUpdate, Unique } from 'typeorm';
import { z } from 'zod';

import { Model } from '@/common/models/Model';

export enum SecurityLevel {
  EXTERNAL = 1,
  READER = 2,
  USER = 3,
  INTEGRATOR = 4,
  ADMIN = 5,
  NOBODY = 999,
}

export enum UserActionType {
  CREATE = 'create',
  READ = 'read',
  UPDATE = 'write',
  DELETE = 'delete',
  EXECUTE = 'execute',
}

export type AuthorisationRule =
  | { level: SecurityLevel; feature?: never; action?: never }
  | { level?: never; feature: string; action: UserActionType | string };

export type CreateUserInput = {
  email: string;
  password: string;
  firstName: string;
  lastName?: string | null;
  level: number;
  internalLevel?: number;
  internal?: boolean;
  color?: string | null;
  passwordStatus?: PasswordStatus;
  preferences?: Record<string, any> | null;
  permissions?: Record<string, any> | null;
  permissionsExpireAt?: Date | null;
  isActive?: boolean;
};

export type UpdateUserInput = Omit<Partial<CreateUserInput>, 'email'>;

export const validationInputErrors: string[] = [];

export type UserApiResponse = {
  id: number;
  uid: string | null;
  email: string;
  firstName: string | null;
  lastName: string | null;
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
  isActive: boolean;
  googleId?: string | null;
};

export type DecodedOverrides = Map<number, number>;

const BCRYPT_SALT_ROUNDS = 10;

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

  @Column({ type: 'varchar', length: 255, select: false, nullable: true })
  password?: string | null;

  @Column({ type: 'varchar', length: 200, name: 'first_name' })
  firstName!: string;

  @Column({ type: 'varchar', length: 200, nullable: true, name: 'last_name' })
  lastName: string | null = null;

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

  @Column({ type: 'boolean', default: true, name: 'is_active' })
  isActive: boolean = true;

  @Column({ type: 'varchar', length: 255, nullable: true, name: 'google_id' })
  googleId: string | null = null;

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
  toApi(): UserApiResponse {
    const base = super.toApi();
    const res = {
      ...base,
      id: base.id,
      createdAt: base.createdAt,
      updatedAt: base.updatedAt,
      uid: this.uid,
      email: this.email,
      firstName: this.firstName,
      lastName: this.lastName,
      level: this.level,
      internalLevel: this.internalLevel,
      internal: this.internal,
      color: this.color,
      passwordStatus: this.passwordStatus,
      passwordUpdatedAt: Model.formatISODate(this.passwordUpdatedAt),
      preferences: this.preferences,
      permissionsExpireAt: Model.formatISODate(this.permissionsExpireAt),
      isActive: this.isActive,
      googleId: this.googleId,
    };

    delete (res as any).password;
    return res;
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
      firstName: z
        .string({ required_error: 'Firstname is required.' })
        .min(1, { message: 'Firstname cannot be empty.' }),
      level: z
        .number({ required_error: 'Level is required.' })
        .int({ message: 'Level must be an integer.' })
        .min(0, { message: 'Level must be a non-negative integer.' })
        .max(5, { message: 'Level must be at most 5.' }),
      password: z
        .string({ required_error: 'Password is required.' })
        .min(1, { message: 'Password cannot be empty.' })
        .optional()
        .nullable(),
      isActive: z.boolean().optional(),
    });

    const result = userValidationSchema.safeParse(this);

    if (!result.success) {
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
