import { Entity, Column, BeforeInsert, BeforeUpdate, Unique } from 'typeorm';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import { PasswordStatus } from './users.types';
import { Model } from '@/common/models/Model';
import { ValidationError } from '@/common/errors/httpErrors';
import logger from '@/lib/logger';

const BCRYPT_SALT_ROUNDS = 10;

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
   * Normalise l'adresse e-mail (minuscule et sans espaces).
   */
  normalizeEmail(): void {
    if (this.email) {
      this.email = this.email.toLowerCase().trim();
    }
  }

  /**
   * Vérifie si l'utilisateur a des droits administrateurs.
   * @returns {boolean} - true si le niveau de l'utilisateur est 5
   */
  isAdmin(): boolean {
    return this.level === 5;
  }

  /**
   * Valide la complexité d'un mot de passe.
   * Le mot de passe doit respecter les critères suivants :
   * - Minimum 8 caractères
   * - Au moins une lettre majuscule
   * - Au moins une lettre minuscule
   * - Au moins un chiffre
   * - Au moins un caractère spécial (@$!%*?&)
   *
   * @param password - mot de passe à valider
   * @returns {boolean} - true si le mot de passe répond aux critères
   */
  validatePassword(password: string): boolean {
    const passwordSchema = z
      .string()
      .min(8)
      .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/, {
        message:
          'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      });

    const result = passwordSchema.safeParse(password);
    return result.success;
  }

  validationErrors: string[] = [];

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
      this.validationErrors = result.error.issues.map((issue) => {
        const fieldName = issue.path.join('.') || 'Field';
        return `${fieldName}: ${issue.message}`;
      });
      return false;
    }
    this.validationErrors = [];
    return true;
  }
}
