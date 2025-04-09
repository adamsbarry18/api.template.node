import {
  BaseEntity,
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  BeforeInsert,
  DeleteDateColumn,
  Unique,
} from 'typeorm';
import bcrypt from 'bcrypt';
import { PasswordStatus, UserApiResponse } from './users.types';

const BCRYPT_SALT_ROUNDS = 10;

@Entity({ name: 'user' })
@Unique(['email'])
export class User extends BaseEntity {
  @PrimaryGeneratedColumn({ name: 'user_id' })
  id: number;

  @Column({ type: 'varchar', length: 36, unique: true, nullable: true })
  uid: string | null;

  @Column({ type: 'varchar', length: 100 })
  email: string;

  @Column({ type: 'varchar', length: 255 })
  password: string;

  @Column({ type: 'varchar', length: 200, nullable: true })
  name: string | null;

  @Column({ type: 'varchar', length: 200, nullable: true })
  surname: string | null;

  @Column({ type: 'int', default: 0 })
  level: number;

  @Column({ type: 'int', name: 'internal_level', default: 0 })
  internalLevel: number;

  @CreateDateColumn({ type: 'timestamp', name: 'created_time', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @UpdateDateColumn({ type: 'timestamp', name: 'updated_time', default: () => 'CURRENT_TIMESTAMP' })
  updatedAt: Date;

  @DeleteDateColumn({ type: 'timestamp', nullable: true, select: false, name: 'deleted_at' })
  // Pas besoin d'exclure ici, on le fera dans toApi()
  deletedAt: Date | null;

  @Column({ type: 'boolean', default: false })
  internal: boolean;

  @Column({ type: 'varchar', length: 45, default: 'fr' })
  language: string;

  @Column({ type: 'varchar', length: 10, nullable: true })
  color: string | null;

  @Column({
    type: 'enum',
    enum: PasswordStatus,
    default: PasswordStatus.ACTIVE,
    name: 'password_status',
  })
  passwordStatus: PasswordStatus;

  @Column({ type: 'timestamp', name: 'password_time', default: () => 'CURRENT_TIMESTAMP' })
  passwordUpdatedAt: Date | string;

  @Column({ type: 'json', nullable: true })
  preferences: Record<string, any> | null;

  @Column({
    type: 'varchar',
    length: 500,
    nullable: true,
    name: 'authorisation_overrides',
  })
  // Pas besoin d'exclure ici, on le fera dans toApi()
  authorisationOverrides: string | null;

  @Column({
    type: 'timestamp',
    nullable: true,
    name: 'permissions_expire_at',
  })
  // Pas besoin de transformer ici, on le fera dans toApi()
  permissionsExpireAt: Date | null | string;

  @BeforeInsert()
  async hashPasswordOnInsert() {
    if (this.password && !this.password.startsWith('$2')) {
      this.password = await bcrypt.hash(this.password, BCRYPT_SALT_ROUNDS);
      this.passwordUpdatedAt = new Date();
    }
  }

  async comparePassword(plainPassword: string): Promise<boolean> {
    if (!this.password) return false;
    return bcrypt.compare(plainPassword, this.password);
  }
  /**
   * Convertit l'entité User en un objet simplifié pour les réponses API.
   * Exclut les champs sensibles et formate les dates.
   */
  toApi(): UserApiResponse {
    // Fonction interne pour convertir une date en ISO string ou retourner null
    const formatISODate = (date: Date | string | null): string | null => {
      if (date instanceof Date && !isNaN(date.getTime())) {
        return date.toISOString();
      }
      // Gérer le cas où la date est déjà une string (potentiellement de la DB)
      if (typeof date === 'string') {
        try {
          // Essayer de parser et re-formatter pour assurer la cohérence ISO
          const parsedDate = new Date(date);
          if (!isNaN(parsedDate.getTime())) {
            return parsedDate.toISOString();
          }
        } catch (e) {
          /* Ignorer l'erreur si la string n'est pas une date valide */
        }
      }
      return null; // Retourne null pour les dates invalides ou autres types
    };

    // Retourne l'objet UserApiResponse
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, deletedAt, authorisationOverrides, ...apiData } = this;

    return {
      ...apiData,
      createdAt: formatISODate(this.createdAt),
      updatedAt: formatISODate(this.updatedAt),
      passwordUpdatedAt: formatISODate(this.passwordUpdatedAt),
      permissionsExpireAt: formatISODate(this.permissionsExpireAt),
    };
  }
}
