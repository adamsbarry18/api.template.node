import {
  BaseEntity,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  BeforeInsert,
  BeforeUpdate,
  AfterInsert,
  AfterUpdate,
  BeforeSoftRemove,
  AfterSoftRemove,
} from 'typeorm';
import { ValidationError } from '@/common/errors/httpErrors';
import { getRedisClient } from '@/lib/redis';
import logger from '@/lib/logger';

interface IModelDiff {
  changed: string[];
  newValues: Record<string, any>;
}

/**
 * Classe de base pour les entités TypeORM, fournissant validation, gestion du cache et sérialisation.
 */
export abstract class Model extends BaseEntity {
  @PrimaryGeneratedColumn({ name: 'id' })
  id: number;

  @CreateDateColumn({ type: 'timestamp', name: 'created_time' })
  createdAt: Date;

  @UpdateDateColumn({ type: 'timestamp', name: 'updated_time' })
  updatedAt: Date;

  @DeleteDateColumn({ type: 'timestamp', name: 'deleted_time', nullable: true })
  deletedAt: Date | null;

  // Propriétés statiques
  static entityTrackedFields: string[] = [];

  /**
   * Formate une date en ISO ou retourne null.
   */
  protected static formatISODate(date: Date | string | null): string | null {
    if (!date) return null;

    if (date instanceof Date && !isNaN(date.getTime())) {
      return date.toISOString();
    }

    if (typeof date === 'string') {
      const parsedDate = new Date(date);
      if (!isNaN(parsedDate.getTime())) {
        return parsedDate.toISOString();
      }
    }

    return null;
  }

  /**
   * Retourne l'identifiant unique de l'entité
   */
  get entityIdentifier(): string {
    return `${this.id}`;
  }

  /**
   * Calcule les différences entre l'état actuel de l'entité et un nouveau modèle
   */
  getDiff(model: Partial<this>): IModelDiff {
    const diff: IModelDiff = { changed: [], newValues: {} };
    const constructor = this.constructor as typeof Model;

    for (const key of Object.keys(model)) {
      if (Object.prototype.hasOwnProperty.call(this, key)) {
        const current = (this as any)[key];
        const newValue = (model as any)[key];

        if (current !== newValue && (current != null || newValue != null)) {
          diff.changed.push(key);
          if (constructor.entityTrackedFields.includes(key)) {
            diff.newValues[key] = newValue;
          }
        }
      }
    }

    return diff;
  }

  /**
   * Met à jour l'entité avec de nouvelles données
   */
  update(data: Partial<this>): void {
    Object.assign(this, data);
  }

  /**
   * Méthode d'alias pour update pour compatibilité API
   */
  patch(data: Partial<this>): void {
    this.update(data);
  }

  /**
   * Convertit l'entité pour réponse API
   */
  toApi(): Record<string, any> {
    const result: Record<string, any> = { ...this };
    delete result.deletedAt;
    return result;
  }

  /**
   * Invalide le cache Redis pour cette entité
   */
  protected async invalidateCache(): Promise<void> {
    const redisClient = getRedisClient();
    if (!redisClient) {
      logger.warn(`Redis unavailable for ${this.constructor.name}:${this.id}`);
      return;
    }

    try {
      const entityName = this.constructor.name.toLowerCase();
      const entityKey = `entity:${entityName}:${this.id}`;
      const listPattern = `entity:${entityName}:list:*`;

      const listKeys = await redisClient.keys(listPattern);
      if (listKeys.length > 0) {
        await redisClient.del([entityKey, ...listKeys]);
        logger.info(`Cache invalidated for ${entityName}:${this.id} and ${listKeys.length} lists`);
      } else {
        await redisClient.del(entityKey);
        logger.info(`Cache invalidated for ${entityName}:${this.id}`);
      }
    } catch (error) {
      logger.error(`Cache invalidation failed for ${this.constructor.name}:${this.id}: ${error}`);
    }
  }

  /**
   * Hooks de cycle de vie TypeORM
   */
  @BeforeInsert()
  protected async beforeInsert(): Promise<void> {
    this.createdAt = new Date();
    this.updatedAt = new Date();
  }

  @AfterInsert()
  protected async afterInsert(): Promise<void> {
    await this.invalidateCache();
  }

  @BeforeUpdate()
  protected async beforeUpdate(): Promise<void> {
    this.updatedAt = new Date();
  }

  @AfterUpdate()
  protected async afterUpdate(): Promise<void> {
    await this.invalidateCache();
  }

  @BeforeSoftRemove()
  protected async beforeSoftRemove(): Promise<void> {
    // Hook pour actions avant suppression
  }

  @AfterSoftRemove()
  protected async afterSoftRemove(): Promise<void> {
    await this.invalidateCache();
  }

  /**
   * Crée une erreur de validation formatée
   */
  static createValidationError(errors: string[]): Error {
    return new ValidationError('Validation Failed', errors);
  }
}
