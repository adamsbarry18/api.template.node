import {
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
  JoinColumn,
} from 'typeorm';

import logger from '@/lib/logger';
import { getRedisClient } from '@/lib/redis';
import dayjs from 'dayjs';

import utc from 'dayjs/plugin/utc';
import timezone from 'dayjs/plugin/timezone';

dayjs.extend(utc);
dayjs.extend(timezone);

/**
 * Classe de base pour les entités TypeORM, fournissant validation, gestion du cache et sérialisation.
 */
export abstract class Model {
  @PrimaryGeneratedColumn({ name: 'id' })
  id!: number;

  @CreateDateColumn({ type: 'timestamp', name: 'created_time' })
  createdAt!: Date;

  @UpdateDateColumn({ type: 'timestamp', name: 'updated_time' })
  updatedAt!: Date;

  @JoinColumn({ name: 'created_by_user_id' })
  createdByUserId?: number | null;

  @JoinColumn({ name: 'updated_by_user_id' })
  updatedByUserId?: number | null;

  @DeleteDateColumn({ type: 'timestamp', name: 'deleted_time', nullable: true })
  deletedAt?: Date | null;

  /**
   * Formate une date en ISO ou retourne null.
   */
  static formatISODate(date: Date | null | undefined): string | null {
    if (!date) return null;
    return dayjs(date).toISOString();
  }

  /**
   * Normalized entity id for user entity changelog
   * @returns Normalized identifier
   */
  get entityIdentifier(): string {
    return `${this.id}`;
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
    return {
      id: (this as any).id,
      createdAt: Model.formatISODate(this.createdAt),
      updatedAt: Model.formatISODate(this.updatedAt),
    };
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
      } else {
        await redisClient.del(entityKey);
      }
    } catch (error) {
      logger.error(`Cache invalidation failed for ${this.constructor.name}:${this.id}: ${error}`);
    }
  }

  /**
   * Hooks de cycle de vie TypeORM
   */
  @BeforeInsert()
  protected beforeInsert(): void {
    this.createdAt = new Date();
    this.updatedAt = new Date();
  }

  @AfterInsert()
  protected async afterInsert(): Promise<void> {
    await this.invalidateCache();
  }

  @BeforeUpdate()
  protected beforeUpdate(): void {
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
}
