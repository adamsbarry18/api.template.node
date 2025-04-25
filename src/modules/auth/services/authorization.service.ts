import dayjs from 'dayjs';

import { NotFoundError } from '@/common/errors/httpErrors';
import logger from '@/lib/logger';
import { redisClient } from '@/lib/redis';
import { UserRepository } from '@/modules/users/data/users.repository';
import { SecurityLevel } from '@/modules/users/models/users.entity';

import {
  FEATURES_CONFIG,
  featuresProcessedFlagsMap,
  type DecodedAuthorisations,
} from '../models/features';

const REDIS_AUTHORISATION_KEY_PATTERN = 'api:users:user_authorisation:{userId}';
const AUTHORISATION_CACHE_TTL_SECONDS = 60 * 30; // 30 minutes

let instance: AuthorizationService | null = null;

type DecodedOverrides = Map<number, number>;

export class AuthorizationService {
  private readonly userRepository: UserRepository;

  constructor(userRepository: UserRepository = new UserRepository()) {
    this.userRepository = userRepository;
  }

  /**
   * Generates the Redis key for storing a user's authorizations.
   * @param userId The user ID.
   * @returns The Redis key string.
   */
  private getRedisAuthorisationKey(userId: number): string {
    return REDIS_AUTHORISATION_KEY_PATTERN.replace('{userId}', userId.toString());
  }

  /**
   * Retrieves all features and their possible actions.
   * @returns An object mapping feature names to their actions.
   */
  async getAllFeatures(): Promise<Record<string, string[]>> {
    const result: Record<string, string[]> = {};
    FEATURES_CONFIG.forEach((feature) => {
      const processed = featuresProcessedFlagsMap.get(feature.id);
      if (processed) {
        result[feature.name] = Object.keys(processed.flags);
      }
    });
    return result;
  }

  /**
   * Lists authorizations by security level.
   * @returns An object mapping levels to their authorizations.
   */
  async listAuthorisationsByLevel(): Promise<Record<number, Record<string, string[]>>> {
    const levels = Object.values(SecurityLevel).filter((v) => typeof v === 'number') as number[];
    const result: Record<number, Record<string, string[]>> = {};
    for (const level of levels) {
      result[level] = await this.listAuthorisationsFromLevel(level);
    }
    return result;
  }

  /**
   * Lists authorizations for a given security level.
   * @param level The security level.
   * @returns An object mapping feature names to their actions.
   */
  async listAuthorisationsFromLevel(level: number): Promise<Record<string, string[]>> {
    const res: Record<string, string[]> = {};
    FEATURES_CONFIG.forEach((feature) => {
      const processed = featuresProcessedFlagsMap.get(feature.id);
      if (processed) {
        res[feature.name] = Object.entries(processed.flags)
          .filter(([, flag]) => flag.level <= level)
          .map(([name]) => name);
      }
    });
    return res;
  }

  /**
   * Retrieves the effective authorizations for a user.
   * @param userId The user ID.
   * @returns The user's authorizations, expiration, and level.
   */
  async getAuthorisation(userId: number): Promise<{
    authorisation: Record<string, string[]>;
    expire: Date | null;
    level: number;
  }> {
    const permissions = await this.getEffectivePermissions(userId);
    if (!permissions) throw new NotFoundError('User not found');

    return {
      authorisation: Object.fromEntries(
        Object.entries(permissions.permissions).map(([k, v]) => [k, v.actions]),
      ),
      expire: permissions.expiresAt,
      level: permissions.level,
    };
  }

  /**
   * Creates a temporary authorization for a user.
   * @param userId The user ID.
   * @param param1 Expiration date and/or security level.
   * @returns Success status.
   */
  async createTemporaryAuthorization(
    userId: number,
    { expire, level }: { expire?: Date; level?: number },
  ): Promise<{ success: boolean }> {
    const user = await this.userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found');

    user.permissionsExpireAt = expire ?? dayjs().add(3, 'days').toDate();
    if (level !== undefined) user.level = level;
    await this.userRepository.save(user);

    await this.invalidateAuthCache(userId);

    return { success: true };
  }

  /**
   * Updates a user's authorizations.
   * @param userId The user ID.
   * @param data Level and/or authorization overrides.
   * @returns Success status.
   */
  async updateAuthorization(
    userId: number,
    data: { level?: number; authorisationOverrides?: string | null },
  ): Promise<{ success: boolean }> {
    const user = await this.userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found');

    if (data.level !== undefined) user.level = data.level;
    if (data.authorisationOverrides !== undefined)
      user.authorisationOverrides = data.authorisationOverrides;

    await this.userRepository.save(user);

    await this.invalidateAuthCache(userId);

    return { success: true };
  }

  /**
   * Deletes a user's specific authorizations (resets overrides and expiration).
   * @param userId The user ID.
   * @returns Success status.
   */
  async deleteAuthorisationsUser(userId: number): Promise<{ success: boolean }> {
    const user = await this.userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found');

    user.authorisationOverrides = null;
    user.permissionsExpireAt = null;
    await this.userRepository.save(user);

    await this.invalidateAuthCache(userId);

    return { success: true };
  }

  /**
   * Checks if a user has a specific permission.
   * @param userId The user ID.
   * @param featureName The feature name.
   * @param actionName The action name.
   * @returns True if the user has the permission, false otherwise.
   */
  async checkAuthorisation(
    userId: number,
    featureName: string,
    actionName: string,
  ): Promise<boolean> {
    const permissions = await this.getEffectivePermissions(userId);
    const hasPermission =
      permissions?.permissions?.[featureName]?.actions.includes(actionName) || false;

    logger.debug(
      `Authorization check for User ${userId}, Feature ${featureName}, Action ${actionName}: ${hasPermission}`,
    );

    return hasPermission;
  }

  /**
   * Checks if a user's security level is sufficient.
   * @param userId The user ID.
   * @param requiredLevel The required security level.
   * @returns True if the user has sufficient level, false otherwise.
   */
  async checkLevelAccess(userId: number, requiredLevel: SecurityLevel): Promise<boolean> {
    const user = await this.userRepository.findById(userId);
    if (!user) throw new NotFoundError(`User with id ${userId} not found.`);

    const hasAccess = user.level >= requiredLevel;

    logger.debug(
      `Level access check for User ${userId} (Level ${user.level}) vs Required ${requiredLevel}: ${hasAccess}`,
    );

    return hasAccess;
  }

  private async getEffectivePermissions(userId: number): Promise<DecodedAuthorisations | null> {
    if (!redisClient?.isReady) {
      logger.warn('Redis unavailable for retrieving authorizations. Calculating directly.');
      return this.calculateEffectivePermissions(userId);
    }

    const redisKey = this.getRedisAuthorisationKey(userId);
    let permissions: DecodedAuthorisations | null = null;

    try {
      const cached = await redisClient.get(redisKey);
      if (cached) {
        permissions = JSON.parse(cached);
        if (permissions?.expiresAt && dayjs(permissions.expiresAt).isBefore(dayjs())) {
          logger.info(`Authorization cache expired for user ${userId}. Recalculating.`);
          permissions = null;
          await redisClient.del(redisKey);
        }
      }
    } catch (error) {
      logger.error(error, `Error retrieving cache for userId: ${userId}`);
    }

    if (!permissions) {
      logger.debug(`Cache miss for user ${userId} authorizations. Calculating.`);
      permissions = await this.calculateEffectivePermissions(userId);
      if (permissions) {
        try {
          await redisClient.setEx(
            redisKey,
            AUTHORISATION_CACHE_TTL_SECONDS,
            JSON.stringify(permissions),
          );
          logger.debug(`Authorizations for user ${userId} cached.`);
        } catch (error) {
          logger.error(error, `Error caching authorizations for userId: ${userId}`);
        }
      }
    } else {
      logger.debug(`Cache hit for user ${userId} authorizations.`);
    }

    return permissions;
  }

  private async invalidateAuthCache(userId: number): Promise<void> {
    if (!redisClient) return;

    try {
      const redisKey = this.getRedisAuthorisationKey(userId);
      await redisClient.del(redisKey);
      logger.debug(`Authorization cache invalidated for user ${userId}`);
    } catch (error) {
      logger.error(error, `Failed to invalidate authorization cache for user ${userId}`);
    }
  }

  private async calculateEffectivePermissions(
    userId: number,
  ): Promise<DecodedAuthorisations | null> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      logger.warn(`User with ID ${userId} not found when calculating permissions.`);
      return null;
    }

    const baseLevel = user.level as SecurityLevel;
    let overrides: DecodedOverrides = new Map();
    let areOverridesExpired = false;
    const permissionExpiryDate = user.permissionsExpireAt ? dayjs(user.permissionsExpireAt) : null;

    if (
      permissionExpiryDate &&
      permissionExpiryDate.isValid() &&
      permissionExpiryDate.isBefore(dayjs())
    ) {
      areOverridesExpired = true;
      logger.info(
        `Authorisation overrides for user ${userId} have expired (Expiry: ${permissionExpiryDate.toISOString()}). Using default level permissions.`,
      );
    }

    if (user.authorisationOverrides && !areOverridesExpired) {
      overrides = this.decodeAuthorisationOverrides(user.authorisationOverrides);
    }

    const effectivePermissions: DecodedAuthorisations['permissions'] = {};

    FEATURES_CONFIG.forEach((featureConfig) => {
      const featureId = featureConfig.id;
      const featureName = featureConfig.name;
      const featureProcessedInfo = featuresProcessedFlagsMap.get(featureId);

      if (!featureProcessedInfo) {
        logger.error(
          `Feature ID ${featureId} (${featureName}) not found in processed feature map during permission calculation. Configuration might be corrupt.`,
        );
        return;
      }

      let finalMask: number;
      if (overrides.has(featureId)) {
        const foundLevel = overrides.get(featureId);
        finalMask =
          foundLevel !== undefined
            ? foundLevel
            : this.calculateDefaultMaskForLevel(featureId, baseLevel);
        logger.debug(`User ${userId}, Feature ${featureName}: Using override mask ${finalMask}`);
      } else {
        finalMask = this.calculateDefaultMaskForLevel(featureId, baseLevel);
        logger.debug(
          `User ${userId}, Feature ${featureName}: Using default mask ${finalMask} for level ${baseLevel}`,
        );
      }

      const allowedActions: string[] = [];
      const actionsMap = featureProcessedInfo.flags;
      for (const actionName in actionsMap) {
        if (Object.prototype.hasOwnProperty.call(actionsMap, actionName)) {
          const actionConfig = actionsMap[actionName];
          if ((finalMask & actionConfig.combinedMask) === actionConfig.combinedMask) {
            allowedActions.push(actionName);
          }
        }
      }

      if (allowedActions.length > 0) {
        effectivePermissions[featureName] = {
          id: featureId,
          actions: allowedActions,
        };
      }
    });

    const expiresAt =
      permissionExpiryDate?.isValid() && !areOverridesExpired
        ? permissionExpiryDate.toDate()
        : null;

    return {
      userId: user.id,
      level: baseLevel,
      expiresAt: expiresAt,
      permissions: effectivePermissions,
    };
  }

  private decodeAuthorisationOverrides(
    overrideString: string | null | undefined,
  ): DecodedOverrides {
    const decoded: DecodedOverrides = new Map();
    if (!overrideString) {
      return decoded;
    }

    const parts = overrideString.split('.');
    for (const part of parts) {
      try {
        const numAuth = parseInt(part, 10) ?? 0;
        if (isNaN(numAuth) || numAuth < 0) {
          logger.warn(
            `Invalid non-numeric or negative part found in authorisationOverrides: '${part}'. Skipping.`,
          );
          continue;
        }
        const bitAuth = numAuth.toString(2).padStart(32, '0');
        const featureId = parseInt(bitAuth.substring(0, 16), 2);
        const permissionMask = parseInt(bitAuth.substring(16), 2);

        if (isNaN(featureId) || isNaN(permissionMask)) {
          logger.warn(`Failed to parse featureId or permissionMask from part '${part}'. Skipping.`);
          continue;
        }

        if (featuresProcessedFlagsMap.has(featureId)) {
          decoded.set(featureId, permissionMask);
        } else {
          logger.warn(
            `Decoded unknown feature ID ${featureId} from authorisationOverrides part '${part}'. Ignoring.`,
          );
        }
      } catch (error) {
        logger.error(error, `Error decoding authorisationOverrides part '${part}'. Skipping.`);
      }
    }
    return decoded;
  }

  private calculateDefaultMaskForLevel(featureId: number, userLevel: SecurityLevel): number {
    const featureInfo = featuresProcessedFlagsMap.get(featureId);
    if (!featureInfo) {
      logger.warn(`Default mask calculation: Feature ID ${featureId} not found in config.`);
      return 0;
    }

    let defaultMask = 0;
    const actionsMap = featureInfo.flags;
    for (const actionName in actionsMap) {
      if (Object.prototype.hasOwnProperty.call(actionsMap, actionName)) {
        const actionConfig = actionsMap[actionName];
        if (actionConfig.level !== undefined && actionConfig.level <= userLevel) {
          defaultMask |= actionConfig.combinedMask;
        }
      }
    }
    return defaultMask;
  }

  /**
   * Returns a singleton instance of AuthorizationService.
   * @returns The AuthorizationService instance.
   */
  static getInstance(): AuthorizationService {
    if (!instance) {
      instance = new AuthorizationService(new UserRepository());
    }
    return instance;
  }
}
