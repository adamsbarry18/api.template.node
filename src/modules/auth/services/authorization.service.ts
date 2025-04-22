import dayjs from 'dayjs';
import {
  FEATURES_CONFIG,
  featuresProcessedFlagsMap,
  DecodedAuthorisations,
} from '../models/features';
import { SecurityLevel } from '@/modules/users/models/users.entity';
import { UserRepository } from '@/modules/users/data/users.repository';
import { NotFoundError } from '@/common/errors/httpErrors';
import logger from '@/lib/logger';
import { redisClient } from '@/lib/redis';

const REDIS_AUTHORISATION_KEY_PATTERN = 'api-auth:user_authorisation:{userId}';
const AUTHORISATION_CACHE_TTL_SECONDS = 60 * 30; // 30 minutes

let instance: AuthorizationService | null = null;

type DecodedOverrides = Map<number, number>;

export class AuthorizationService {
  private readonly userRepository: UserRepository;

  constructor(userRepository: UserRepository = new UserRepository()) {
    this.userRepository = userRepository;
  }

  /**
   * Génère la clé Redis pour stocker les autorisations d'un utilisateur
   */
  private getRedisAuthorisationKey(userId: number): string {
    return REDIS_AUTHORISATION_KEY_PATTERN.replace('{userId}', userId.toString());
  }

  /**
   * Récupère toutes les fonctionnalités et leurs actions possibles
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
   * Liste les autorisations par niveau de sécurité
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
   * Liste les autorisations pour un niveau de sécurité donné
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
   * Récupère les autorisations effectives pour un utilisateur
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
   * Crée une autorisation temporaire pour un utilisateur
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

    // Invalider le cache des autorisations
    await this.invalidateAuthCache(userId);

    return { success: true };
  }

  /**
   * Met à jour les autorisations d'un utilisateur
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

    // Invalider le cache des autorisations
    await this.invalidateAuthCache(userId);

    return { success: true };
  }

  /**
   * Supprime les autorisations spécifiques d'un utilisateur (réinitialise les overrides et l'expiration)
   */
  async deleteAuthorisationsUser(userId: number): Promise<{ success: boolean }> {
    const user = await this.userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found');

    user.authorisationOverrides = null;
    user.permissionsExpireAt = null;
    await this.userRepository.save(user);

    // Invalider le cache des autorisations
    await this.invalidateAuthCache(userId);

    return { success: true };
  }

  /**
   * Vérifie si un utilisateur a une permission spécifique
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
   * Vérifie si le niveau de sécurité d'un utilisateur est suffisant
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

  /**
   * Récupère les permissions effectives pour un utilisateur avec cache Redis
   */
  private async getEffectivePermissions(userId: number): Promise<DecodedAuthorisations | null> {
    if (!redisClient) {
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

  /**
   * Invalide le cache des autorisations pour un utilisateur
   */
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

  /**
   * Calcule les permissions effectives sans utiliser le cache
   */
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
        finalMask = overrides.get(featureId)!;
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

  /**
   * Décode la chaîne d'override d'autorisations en Map de masques par featureId
   */
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
        const numAuth = parseInt(part, 10);
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

  /**
   * Calcule le masque de permission par défaut pour une fonctionnalité et un niveau utilisateur
   */
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

  static getInstance(): AuthorizationService {
    if (!instance) {
      instance = new AuthorizationService(new UserRepository());
    }
    return instance;
  }
}
