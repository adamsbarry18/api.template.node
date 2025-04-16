import jwt from 'jsonwebtoken';
import dayjs from 'dayjs';
import { redisClient } from '@/lib/redis';
import config from '@/config';
import logger from '@/lib/logger';
import { UnauthorizedError, InternalServerError } from '@/common/errors/httpErrors';
import { UsersService } from '@/modules/users/services/users.services';
import { UserRepository } from '@/modules/users/data/users.repository';
import { PasswordStatus, UserApiResponse, SecurityLevel } from '@/modules/users/models/users.types';
import {
  DecodedAuthorisations,
  PermissionsInputMap,
} from '@/modules/auth/models/authorization.types';
import {
  FEATURES_CONFIG,
  FEATURES_BY_NAME,
  featuresProcessedFlagsMap,
  featuresRawFlagsConfigMap,
} from '../models/features';

const REDIS_AUTHORISATION_KEY_PATTERN = 'api-auth:user_authorisation:{userId}';
const REDIS_TOKEN_INVALIDATION_KEY = 'api-auth:token_invalidation:{token}';
const AUTHORISATION_CACHE_TTL_SECONDS = 60 * 30; // 30 minutes
const TOKEN_DEFAULT_EXPIRE_SECONDS = 60 * 60 * 24 * 30; // 30 jours
const PASSWORD_EXPIRED_IN_DAYS = 90;

type DecodedOverrides = Map<number, number>;

export class AuthService {
  private readonly usersService: UsersService;
  private readonly userRepository: UserRepository;

  constructor(userRepository?: UserRepository, usersService?: UsersService) {
    this.userRepository = userRepository ?? new UserRepository();
    this.usersService = usersService ?? new UsersService(this.userRepository);
  }

  /**
   * Generates the Redis key to store user authorizations.
   *
   * @private
   * @param {number} userId - The user's ID.
   * @returns {string} The Redis key for user authorizations.
   */
  private getRedisAuthorisationKey(userId: number): string {
    return REDIS_AUTHORISATION_KEY_PATTERN.replace('{userId}', userId.toString());
  }

  /**
   * Generates the Redis key for token invalidation.
   *
   * @private
   * @param {string} token - The JWT token.
   * @returns {string} The Redis key for token invalidation.
   */
  private getRedisInvalidationKey(token: string): string {
    return REDIS_TOKEN_INVALIDATION_KEY.replace('{token}', token);
  }

  /**
   * Authenticates a user by verifying email and password.
   * Also checks the password status (validation and expiration).
   *
   * @param {string} email - The user's email address.
   * @param {string} password - The user's password.
   * @returns {Promise<{ token: string; user: UserApiResponse }>} An object containing the JWT token and user details.
   * @throws {UnauthorizedError} If credentials are required, invalid, password is validating, or password has expired.
   */
  async login(email: string, password: string): Promise<{ token: string; user: UserApiResponse }> {
    if (!email || !password) {
      throw new UnauthorizedError('Email and password required.');
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await this.usersService.findByEmailForAuth(normalizedEmail);
    if (!user) {
      throw new UnauthorizedError('Invalid email or password.');
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      logger.error(`Incorrect password for user ID: ${user.id}`);
      throw new UnauthorizedError('Invalid email or password.');
    }

    if (user.passwordStatus === PasswordStatus.VALIDATING) {
      throw new UnauthorizedError('Password validation in progress.');
    }
    const passwordExpired = user.passwordUpdatedAt
      ? dayjs(user.passwordUpdatedAt).add(PASSWORD_EXPIRED_IN_DAYS, 'days').isBefore(dayjs())
      : false;
    if (user.passwordStatus === PasswordStatus.EXPIRED || passwordExpired) {
      if (user.passwordStatus !== PasswordStatus.EXPIRED) {
        await this.usersService.updatePasswordStatus(user.id, PasswordStatus.EXPIRED);
      }
      throw new UnauthorizedError('Password expired.');
    }

    const token = await this.signToken(user.id, { level: user.level, internal: user.internal });
    const userApi = this.usersService.mapToApiResponse(user);
    return { user: userApi!, token };
  }

  /**
   * Logs out a user by invalidating their token.
   * Invalidation stores the token in Redis to prevent its reuse.
   *
   * @param {string} token - The JWT token to invalidate.
   * @returns {Promise<void>}
   */
  async logout(token: string): Promise<void> {
    if (!token) return;
    await this.invalidateToken(token);
  }

  /**
   * Signs a JWT token for a user.
   * The payload contains the userId and other useful information for verification.
   *
   * @param {number} userId - The user's ID.
   * @param {Record<string, any>} [extraPayload={}] - Additional data to include in the token payload.
   * @returns {Promise<string>} The signed JWT token.
   * @throws {InternalServerError} If token generation fails.
   */
  async signToken(userId: number, extraPayload: Record<string, any> = {}): Promise<string> {
    const payload = { sub: userId, ...extraPayload };
    try {
      return jwt.sign(payload, config.JWT_SECRET, { expiresIn: TOKEN_DEFAULT_EXPIRE_SECONDS });
    } catch (error: any) {
      logger.error(error, `Error signing JWT for user ID: ${userId}`);
      throw new InternalServerError('Could not generate authentication token.');
    }
  }

  /**
   * Invalidates a token by storing it in Redis with a TTL equal to its original expiration time.
   *
   * @param {string} token - The JWT token to invalidate.
   * @returns {Promise<void>}
   * @throws {InternalServerError} If Redis is unavailable or if storing the token fails.
   */
  async invalidateToken(token: string): Promise<void> {
    if (!redisClient) {
      logger.error('Redis unavailable for token invalidation.');
      throw new InternalServerError('Authentication service temporarily unavailable.');
    }
    const redisKey = this.getRedisInvalidationKey(token);
    try {
      await redisClient.setEx(redisKey, TOKEN_DEFAULT_EXPIRE_SECONDS, 'invalidated');
    } catch (error) {
      logger.error(error, `Error invalidating token: ${token.substring(0, 10)}...`);
      throw new InternalServerError('Error during logout.');
    }
  }

  /**
   * Checks if a token has been invalidated (blacklisted) via Redis.
   *
   * @param {string} token - The JWT token to check.
   * @returns {Promise<boolean>} True if the token is invalidated, false otherwise.
   */
  async isTokenInvalidated(token: string): Promise<boolean> {
    if (!redisClient) {
      logger.error('Redis unavailable for token invalidation check.');
      // Consider allowing access if Redis is down, depending on security policy
      return false;
    }
    const redisKey = this.getRedisInvalidationKey(token);
    try {
      const res = await redisClient.get(redisKey);
      return !!res;
    } catch (error) {
      logger.error(error, `Error checking token invalidation: ${token.substring(0, 10)}...`);
      // Fail safe: assume token is valid if Redis check fails
      return false;
    }
  }

  /**
   * Retrieves the effective authorizations for a user.
   * First attempts to load from Redis cache, otherwise calculates permissions and caches the result.
   *
   * @param {number} userId - The user's ID.
   * @returns {Promise<DecodedAuthorisations | null>} The decoded authorizations or null if not found/error.
   */
  async getAuthorisation(userId: number): Promise<DecodedAuthorisations | null> {
    if (!redisClient) {
      logger.warn('Redis unavailable for retrieving authorizations. Calculating directly.');
      return this.getUserEffectivePermissions(userId);
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
      permissions = await this.getUserEffectivePermissions(userId);
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
   * Generates a new JWT token for a given user.
   *
   * @param {number} userId - The ID of the user.
   * @returns {Promise<{ token: string }>} The signed JWT token.
   * @throws {NotFoundError} If the user is not found.
   */
  async generateTokenForUser(userId: number): Promise<{ token: string }> {
    const user = await this.usersService.findById(userId);
    const token = await this.signToken(user.id, { level: user.level, internal: user.internal });
    return { token };
  }

  /**
   * Checks if a user has a specific permission for a given feature and action.
   *
   * @param {number} userId - The user's ID.
   * @param {string} featureName - The name of the feature.
   * @param {string} actionName - The name of the action.
   * @returns {Promise<boolean>} True if the user has the permission, false otherwise.
   */
  async checkAuthorisation(
    userId: number,
    featureName: string,
    actionName: string,
  ): Promise<boolean> {
    const permissions = await this.getAuthorisation(userId);
    const hasPermission =
      permissions?.permissions?.[featureName]?.actions.includes(actionName) || false;
    logger.debug(
      `Authorization check for User ${userId}, Feature ${featureName}, Action ${actionName}: ${hasPermission}`,
    );
    return hasPermission;
  }

  /**
   * Checks if the user's security level is sufficient compared to the required level.
   *
   * @param {number} userId - The user's ID.
   * @param {SecurityLevel} requiredLevel - The minimum required security level.
   * @returns {Promise<boolean>} True if the user's level meets or exceeds the required level, false otherwise.
   * @throws {NotFoundError} If the user is not found.
   */
  async checkLevelAccess(userId: number, requiredLevel: SecurityLevel): Promise<boolean> {
    const user = await this.usersService.findById(userId);
    const hasAccess = user.level >= requiredLevel;
    logger.debug(
      `Level access check for User ${userId} (Level ${user.level}) vs Required ${requiredLevel}: ${hasAccess}`,
    );
    return hasAccess;
  }

  /**
   * Decodes the `authorisationOverrides` string (e.g., "123.456") into a Map of masks per featureId.
   *
   * @private
   * @param {string | null | undefined} overrideString - The string from the User entity.
   * @returns {DecodedOverrides} A Map<featureId, permissionMask>.
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
   * Calculates the default permission mask for a given feature and user level.
   *
   * @private
   * @param {number} featureId - The ID of the feature.
   * @param {SecurityLevel} userLevel - The user's security level.
   * @returns {number} The default permission bitmask.
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

  /**
   * Calculates the complete effective permissions for a given user.
   * Combines default permissions (based on level) with specific overrides.
   *
   * @param {number} userId - The user's ID.
   * @returns {Promise<DecodedAuthorisations | null>} A DecodedAuthorisations object or null if the user is not found.
   */
  async getUserEffectivePermissions(userId: number): Promise<DecodedAuthorisations | null> {
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
   * Checks if a user has a specific permission (direct method without cache).
   * Useful for one-off checks where caching is not desired or available.
   *
   * @param {number} userId - The user's ID.
   * @param {string} featureName - The name of the feature.
   * @param {string} actionName - The name of the action.
   * @returns {Promise<boolean>} True if the user has the permission, false otherwise.
   */
  async checkPermissionDirect(
    userId: number,
    featureName: string,
    actionName: string,
  ): Promise<boolean> {
    try {
      const effectiveAuths = await this.getUserEffectivePermissions(userId);
      return !!effectiveAuths?.permissions?.[featureName]?.actions.includes(actionName);
    } catch (error) {
      logger.error(
        error,
        `Error in checkPermissionDirect(${userId}, ${featureName}, ${actionName})`,
      );
      return false;
    }
  }

  /**
   * Encodes a permission structure { featureName: [actionName] } into an `authorisationOverrides` string.
   *
   * @param {PermissionsInputMap | null | undefined} permissions - The object describing the permissions to encode.
   * @returns {string | null} The encoded string for database storage, or null if no permissions are provided.
   */
  public static encodePermissionsToString(
    permissions: PermissionsInputMap | null | undefined,
  ): string | null {
    // Ajout de static
    if (!permissions || Object.keys(permissions).length === 0) {
      return null;
    }

    const featureMasks: Map<number, number> = new Map();

    for (const featureName in permissions) {
      if (Object.prototype.hasOwnProperty.call(permissions, featureName)) {
        const featureConfig = FEATURES_BY_NAME[featureName];
        const rawFlagsConfig = featureConfig
          ? featuresRawFlagsConfigMap.get(featureConfig.id)
          : null;

        if (featureConfig && rawFlagsConfig) {
          let currentMask = 0;
          const actionsToEncode = permissions[featureName];

          if (!Array.isArray(actionsToEncode)) {
            logger.warn(
              `Encode: Actions for feature '${featureName}' is not an array. Skipping feature.`,
            );
            continue;
          }

          actionsToEncode.forEach((action) => {
            const actionConfig = rawFlagsConfig[action];
            if (actionConfig) {
              currentMask |= actionConfig.value;
            } else {
              logger.warn(
                `Encode: Unknown action '${action}' in feature '${featureName}'. Skipping action.`,
              );
            }
          });

          if (currentMask > 0) {
            featureMasks.set(featureConfig.id, currentMask);
          } else {
            logger.debug(
              `Encode: No valid actions provided for feature '${featureName}', resulting mask is 0. Not storing override.`,
            );
          }
        } else {
          logger.warn(`Encode: Unknown feature name '${featureName}'. Skipping feature.`);
        }
      }
    }

    if (featureMasks.size === 0) {
      return null;
    }

    // Appel de la méthode statique
    return AuthService.encodeFeatureMasks(featureMasks);
  }

  /**
   * Encodes a Map<featureId, permissionMask> into a string for the database.
   * Combines each (ID, mask) pair into a 32-bit integer.
   *
   * @private
   * @param {Map<number, number>} featureMasks - The map of feature IDs to permission masks.
   * @returns {string | null} The encoded string or null if the map is empty or encoding fails.
   */
  private static encodeFeatureMasks(featureMasks: Map<number, number>): string | null {
    // Ajout de static
    const encodedParts: number[] = [];

    featureMasks.forEach((permissionMask, featureId) => {
      try {
        if (
          typeof featureId !== 'number' ||
          featureId < 0 ||
          featureId > 0xffff ||
          isNaN(featureId)
        ) {
          logger.warn(`Invalid Feature ID ${featureId}. Skipping.`);
          return;
        }
        if (
          typeof permissionMask !== 'number' ||
          permissionMask < 0 ||
          permissionMask > 0xffff ||
          isNaN(permissionMask)
        ) {
          logger.warn(
            `Invalid Permission mask ${permissionMask} for feature ${featureId}. Clamping to 0-65535.`,
          );
          permissionMask = Math.max(0, Math.min(permissionMask, 0xffff));
        }

        const idBits = featureId.toString(2).padStart(16, '0');
        const permBits = permissionMask.toString(2).padStart(16, '0');
        const combined = parseInt(idBits + permBits, 2);

        if (!isNaN(combined)) {
          encodedParts.push(combined);
        } else {
          logger.error(
            `Could not parse combined bits for feature ${featureId} (mask: ${permissionMask}). Skipping.`,
          );
        }
      } catch (e) {
        logger.error(
          e,
          `Error encoding feature ${featureId} with mask ${permissionMask}. Skipping.`,
        );
      }
    });

    if (encodedParts.length === 0) {
      return null;
    }

    const result = encodedParts.join('.');
    return result;
  }
}
