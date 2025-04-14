import dayjs from 'dayjs';
import logger from '@/lib/logger';
import {
  FEATURES_CONFIG,
  FEATURES_BY_NAME,
  featuresProcessedFlagsMap,
  featuresRawFlagsConfigMap,
} from './features';
import { SecurityLevel } from '../users/models/users.types';
import { DecodedAuthorisations, PermissionsInputMap } from './authorization.types';
import { UserRepository } from '../users/data/users.repository';
import { NotFoundError } from '@/common/errors/httpErrors';

// Type interne pour représenter les overrides décodés
type DecodedOverrides = Map<number, number>;
export class AuthorisationsService {
  private readonly userRepository: UserRepository;

  constructor() {
    this.userRepository = new UserRepository();
  }

  /**
   * Décode la chaîne `authorisationOverrides` (ex: "123.456") en une Map de masques par featureId.
   * @param overrideString - La chaîne provenant de l'entité User.
   * @returns Une Map<featureId, permissionMask>.
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
   * Calcule le masque de permission par défaut pour une feature donnée et un niveau utilisateur.
   * @param featureId - L'ID de la feature.
   * @param userLevel - Le niveau de sécurité de l'utilisateur.
   * @returns Le masque de bits des permissions par défaut.
   */
  private calculateDefaultMaskForLevel(featureId: number, userLevel: SecurityLevel): number {
    const featureInfo = featuresProcessedFlagsMap.get(featureId);
    if (!featureInfo) return 0;

    let defaultMask = 0;
    const actionsMap = featureInfo.flags;
    for (const actionName in actionsMap) {
      const actionConfig = actionsMap[actionName];
      if (actionConfig.level !== undefined && actionConfig.level <= userLevel) {
        defaultMask |= actionConfig.combinedMask;
      }
    }
    return defaultMask;
  }

  /**
   * Calcule les permissions effectives complètes pour un utilisateur donné.
   * Combine les permissions par défaut (basées sur le niveau) avec les overrides spécifiques.
   * @param userId - L'ID de l'utilisateur.
   * @returns Un objet DecodedAuthorisations ou null si l'utilisateur n'est pas trouvé.
   * @throws {NotFoundError} Si l'utilisateur n'existe pas.
   * @throws {InternalServerError} Si la configuration des features est corrompue.
   */
  async getUserEffectivePermissions(userId: number): Promise<DecodedAuthorisations | null> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new NotFoundError(`User with ID ${userId} not found when calculating permissions.`);
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
      } else {
        finalMask = this.calculateDefaultMaskForLevel(featureId, baseLevel);
      }
      const allowedActions: string[] = [];
      const actionsMap = featureProcessedInfo.flags;
      for (const actionName in actionsMap) {
        const actionConfig = actionsMap[actionName];
        if ((finalMask & actionConfig.combinedMask) === actionConfig.combinedMask) {
          allowedActions.push(actionName);
        }
      }

      if (allowedActions.length > 0) {
        effectivePermissions[featureName] = {
          id: featureId,
          actions: allowedActions,
        };
      }
    });
    const expiresAt = permissionExpiryDate?.isValid() ? permissionExpiryDate.toDate() : null;
    return {
      userId: user.id,
      level: baseLevel,
      expiresAt: expiresAt,
      permissions: effectivePermissions,
    };
  }

  /**
   * Vérifie si un utilisateur a une permission spécifique.
   * NOTE: Préférer utiliser `AuthService.hasPermission` qui intègre le cache.
   * Cette méthode effectue un calcul complet à chaque appel.
   */
  async checkPermission(userId: number, featureName: string, actionName: string): Promise<boolean> {
    try {
      const effectiveAuths = await this.getUserEffectivePermissions(userId);
      return !!effectiveAuths?.permissions?.[featureName]?.actions.includes(actionName);
    } catch (error) {
      if (error instanceof NotFoundError) {
        logger.warn(`checkPermission failed for non-existent user ${userId}`);
      } else {
        logger.error(error, `Error in checkPermission(${userId}, ${featureName}, ${actionName})`);
      }
      return false;
    }
  }

  /**
   * Encode une structure de permissions { featureName: [actionName] } en chaîne `authorisationOverrides`.
   * @param permissions - L'objet décrivant les permissions à encoder.
   * @returns La chaîne encodée pour stockage en BDD, ou null si aucune permission n'est fournie.
   */
  encodePermissionsToString(permissions: PermissionsInputMap): string | null {
    const featureMasks: Map<number, number> = new Map();
    for (const featureName in permissions) {
      const featureConfig = FEATURES_BY_NAME[featureName];
      const rawFlagsConfig = featureConfig ? featuresRawFlagsConfigMap.get(featureConfig.id) : null;

      if (featureConfig && rawFlagsConfig) {
        let currentMask = 0;
        const actionsToEncode = permissions[featureName];
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
        }
      } else {
        logger.warn(`Encode: Unknown feature name '${featureName}'. Skipping feature.`);
      }
    }

    if (featureMasks.size === 0) {
      return null;
    }

    return this.encodeFeatureMasks(featureMasks);
  }

  /**
   * Encode une Map<featureId, permissionMask> en chaîne pour la BDD.
   * Combine chaque paire (ID, masque) en un entier de 32 bits.
   */
  private encodeFeatureMasks(featureMasks: Map<number, number>): string | null {
    const encodedParts: number[] = [];

    featureMasks.forEach((permissionMask, featureId) => {
      try {
        if (permissionMask < 0 || permissionMask > 0xffff) {
          logger.warn(
            `Permission mask ${permissionMask} for feature ${featureId} exceeds 16 bits (0-65535). Clamping.`,
          );
          permissionMask = Math.max(0, Math.min(permissionMask, 0xffff));
        }
        if (featureId < 0 || featureId > 0xffff) {
          logger.warn(`Feature ID ${featureId} exceeds 16 bits (0-65535). Skipping.`);
          return;
        }

        const idBits = featureId.toString(2).padStart(16, '0');
        const permBits = permissionMask.toString(2).padStart(16, '0');
        const combined = parseInt(idBits + permBits, 2);
        if (!isNaN(combined)) {
          encodedParts.push(combined);
        } else {
          logger.warn(
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
    const result = encodedParts.join('.');
    return result !== '' ? result : null;
  }
}
