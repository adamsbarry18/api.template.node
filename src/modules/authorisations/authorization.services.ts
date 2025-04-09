import dayjs from 'dayjs';
import logger from '@/lib/logger';
import {
  FEATURES_CONFIG,
  FEATURES_BY_NAME,
  featuresProcessedFlagsMap,
  featuresRawFlagsConfigMap,
  paddingLeft,
} from './features';
import { SecurityLevel } from '../users/models/users.types';
import { DecodedAuthorisations, PermissionsInputMap } from './authorization.types';
import { UserRepository } from '../users/data/users.repository';
import { NotFoundError } from '@/common/errors/httpErrors';

type DecodedOverrides = Map<number, number>;

export class AuthorisationsService {
  private readonly userRepository: UserRepository;

  constructor() {
    this.userRepository = new UserRepository();
  }

  /** Décode la chaîne 'authorisationOverrides'. (INCHANGÉ) */
  private decodeAuthorisationOverrides(
    overrideString: string | null | undefined,
  ): DecodedOverrides {
    // ... (logique identique à la version précédente) ...
    const decoded: DecodedOverrides = new Map();
    if (!overrideString) return decoded;
    const parts = overrideString.split('.');
    for (const part of parts) {
      try {
        const numAuth = parseInt(part, 10);
        if (isNaN(numAuth)) continue;
        const bitAuth = paddingLeft(numAuth.toString(2), '0'.repeat(32));
        const featureId = parseInt(bitAuth.substring(0, 16), 2);
        const permissionMask = parseInt(bitAuth.substring(16), 2);
        if (featuresProcessedFlagsMap.has(featureId)) {
          // Vérifier existence avec map traitée
          decoded.set(featureId, permissionMask);
        } else {
          /* log warn */
        }
      } catch (error) {
        /* log error */
      }
    }
    return decoded;
  }

  /** Calcule le masque par défaut pour une feature/level. (INCHANGÉ) */
  private calculateDefaultMaskForLevel(featureId: number, userLevel: SecurityLevel): number {
    // ... (logique identique à la version précédente, utilise featuresProcessedFlagsMap) ...
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

  /** Calcule les permissions effectives d'un utilisateur. */
  async getUserEffectivePermissions(userId: number): Promise<DecodedAuthorisations | null> {
    const user = await this.userRepository.findById(userId);
    if (!user) if (!user) throw new NotFoundError('Could not find user');

    const baseLevel = user.level as SecurityLevel;
    let overrides: DecodedOverrides = new Map();
    let areOverridesExpired = false;

    if (user.permissionsExpireAt && dayjs(user.permissionsExpireAt).isBefore(dayjs())) {
      areOverridesExpired = true;
    }
    if (user.authorisationOverrides && !areOverridesExpired) {
      overrides = this.decodeAuthorisationOverrides(user.authorisationOverrides);
    }

    const effectivePermissions: DecodedAuthorisations['permissions'] = {};

    FEATURES_CONFIG.forEach((featureConfig) => {
      const featureId = featureConfig.id;
      const featureName = featureConfig.name;
      const featureProcessedInfo = featuresProcessedFlagsMap.get(featureId);
      if (!featureProcessedInfo) return;

      let finalMask: number;
      if (overrides.has(featureId)) {
        finalMask = overrides.get(featureId)!;
      } else {
        finalMask = this.calculateDefaultMaskForLevel(featureId, baseLevel);
      }

      const allowedActions: string[] = [];
      const actionsMap = featureProcessedInfo.flags; // { actionName: ProcessedFlag }
      for (const actionName in actionsMap) {
        // MODIFICATION: Utilisation de l'opération ET bitwise pour vérifier la permission
        // On vérifie si le masque final contient TOUS les bits du masque combiné de l'action
        if (
          (finalMask & actionsMap[actionName].combinedMask) ===
          actionsMap[actionName].combinedMask
        ) {
          allowedActions.push(actionName);
        }
      }

      // Structure retournée simplifiée (sans instance 'flags')
      effectivePermissions[featureName] = {
        id: featureId,
        actions: allowedActions,
      };
    });

    return {
      userId: user.id,
      level: baseLevel,
      expiresAt:
        user.permissionsExpireAt instanceof Date
          ? user.permissionsExpireAt
          : typeof user.permissionsExpireAt === 'string'
            ? dayjs(user.permissionsExpireAt).isValid()
              ? dayjs(user.permissionsExpireAt).toDate()
              : null
            : null,
      permissions: effectivePermissions,
    };
  }

  /** Vérifie une permission spécifique (feature + action). */
  async checkPermission(userId: number, featureName: string, actionName: string): Promise<boolean> {
    const effectiveAuths = await this.getUserEffectivePermissions(userId);
    if (!effectiveAuths) return false;

    const featurePermissions = effectiveAuths.permissions[featureName];
    if (!featurePermissions) return false;
    return featurePermissions.actions.includes(actionName);
  }

  /**
   * Encode un objet de permissions { feature: [actions] } en chaîne bitmask.
   * N'UTILISE PLUS la bibliothèque bitmask-flags.
   */
  encodePermissionsToString(permissions: PermissionsInputMap): string | null {
    const featureMasks: Map<number, number> = new Map(); // Map<featureId, permissionMask>

    for (const featureName in permissions) {
      const featureConfig = FEATURES_BY_NAME[featureName];
      // Récupérer la config BRUTE pour obtenir les valeurs de base des actions
      const rawFlagsConfig = featureConfig ? featuresRawFlagsConfigMap.get(featureConfig.id) : null;

      if (featureConfig && rawFlagsConfig) {
        let currentMask = 0;
        permissions[featureName].forEach((action) => {
          const actionConfig = rawFlagsConfig[action];
          if (actionConfig) {
            // MODIFICATION: Utiliser l'opération OU bitwise pour construire le masque
            currentMask |= actionConfig.value; // Utiliser la valeur BRUTE de l'action
          } else {
            logger.warn(`Encode: Unknown action '${action}' in feature '${featureName}'`);
          }
        });
        if (currentMask > 0) {
          featureMasks.set(featureConfig.id, currentMask);
        }
      } else {
        logger.warn(`Encode: Unknown feature: ${featureName}`);
      }
    }
    // Appeler l'encodeur qui transforme la Map en chaîne
    return this.encodeFeatureMasks(featureMasks);
  }

  /**
   * Encode une Map<featureId, permissionMask> en chaîne pour la BDD.
   * Remplace l'ancienne méthode 'encodeAuthorisations'.
   */
  private encodeFeatureMasks(featureMasks: Map<number, number>): string | null {
    const inlines: number[] = [];
    featureMasks.forEach((permissionMask, featureId) => {
      try {
        // Assurer que les masques ne dépassent pas 16 bits (0-65535)
        if (permissionMask < 0 || permissionMask > 65535) {
          logger.warn(
            `Permission mask ${permissionMask} for feature ${featureId} exceeds 16 bits. Clamping.`,
          );
          permissionMask = Math.max(0, Math.min(permissionMask, 65535));
        }
        if (featureId < 0 || featureId > 65535) {
          // Vérifier aussi featureId
          logger.warn(`Feature ID ${featureId} exceeds 16 bits. Skipping.`);
          return;
        }

        const idBits = paddingLeft(featureId.toString(2), '0'.repeat(16));
        const permBits = paddingLeft(permissionMask.toString(2), '0'.repeat(16));
        const combined = parseInt(idBits + permBits, 2);
        if (!isNaN(combined)) {
          inlines.push(combined);
        } else {
          logger.warn(`Could not parse combined bits for feature ${featureId}`);
        }
      } catch (e) {
        logger.error(e, `Error encoding feature ${featureId} with mask ${permissionMask}`);
      }
    });
    const result = inlines.join('.');
    return result !== '' ? result : null;
  }
}
