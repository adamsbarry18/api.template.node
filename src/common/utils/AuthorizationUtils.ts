import logger from '@/lib/logger';
import { FEATURES_BY_NAME, featuresRawFlagsConfigMap } from '@/modules/auth/models/features';

// Type pour la carte des permissions en entrée
export type PermissionsInputMap = Record<string, string[]>;

export class AuthorizationUtils {
  /**
   * Encode une structure de permissions en chaîne pour stockage dans la base de données
   */
  public static encodePermissionsToString(
    permissions: PermissionsInputMap | null | undefined,
  ): string | null {
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
            continue;
          }

          actionsToEncode.forEach((action) => {
            const actionConfig = rawFlagsConfig[action];
            if (actionConfig) {
              currentMask |= actionConfig.value;
            }
          });

          if (currentMask > 0) {
            featureMasks.set(featureConfig.id, currentMask);
          }
        }
      }
    }

    if (featureMasks.size === 0) {
      return null;
    }

    return AuthorizationUtils.encodeFeatureMasks(featureMasks);
  }

  /**
   * Encode une Map<featureId, permissionMask> en chaîne pour la base de données
   */
  private static encodeFeatureMasks(featureMasks: Map<number, number>): string | null {
    const encodedParts: number[] = [];

    featureMasks.forEach((permissionMask, featureId) => {
      try {
        if (
          typeof featureId !== 'number' ||
          featureId < 0 ||
          featureId > 0xffff ||
          isNaN(featureId)
        ) {
          return;
        }
        if (
          typeof permissionMask !== 'number' ||
          permissionMask < 0 ||
          permissionMask > 0xffff ||
          isNaN(permissionMask)
        ) {
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

    return encodedParts.join('.');
  }
}
