// src/modules/authorisations/authorisations.service.ts

import dayjs from 'dayjs'; // Bibliothèque de manipulation de dates
import logger from '@/lib/logger'; // Logger de l'application
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
type DecodedOverrides = Map<number, number>; // Map<featureId, permissionMask>

/**
 * Service responsable du calcul des permissions effectives des utilisateurs
 * en fonction de leur niveau, des overrides spécifiques (authorisationOverrides),
 * et de la configuration globale des fonctionnalités (features).
 * Gère également l'encodage et le décodage de la chaîne d'overrides.
 * NOTE: Ce service ne gère PAS la mise en cache ; elle est déléguée à AuthService.
 */
export class AuthorisationsService {
  private readonly userRepository: UserRepository;

  constructor() {
    // Instanciation directe du repository. Adaptez si vous utilisez l'injection de dépendances.
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
      return decoded; // Retourne une map vide si pas d'overrides
    }

    const parts = overrideString.split('.'); // Sépare les entrées encodées
    for (const part of parts) {
      try {
        const numAuth = parseInt(part, 10); // Convertit la partie en nombre entier
        if (isNaN(numAuth) || numAuth < 0) {
          logger.warn(
            `Invalid non-numeric or negative part found in authorisationOverrides: '${part}'. Skipping.`,
          );
          continue;
        }

        // Convertit en binaire 32 bits (potentiellement > 32 bits en JS, mais on le traite comme tel)
        // Utilisation de padStart pour la lisibilité
        const bitAuth = numAuth.toString(2).padStart(32, '0');

        // Extrait les 16 bits de poids fort pour featureId, 16 bits de poids faible pour permissionMask
        const featureId = parseInt(bitAuth.substring(0, 16), 2);
        const permissionMask = parseInt(bitAuth.substring(16), 2);

        // Vérifie si le featureId décodé correspond à une feature connue (via la map traitée)
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
    // Récupère les informations traitées de la feature (qui contiennent les niveaux par défaut par action)
    const featureInfo = featuresProcessedFlagsMap.get(featureId);
    if (!featureInfo) return 0; // Feature inconnue, pas de permissions par défaut

    let defaultMask = 0;
    const actionsMap = featureInfo.flags; // { actionName: ProcessedFlag }

    // Itère sur chaque action définie pour cette feature
    for (const actionName in actionsMap) {
      const actionConfig = actionsMap[actionName];
      // Si l'action a un niveau défini et que ce niveau est <= au niveau de l'utilisateur
      if (actionConfig.level !== undefined && actionConfig.level <= userLevel) {
        // Ajoute (via OU bitwise) le masque *combiné* de l'action au masque par défaut
        // Le masque combiné inclut les permissions héritées (ex: write inclut read)
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
    // Récupère l'utilisateur depuis la base de données
    const user = await this.userRepository.findById(userId);
    if (!user) {
      // Important de lever une erreur si l'utilisateur n'est pas trouvé
      throw new NotFoundError(`User with ID ${userId} not found when calculating permissions.`);
    }

    const baseLevel = user.level as SecurityLevel; // Niveau de base de l'utilisateur
    let overrides: DecodedOverrides = new Map();
    let areOverridesExpired = false;

    // Vérifier si les overrides ont une date d'expiration et si elle est passée
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

    // Décoder les overrides seulement s'ils existent et ne sont pas expirés
    if (user.authorisationOverrides && !areOverridesExpired) {
      overrides = this.decodeAuthorisationOverrides(user.authorisationOverrides);
    }

    // Objet pour stocker les permissions effectives calculées
    const effectivePermissions: DecodedAuthorisations['permissions'] = {};

    // Itérer sur TOUTES les features définies dans la configuration globale
    FEATURES_CONFIG.forEach((featureConfig) => {
      const featureId = featureConfig.id;
      const featureName = featureConfig.name;
      const featureProcessedInfo = featuresProcessedFlagsMap.get(featureId);

      // Si la feature n'existe pas dans la config traitée (problème de config), on l'ignore
      if (!featureProcessedInfo) {
        logger.error(
          `Feature ID ${featureId} (${featureName}) not found in processed feature map during permission calculation. Configuration might be corrupt.`,
        );
        return; // Passe à la feature suivante
      }

      // Déterminer le masque final pour cette feature : override ou défaut ?
      let finalMask: number;
      if (overrides.has(featureId)) {
        // Utiliser le masque de l'override décodé
        finalMask = overrides.get(featureId)!;
      } else {
        // Calculer le masque par défaut basé sur le niveau de l'utilisateur
        finalMask = this.calculateDefaultMaskForLevel(featureId, baseLevel);
      }

      // Trouver les actions permises par ce masque final
      const allowedActions: string[] = [];
      const actionsMap = featureProcessedInfo.flags; // { actionName: ProcessedFlag }

      for (const actionName in actionsMap) {
        const actionConfig = actionsMap[actionName];
        // Vérifier si tous les bits requis par l'action (via son combinedMask) sont présents dans finalMask
        if ((finalMask & actionConfig.combinedMask) === actionConfig.combinedMask) {
          allowedActions.push(actionName);
        }
      }

      // Ajouter les permissions de cette feature au résultat final
      // On ne stocke que les features pour lesquelles l'utilisateur a au moins une action (optionnel, mais économise de l'espace)
      if (allowedActions.length > 0) {
        effectivePermissions[featureName] = {
          id: featureId,
          actions: allowedActions,
        };
      } else {
        // Si vous voulez inclure toutes les features même sans actions :
        // effectivePermissions[featureName] = { id: featureId, actions: [] };
      }
    }); // Fin de la boucle sur FEATURES_CONFIG

    // Formater la date d'expiration correctement pour l'objet retourné
    const expiresAt = permissionExpiryDate?.isValid() ? permissionExpiryDate.toDate() : null;

    // Construire l'objet DecodedAuthorisations final
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
      // Vérification directe dans l'objet retourné
      return !!effectiveAuths?.permissions?.[featureName]?.actions.includes(actionName);
    } catch (error) {
      if (error instanceof NotFoundError) {
        logger.warn(`checkPermission failed for non-existent user ${userId}`);
      } else {
        logger.error(error, `Error in checkPermission(${userId}, ${featureName}, ${actionName})`);
      }
      return false; // Refus par défaut en cas d'erreur ou user non trouvé
    }
  }

  /**
   * Encode une structure de permissions { featureName: [actionName] } en chaîne `authorisationOverrides`.
   * @param permissions - L'objet décrivant les permissions à encoder.
   * @returns La chaîne encodée pour stockage en BDD, ou null si aucune permission n'est fournie.
   */
  encodePermissionsToString(permissions: PermissionsInputMap): string | null {
    const featureMasks: Map<number, number> = new Map(); // Map<featureId, permissionMask>

    // Itère sur les features fournies en entrée
    for (const featureName in permissions) {
      const featureConfig = FEATURES_BY_NAME[featureName]; // Trouver la config de la feature par son nom
      // Récupérer la config BRUTE des flags pour cette feature (nécessaire pour les valeurs de base)
      const rawFlagsConfig = featureConfig ? featuresRawFlagsConfigMap.get(featureConfig.id) : null;

      if (featureConfig && rawFlagsConfig) {
        let currentMask = 0;
        const actionsToEncode = permissions[featureName]; // Tableau des actions ['read', 'write']

        // Pour chaque action à encoder pour cette feature
        actionsToEncode.forEach((action) => {
          const actionConfig = rawFlagsConfig[action]; // Trouver la config brute de l'action
          if (actionConfig) {
            // Utiliser OU bitwise pour ajouter la valeur de l'action au masque courant
            currentMask |= actionConfig.value; // Utilise la valeur brute (ex: 1, 2, 4...)
          } else {
            logger.warn(
              `Encode: Unknown action '${action}' in feature '${featureName}'. Skipping action.`,
            );
          }
        });

        // Stocker le masque calculé pour cette feature s'il n'est pas nul
        if (currentMask > 0) {
          featureMasks.set(featureConfig.id, currentMask);
        }
      } else {
        logger.warn(`Encode: Unknown feature name '${featureName}'. Skipping feature.`);
      }
    }

    // Si aucune permission n'a été encodée, retourner null
    if (featureMasks.size === 0) {
      return null;
    }

    // Convertir la Map de masques en chaîne de nombres 32 bits séparés par '.'
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
        // Validation des bornes (0-65535 pour 16 bits)
        if (permissionMask < 0 || permissionMask > 0xffff) {
          logger.warn(
            `Permission mask ${permissionMask} for feature ${featureId} exceeds 16 bits (0-65535). Clamping.`,
          );
          permissionMask = Math.max(0, Math.min(permissionMask, 0xffff)); // Clamp
        }
        if (featureId < 0 || featureId > 0xffff) {
          logger.warn(`Feature ID ${featureId} exceeds 16 bits (0-65535). Skipping.`);
          return; // Ne pas inclure cette entrée
        }

        // Conversion en binaire 16 bits et combinaison
        const idBits = featureId.toString(2).padStart(16, '0');
        const permBits = permissionMask.toString(2).padStart(16, '0');
        const combined = parseInt(idBits + permBits, 2); // Reconvertit en entier base 10

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

    // Joindre les parties encodées avec '.'
    const result = encodedParts.join('.');
    return result !== '' ? result : null; // Retourne null si vide
  }
}
