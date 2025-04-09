/**
 * Représente l'état DÉCODÉ et CALCULÉ des autorisations effectives
 * pour un utilisateur donné.
 * Cet objet est le résultat de la combinaison du niveau de base de l'utilisateur
 * et de ses overrides spécifiques (stockés dans user.authorisationOverrides),
 * en tenant compte de la date d'expiration (user.permissionsExpireAt).
 */
export interface DecodedAuthorisations {
  /** L'ID de l'utilisateur concerné. */
  userId: number;

  /**
   * Le niveau de sécurité de base de l'utilisateur tel que défini dans son enregistrement User.
   * C'est ce niveau qui est utilisé pour calculer les permissions par défaut.
   */
  level: number; // Ou: level: SecurityLevel;

  /**
   * La date d'expiration des permissions spécifiques (overrides) stockées
   * dans `user.authorisationOverrides`. Si cette date est passée, les overrides
   * sont ignorés et seules les permissions basées sur `level` sont appliquées.
   */
  expiresAt: Date | null;

  /**
   * Un objet où chaque clé est le nom d'une fonctionnalité (feature) configurée
   * (ex: 'user', 'config', 'folder').
   * La valeur associée contient les permissions effectives pour cette fonctionnalité.
   */
  permissions: {
    [featureName: string]: {
      /** L'ID numérique de la fonctionnalité (depuis FEATURES_CONFIG). */
      id: number;

      /**
       * Optionnel: L'instance de flags (bitmask-flags) calculée.
       * Peut être utile pour des opérations avancées, mais souvent
       * le tableau `actions` est suffisant pour les vérifications.
       * Si vous l'incluez, assurez-vous que le type est correct (il dépend de la lib `bitmask-flags`).
       */
      // flags?: any; // Type de l'instance bitmask-flags

      /**
       * La liste explicite des noms d'actions permises pour cette fonctionnalité,
       * résultant de la combinaison du niveau et des overrides.
       * Ex: ['read', 'write', 'create']
       */
      actions: string[];

      /**
       * Optionnel: Le masque binaire final résultant (peut être utile pour le débogage).
       */
      // mask?: number;
    };
  };
}

/**
 * Optionnel: Type décrivant l'entrée pour la fonction d'encodage des permissions.
 * Utile si vous construisez une UI pour gérer les permissions fines.
 * Clé = nom de la feature, Valeur = tableau des noms d'actions à autoriser.
 */
export type PermissionsInputMap = {
  [featureName: string]: string[]; // ex: { user: ['read', 'write'], config: ['read'] }
};
