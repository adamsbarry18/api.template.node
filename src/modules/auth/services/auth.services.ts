import jwt from 'jsonwebtoken';
import dayjs from 'dayjs';

import { User } from '@/modules/users/models/users.entity';
import { UsersService } from '@/modules/users/services/users.services';
import { AuthorisationsService } from '@/modules/authorisations/authorization.services';
import { DecodedAuthorisations } from '@/modules/authorisations/authorization.types';
import { SecurityLevel, UserApiResponse, PasswordStatus } from '@/modules/users/models/users.types';
import { CustomJwtPayload } from '@/common/types';

// Libs et Config
import logger from '@/lib/logger';
import config from '@/config';
import { redisClient } from '@/lib/redis';
import {
  UnauthorizedError,
  ForbiddenError,
  InternalServerError,
  NotFoundError,
} from '@/common/errors/httpErrors';

// --- Constantes de Configuration ---
const REDIS_INVALIDATION_TOKEN_KEY = config.REDIS_KEYS_TOKEN_INVALIDATION_PREFIX;
const REDIS_USER_PERMISSIONS_KEY_PREFIX = config.REDIS_KEYS_USER_PERMISSIONS_PREFIX;
const REDIS_USER_PERMISSIONS_KEY_SUFFIX = config.REDIS_KEYS_USER_PERMISSIONS_SUFFIX;

// TTLs (en secondes)
const AUTHORISATION_CACHE_TTL_SECONDS = config.AUTH_CACHE_TTL_SECONDS;
const TOKEN_DEFAULT_EXPIRE_IN_SECONDS = config.JWT_EXPIRATION_SECONDS;
// Note: Le TTL pour les codes de reset/confirmation est utilisé dans UsersService, pas directement ici.

// Durées (en jours)
const PASSWORD_EXPIRED_IN_DAYS = config.PASSWORD_EXPIRY_DAYS;

export class AuthService {
  // Services requis injectés ou instanciés
  private readonly usersService: UsersService;
  private readonly authorisationsService: AuthorisationsService;

  constructor() {
    // Instanciation directe ici, adaptez si vous utilisez l'injection de dépendances
    this.usersService = new UsersService();
    this.authorisationsService = new AuthorisationsService();
  }

  /**
   * Tente de connecter un utilisateur avec email et mot de passe.
   * Vérifie le statut et l'expiration du mot de passe.
   * Retourne les informations utilisateur (formatées) et un token JWT en cas de succès.
   * Lève des erreurs HTTP appropriées en cas d'échec.
   */
  async login(email: string, password: string): Promise<{ user: UserApiResponse; token: string }> {
    if (!email || !password) {
      throw new UnauthorizedError('Email and password are required.');
    }

    const lowerCaseEmail = email.toLowerCase().trim();
    const user = await this.usersService.findByEmailForAuth(lowerCaseEmail);

    // Vérification de l'existence de l'utilisateur
    if (!user) {
      logger.warn(`Login attempt failed: User not found for email ${lowerCaseEmail}`);
      throw new UnauthorizedError('Invalid credentials.'); // Message générique pour sécurité
    }

    // Vérification du mot de passe via la méthode de l'entité (utilisant bcrypt)
    const isPasswordMatch = await user.comparePassword(password);
    if (!isPasswordMatch) {
      logger.warn(`Login attempt failed: Invalid password for user ${user.id}`);
      throw new UnauthorizedError('Invalid credentials.'); // Message générique
    }

    // Vérification du statut du mot de passe (nécessite validation ?)
    if (user.passwordStatus === PasswordStatus.VALIDATING) {
      throw new ForbiddenError('Password requires validation. Please check your email.');
    }

    // Vérification de l'expiration du mot de passe
    const passwordLastUpdated = dayjs(user.passwordUpdatedAt);
    if (!passwordLastUpdated.isValid()) {
      // Log d'erreur si la date est invalide en BDD, mais on pourrait choisir de continuer
      logger.error(
        `Invalid passwordUpdatedAt format for user ${user.id}: ${user.passwordUpdatedAt}. Proceeding with caution.`,
      );
      // Alternative : lancer une InternalServerError si cette date est critique
      // throw new InternalServerError('User account configuration issue (invalid password update date).');
    }

    // Calcul de l'âge du mot de passe seulement si la date est valide
    const passwordAgeInDays = passwordLastUpdated.isValid()
      ? dayjs().diff(passwordLastUpdated, 'day')
      : -1;

    if (
      user.passwordStatus === PasswordStatus.EXPIRED ||
      (passwordAgeInDays !== -1 && passwordAgeInDays >= PASSWORD_EXPIRED_IN_DAYS)
    ) {
      // Si le statut n'est pas déjà EXPIRED en BDD, on le met à jour.
      if (user.passwordStatus !== PasswordStatus.EXPIRED) {
        try {
          // Idéalement, UsersService aurait une méthode dédiée pour ne pas bypasser d'autres logiques d'update
          await this.usersService.update(user.id, { passwordStatus: PasswordStatus.EXPIRED });
          logger.info(`Password status set to EXPIRED for user ${user.id} due to age.`);
        } catch (updateError) {
          logger.error(
            updateError,
            `Failed to update password status to EXPIRED for user ${user.id}`,
          );
          // Continuer pour lever l'erreur Forbidden, mais la BDD n'est pas à jour
        }
      }
      throw new ForbiddenError('Your password has expired. Please reset it.');
    }

    // Succès de l'authentification
    logger.info(`User ${user.id} (${user.email}) logged in successfully.`);

    // Générer le token JWT
    const token = this.generateJwtToken(user);

    // Formater la réponse utilisateur via la méthode de l'entité
    const userApiResponse = user.toApi();

    return { user: userApiResponse, token };
  }

  /**
   * Invalide un token JWT en l'ajoutant à la liste noire Redis avec un TTL approprié.
   */
  async logout(token: string): Promise<void> {
    if (!token) {
      logger.warn('Logout attempt without token.');
      return; // Pas de token à invalider
    }

    if (!redisClient) {
      logger.error(
        'Redis client not available for logout (token invalidation). Cannot invalidate token.',
      );
      // Selon la criticité, on pourrait lancer une erreur 503 ici
      // throw new InternalServerError('Logout service temporarily unavailable.');
      return; // Ou continuer sans invalider (moins sûr)
    }

    try {
      // Décoder le token pour obtenir sa date d'expiration
      const decoded = jwt.decode(token) as CustomJwtPayload;
      let redisTTL = TOKEN_DEFAULT_EXPIRE_IN_SECONDS; // Utiliser l'expiration par défaut comme fallback

      if (decoded?.exp) {
        const expiresInSeconds = decoded.exp - dayjs().unix(); // Temps restant en secondes
        // S'assurer que le TTL est raisonnable (au moins 1 min, pas plus que l'expiration par défaut)
        if (expiresInSeconds > 0) {
          redisTTL = Math.max(60, Math.min(expiresInSeconds, TOKEN_DEFAULT_EXPIRE_IN_SECONDS));
        } else {
          // Le token est déjà expiré techniquement, mais on l'ajoute quand même pour une courte durée
          redisTTL = 60;
        }
      }

      // Ajouter le token à la liste noire Redis
      await redisClient.setEx(
        `${REDIS_INVALIDATION_TOKEN_KEY}${token}`,
        redisTTL, // Durée de vie dans Redis
        'invalidated', // Valeur simple, la présence de la clé suffit
      );
      logger.info(
        `Token invalidated successfully via logout (marked in Redis for ${redisTTL}s). Token starts with ${token.substring(0, 10)}...`,
      );
    } catch (error: any) {
      logger.error(
        error,
        `Redis SETEX error during token invalidation: ${error.message}. Token starts with ${token.substring(0, 10)}...`,
      );
      // Ne pas planter le processus de logout pour une erreur Redis
    }
  }

  /**
   * Vérifie si un token JWT a été invalidé (présent dans la liste noire Redis).
   * Utilisé par la stratégie Passport JWT.
   */
  async isTokenInvalidated(token: string | null | undefined): Promise<boolean> {
    if (!token) return true; // Considérer un token manquant comme invalide
    if (!redisClient) {
      logger.warn(
        'Redis client not available for token invalidation check. Assuming token is valid.',
      );
      return false; // Comportement par défaut si Redis HS: laisser passer
    }
    try {
      const cacheKey = `${REDIS_INVALIDATION_TOKEN_KEY}${token}`;
      const result = await redisClient.get(cacheKey);
      if (result) {
        logger.debug(
          `Token invalidation check: Token found in blacklist. Token starts with ${token.substring(0, 10)}...`,
        );
        return true; // Trouvé dans la blacklist = invalidé
      }
      return false; // Non trouvé = valide (ou expiré naturellement)
    } catch (error) {
      logger.error(
        error,
        `Redis GET error during token invalidation check. Assuming token is valid. Token starts with ${token.substring(0, 10)}...`,
      );
      return false; // Laisser passer en cas d'erreur Redis
    }
  }

  /**
   * Génère un token JWT signé pour un utilisateur donné.
   * @param user - L'entité User contenant les informations à inclure dans le payload.
   * @returns Le token JWT signé.
   * @throws {InternalServerError} Si la signature JWT échoue.
   */
  private generateJwtToken(user: User): string {
    // Construire le payload du token
    const payload: CustomJwtPayload = {
      id: user.id, // 'sub' (subject) est souvent utilisé, mais 'id' est clair
      level: user.level,
      internal: user.internal,
      // uid: user.uid, // Optionnel: si l'UID est utile côté client/services
      // email: user.email, // Optionnel: évitez si possible pour limiter l'exposition
    };

    try {
      // Signer le token avec le secret et les options d'expiration
      const token = jwt.sign(payload, config.JWT_SECRET, {
        expiresIn: TOKEN_DEFAULT_EXPIRE_IN_SECONDS, // Expiration définie dans les constantes
        // algorithm: 'HS256' // Est la valeur par défaut
        // issuer: 'your-app-name', // Optionnel
        // audience: 'your-audience', // Optionnel
      });
      return token;
    } catch (error: any) {
      logger.error(error, `Failed to sign JWT for user ${user.id}`);
      throw new InternalServerError('Failed to generate authentication token.');
    }
  }

  /**
   * Récupère les permissions effectives d'un utilisateur, utilisant un cache Redis.
   * Délègue le calcul à AuthorisationsService si le cache est vide ou expiré.
   */
  async getEffectivePermissions(userId: number): Promise<DecodedAuthorisations | null> {
    if (!userId) return null;

    const cacheKey = `${REDIS_USER_PERMISSIONS_KEY_PREFIX}${userId}${REDIS_USER_PERMISSIONS_KEY_SUFFIX}`;

    // 1. Essai de lecture du cache Redis
    if (redisClient) {
      try {
        const cachedData = await redisClient.get(cacheKey);
        if (cachedData) {
          logger.debug(`Permissions cache HIT for user ${userId}`);
          return JSON.parse(cachedData) as DecodedAuthorisations; // Assume que les données sont du JSON valide
        }
        logger.debug(`Permissions cache MISS for user ${userId}`);
      } catch (error) {
        logger.error(
          error,
          `Redis GET error for permissions key ${cacheKey}. Fetching from source.`,
        );
        // Continuer pour récupérer depuis la source
      }
    } else {
      logger.warn('Redis client not available for permissions caching.');
    }

    // 2. Cache miss ou Redis indisponible: Calcul via AuthorisationsService
    logger.debug(`Calculating effective permissions for user ${userId}...`);
    const permissions = await this.authorisationsService.getUserEffectivePermissions(userId);

    // 3. Mise en cache du résultat (même si null)
    if (redisClient) {
      try {
        // Utiliser JSON.stringify pour stocker l'objet
        await redisClient.setEx(
          cacheKey,
          AUTHORISATION_CACHE_TTL_SECONDS,
          JSON.stringify(permissions),
        );
        logger.debug(
          `Permissions cached successfully for user ${userId} (TTL: ${AUTHORISATION_CACHE_TTL_SECONDS}s)`,
        );
      } catch (error) {
        logger.error(
          error,
          `Redis SETEX error for permissions key ${cacheKey}. Cache not updated.`,
        );
        // L'opération principale a réussi, on ne relance pas l'erreur de cache
      }
    }

    return permissions;
  }

  /**
   * Vérifie si un utilisateur possède une permission spécifique (feature + action).
   * Utilise le cache via getEffectivePermissions.
   */
  async hasPermission(userId: number, featureName: string, actionName: string): Promise<boolean> {
    if (!userId || !featureName || !actionName) {
      return false; // Arguments invalides
    }

    try {
      // Récupère les permissions (depuis cache ou source)
      const effectiveAuths = await this.getEffectivePermissions(userId);

      // Vérifie si l'utilisateur et la feature existent
      if (!effectiveAuths?.permissions?.[featureName]) {
        return false;
      }

      // Vérifie si l'action est dans la liste des actions autorisées
      const hasAction = effectiveAuths.permissions[featureName].actions.includes(actionName);
      return hasAction;
    } catch (error) {
      // Si getEffectivePermissions lève une erreur (ex: NotFoundError, DB error)
      // On loggue et refuse la permission par sécurité.
      if (error instanceof NotFoundError) {
        logger.warn(
          `Permission check (${featureName}:${actionName}) failed for user ${userId}: User not found.`,
        );
      } else {
        logger.error(
          error,
          `Error checking permission '${featureName}:${actionName}' for user ${userId}`,
        );
      }
      return false; // Refus par défaut en cas d'erreur
    }
  }

  /**
   * Invalide le cache de permissions Redis pour un utilisateur spécifique.
   * Doit être appelée lorsque les permissions d'un utilisateur changent (level, overrides, expiry).
   */
  async invalidatePermissionsCache(userId: number): Promise<void> {
    if (!userId) return;
    if (!redisClient) {
      logger.warn(
        `Redis client not available, cannot invalidate permissions cache for user ${userId}`,
      );
      return;
    }

    const cacheKey = `${REDIS_USER_PERMISSIONS_KEY_PREFIX}${userId}${REDIS_USER_PERMISSIONS_KEY_SUFFIX}`;
    try {
      const result = await redisClient.del(cacheKey);
      if (result > 0) {
        logger.info(
          `Permissions cache invalidated successfully for user ${userId} (key: ${cacheKey})`,
        );
      } else {
        logger.debug(
          `Permissions cache key ${cacheKey} not found for user ${userId}, nothing to invalidate.`,
        );
      }
    } catch (error) {
      logger.error(
        error,
        `Redis DEL error while invalidating permissions cache for user ${userId}`,
      );
      // Ne pas planter pour une erreur d'invalidation de cache, mais l'erreur est problématique.
    }
  }

  /**
   * Vérifie statiquement si le niveau de l'utilisateur (depuis le token) est suffisant.
   */
  static checkLevel(
    requestingUser: CustomJwtPayload | undefined,
    requiredLevel: SecurityLevel,
  ): boolean {
    if (!requestingUser?.level) {
      // Vérifie l'existence et la validité (non undefined/null/0 si 0 n'est pas un niveau valide)
      logger.warn(
        `Attempt to check level ${requiredLevel} for user without level in token payload.`,
      );
      return false;
    }
    // Comparaison simple des niveaux
    return requestingUser.level >= requiredLevel;
  }
}
