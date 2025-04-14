import jwt from 'jsonwebtoken';
import dayjs from 'dayjs';
import { redisClient } from '@/lib/redis';
import config from '@/config';
import logger from '@/lib/logger';
import {
  UnauthorizedError,
  ForbiddenError,
  InternalServerError,
  NotFoundError,
} from '@/common/errors/httpErrors';
import { UsersService } from '@/modules/users/services/users.services';
import { AuthorisationsService } from '@/modules/auth/services/authorization.services';
import { PasswordStatus, UserApiResponse } from '@/modules/users/models/users.types';
import { DecodedAuthorisations } from '@/modules/auth/models/authorization.types';

//
// Constantes pour les clés Redis et durées
//
const REDIS_AUTHORISATION_KEY_PATTERN = 'api-auth:user_authorisation:{userId}';
const REDIS_TOKEN_INVALIDATION_KEY = 'api-auth:token_invalidation:{token}';
const AUTHORISATION_CACHE_TTL_SECONDS = 60 * 30; // 30 minutes
const TOKEN_DEFAULT_EXPIRE_SECONDS = 60 * 60 * 24 * 30; // 30 jours
const PASSWORD_EXPIRED_IN_DAYS = 90;

export class AuthService {
  private usersService: UsersService;
  private authorisationsService: AuthorisationsService;

  constructor() {
    this.usersService = new UsersService();
    this.authorisationsService = new AuthorisationsService();
  }

  /**
   * Génère la clé Redis pour stocker les autorisations de l'utilisateur.
   */
  private getRedisAuthorisationKey(userId: number): string {
    return REDIS_AUTHORISATION_KEY_PATTERN.replace('{userId}', userId.toString());
  }

  /**
   * Génère la clé Redis pour l'invalidation d'un token.
   */
  private getRedisInvalidationKey(token: string): string {
    return REDIS_TOKEN_INVALIDATION_KEY.replace('{token}', token);
  }

  /**
   * Authentifie un utilisateur en vérifiant l'email et le mot de passe.
   * Vérifie également le statut du mot de passe (validation et expiration).
   */
  async login(email: string, password: string): Promise<{ token: string; user: UserApiResponse }> {
    if (!email || !password) {
      throw new UnauthorizedError('Email et mot de passe requis.');
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await this.usersService.findByEmailForAuth(normalizedEmail);
    if (!user) {
      throw new UnauthorizedError('Email ou mot de passe invalide.');
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      logger.error(`Mauvais mot de passe pour l’utilisateur ID: ${user.id}`);
      throw new UnauthorizedError('Email ou mot de passe invalide.');
    }

    // Vérifier le statut du mot de passe
    if (user.passwordStatus === PasswordStatus.VALIDATING) {
      throw new UnauthorizedError('Mot de passe en cours de validation.');
    }
    const passwordExpired = user.passwordUpdatedAt
      ? dayjs(user.passwordUpdatedAt).add(PASSWORD_EXPIRED_IN_DAYS, 'days').isBefore(dayjs())
      : false;
    if (user.passwordStatus === PasswordStatus.EXPIRED || passwordExpired) {
      throw new UnauthorizedError('Mot de passe expiré.');
    }

    // Générer le token JWT (payload enrichi avec quelques infos utiles)
    const token = await this.signToken(user.id, { level: user.level, internal: user.internal });
    const userApi = this.usersService.mapToApiResponse(user);
    return { user: userApi!, token };
  }

  /**
   * Déconnecte un utilisateur en invalidant son token.
   * L'invalidation enregistre le token dans Redis afin d'empêcher sa réutilisation.
   */
  async logout(token: string): Promise<void> {
    if (!token) return;
    await this.invalidateToken(token);
  }

  /**
   * Signe un token JWT pour un utilisateur.
   * Le payload contient le userId et d'autres informations utiles pour la vérification.
   */
  async signToken(userId: number, extraPayload: Record<string, any> = {}): Promise<string> {
    const payload = { sub: userId, ...extraPayload };
    try {
      return jwt.sign(payload, config.JWT_SECRET, { expiresIn: TOKEN_DEFAULT_EXPIRE_SECONDS });
    } catch (error: any) {
      logger.error(error, `Erreur lors de la signature du JWT pour l’utilisateur ID: ${userId}`);
      throw new InternalServerError('Impossible de générer le token d’authentification.');
    }
  }

  /**
   * Invalide un token en le stockant dans Redis avec une durée égale à son expiration.
   */
  async invalidateToken(token: string): Promise<void> {
    if (!redisClient) {
      logger.error('Redis indisponible pour l’invalidation des tokens.');
      throw new InternalServerError('Service d’authentification temporairement indisponible.');
    }
    const redisKey = this.getRedisInvalidationKey(token);
    try {
      await redisClient.setEx(redisKey, TOKEN_DEFAULT_EXPIRE_SECONDS, token);
    } catch (error) {
      logger.error(error, `Erreur lors de l’invalidation du token: ${token.substring(0, 10)}...`);
      throw new InternalServerError('Erreur lors de la déconnexion.');
    }
  }

  /**
   * Vérifie si un token a été invalidé (blacklisté) via Redis.
   */
  async isTokenInvalidated(token: string): Promise<boolean> {
    if (!redisClient) {
      logger.error('Redis indisponible pour la vérification d’invalidation des tokens.');
      throw new InternalServerError('Service d’authentification temporairement indisponible.');
    }
    const redisKey = this.getRedisInvalidationKey(token);
    try {
      const res = await redisClient.get(redisKey);
      return !!res;
    } catch (error) {
      logger.error(
        error,
        `Erreur lors de la vérification d’invalidation du token: ${token.substring(0, 10)}...`,
      );
      throw new InternalServerError('Erreur lors de la vérification du token.');
    }
  }

  /**
   * Récupère les autorisations effectives d’un utilisateur.
   * Tente d'abord de charger le cache depuis Redis, sinon appelle le service d'autorisations et met en cache le résultat.
   */
  async getAuthorisation(userId: number): Promise<DecodedAuthorisations | null> {
    if (!redisClient) {
      logger.error('Redis indisponible pour la récupération des autorisations.');
      throw new InternalServerError('Service d’authentification temporairement indisponible.');
    }
    const redisKey = this.getRedisAuthorisationKey(userId);
    let permissions: DecodedAuthorisations | null = null;

    try {
      const cached = await redisClient.get(redisKey);
      if (cached) {
        permissions = JSON.parse(cached);
        // Si une date d'expiration est définie dans le cache, on la vérifie
        if (permissions.expiresAt && dayjs(permissions.expiresAt).isBefore(dayjs())) {
          permissions = null;
        }
      }
    } catch (error) {
      logger.error(error, `Erreur lors de la récupération du cache pour userId: ${userId}`);
    }

    if (!permissions) {
      permissions = await this.authorisationsService.getUserEffectivePermissions(userId);
      if (permissions) {
        try {
          await redisClient.setEx(
            redisKey,
            AUTHORISATION_CACHE_TTL_SECONDS,
            JSON.stringify(permissions),
          );
        } catch (error) {
          logger.error(
            error,
            `Erreur lors de la mise en cache des autorisations pour userId: ${userId}`,
          );
        }
      }
    }

    return permissions;
  }

  /**
   * Génère un nouveau token JWT pour un utilisateur donné.
   * @param userId - L’ID de l’utilisateur.
   * @returns Le token JWT signé.
   */

  async generateTokenForUser(userId): Promise<{ token: string }> {
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new NotFoundError(`User with email ${userId} not found`);
    }
    const token = await this.signToken(user.id, {});
    return { token };
  }

  /**
   * Vérifie si un utilisateur possède une permission pour une feature et une action donnés.
   */
  async checkAuthorisation(
    userId: number,
    featureName: string,
    actionName: string,
  ): Promise<boolean> {
    const permissions = await this.getAuthorisation(userId);
    return permissions?.permissions?.[featureName]?.actions.includes(actionName) || false;
  }

  /**
   * Vérifie si le niveau de l'utilisateur est suffisant par rapport au niveau requis.
   */
  async checkLevelAccess(userId: number, requiredLevel: number): Promise<boolean> {
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new ForbiddenError('Utilisateur non trouvé');
    }
    return user.level >= requiredLevel;
  }
}
